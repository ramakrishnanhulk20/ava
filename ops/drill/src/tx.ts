import { BroadcastTxError, StargateClient } from "@cosmjs/stargate";
import {
  EthNativeSigner,
  QoreHttpError,
  checkCosmosGasLimit,
  getJson,
  postJsonRpc,
  sha256Hex,
  withRetry,
  type EthTxParams,
} from "@qorechain/sdk";
import type { DrillAccount } from "./account.js";
import { CHAIN_ID, DENOM, HTTP, MIN_GAS_PRICE_MILLI_UQOR, REST, RPC } from "./env.js";

export type Messages = EthTxParams["messages"];
export type Fee = EthTxParams["fee"];

const GAS_ADJUSTMENT_PERCENT = 130n;
// The SDK's own client prices at 0.15 uqor per gas, safely above the floor.
const GAS_PRICE_MILLI_UQOR = 150n;
// A broken or hostile simulation answer must not be able to spend the balance on fees.
export const MAX_FEE_UQOR = 200_000n;

// The organisers' Workshop 1 example sends the registration with exactly this
// fee. The 2,592-byte key used about 300,000 gas in the docs' run.
export const REGISTRATION_FEE: Fee = { amount: [{ denom: DENOM, amount: "100000" }], gas: "800000" };

export const FEE_RULE = `simulated, x1.3, ${Number(GAS_PRICE_MILLI_UQOR) / 1000} uqor per gas, at most ${MAX_FEE_UQOR} uqor`;

export interface CommittedTx {
  hash: string;
  height: string;
  gasUsed: string;
  gasWanted: string;
  fee: Fee;
  /** Set only for hybrid transactions, after the chain's verdict was checked. */
  hybridVerified: boolean;
}

type Json = Record<string, unknown>;

function digits(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}$/.test(value)) throw new Error(`Unexpected ${what} in a chain answer.`);
  return BigInt(value);
}

function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

/**
 * Reads the account number and sequence the next signature must carry.
 *
 * @returns undefined when the chain has never seen the address (not funded yet).
 */
export async function accountSequence(address: string): Promise<{ accountNumber: bigint; sequence: bigint } | undefined> {
  let body: { account?: Json };
  try {
    body = await getJson<{ account?: Json }>(`${REST}/cosmos/auth/v1beta1/accounts/${encodeURIComponent(address)}`, HTTP);
  } catch (err) {
    if (err instanceof QoreHttpError && err.status === 404) return undefined;
    throw err;
  }
  const record = (body.account?.base_account ?? body.account) as Json | undefined;
  if (record === undefined) throw new Error("The account answer carries no account record.");
  return { accountNumber: digits(record.account_number, "account number"), sequence: digits(record.sequence, "sequence") };
}

/**
 * Prices a simulated transaction: gas limit = simulated x 1.3 rounded up, fee =
 * gas limit x 0.15 uqor rounded up. Refuses a fee under the 0.1 uqor floor or
 * above MAX_FEE_UQOR.
 */
export function feeFromSimulation(gasUsed: bigint): Fee {
  const gas = ceilDiv(gasUsed * GAS_ADJUSTMENT_PERCENT, 100n);
  checkCosmosGasLimit(gas);
  const fee: Fee = { amount: [{ denom: DENOM, amount: ceilDiv(gas * GAS_PRICE_MILLI_UQOR, 1000n).toString() }], gas: gas.toString() };
  assertFeeBounds(fee);
  return fee;
}

function assertFeeBounds(fee: Fee): void {
  const coin = fee.amount.length === 1 ? fee.amount[0] : undefined;
  if (coin === undefined || coin.denom !== DENOM) throw new Error(`A fee must be a single ${DENOM} amount.`);
  const amount = digits(coin.amount, "fee amount");
  const gas = digits(fee.gas, "gas limit");
  if (amount < ceilDiv(gas * MIN_GAS_PRICE_MILLI_UQOR, 1000n)) throw new Error(`Fee ${amount} uqor is under the 0.1 uqor per gas floor for ${gas} gas.`);
  if (amount > MAX_FEE_UQOR) throw new Error(`Fee ${amount} uqor is above the ${MAX_FEE_UQOR} uqor cap. Refusing to send.`);
}

async function simulateGas(txRawBytes: Uint8Array): Promise<bigint> {
  // postJsonRpc is the SDK's plain JSON POST with timeout and retries; a simulation is safe to repeat.
  let body: { gas_info?: { gas_used?: unknown } };
  try {
    body = await postJsonRpc<{ gas_info?: { gas_used?: unknown } }>(
      `${REST}/cosmos/tx/v1beta1/simulate`,
      { tx_bytes: Buffer.from(txRawBytes).toString("base64") },
      HTTP,
    );
  } catch (err) {
    const detail = err instanceof QoreHttpError ? ` (HTTP ${err.status}: ${(err.body ?? "").slice(0, 300)})` : "";
    throw new Error(`Simulation failed, nothing was sent${detail}: ${err instanceof Error ? err.message.slice(0, 300) : String(err)}`);
  }
  return digits(body.gas_info?.gas_used, "simulated gas");
}

/** Reads a committed transaction over REST, waiting for the indexer, and requires code 0. */
async function fetchCommitted(hash: string): Promise<Json> {
  let body: Json;
  try {
    body = await withRetry(() => getJson<Json>(`${REST}/cosmos/tx/v1beta1/txs/${hash}`, HTTP), {
      retries: 12,
      backoff: 2_000,
      maxBackoff: 6_000,
    });
  } catch (err) {
    if (err instanceof QoreHttpError && err.status === 404) {
      throw new Error(`Transaction ${hash} was not found on chain after about a minute. Look it up before sending anything again.`);
    }
    throw err;
  }
  const response = body.tx_response as Json | undefined;
  if (response === undefined || typeof response.code !== "number") throw new Error(`Transaction ${hash}: answer has no result code.`);
  if (response.code !== 0) {
    const log = typeof response.raw_log === "string" ? response.raw_log.slice(0, 300) : "";
    throw new Error(`Transaction ${hash} failed on chain (the fee was charged): code ${response.code} ${String(response.codespace ?? "")} ${log}`);
  }
  return body;
}

/**
 * The public proof a transaction was hybrid-signed, as the docs define it: a
 * pqc_hybrid_verify event with status verified, and a 4,627-byte ML-DSA-87
 * signature in the PQCHybridSignature extension.
 */
function requireHybridVerified(hash: string, body: Json): void {
  const events = (body.tx_response as Json).events;
  const verified =
    Array.isArray(events) &&
    events.some(
      (e: Json) =>
        e.type === "pqc_hybrid_verify" &&
        Array.isArray(e.attributes) &&
        e.attributes.some((a: Json) => a.key === "status" && a.value === "verified"),
    );
  if (!verified) throw new Error(`Transaction ${hash} has no pqc_hybrid_verify event with status verified.`);
  const txBody = ((body.tx as Json | undefined)?.body ?? {}) as Json;
  const extensions = [txBody.extension_options, txBody.non_critical_extension_options].flatMap((x) => (Array.isArray(x) ? x : []));
  const hybrid = extensions.find((x: Json) => String(x["@type"]).endsWith("PQCHybridSignature")) as Json | undefined;
  const size = typeof hybrid?.pqc_signature === "string" ? Buffer.from(hybrid.pqc_signature, "base64").length : 0;
  if (size !== 4627) throw new Error(`Transaction ${hash} does not carry a 4,627-byte ML-DSA-87 signature (found ${size} bytes).`);
}

/**
 * Signs `messages` with the drill account through the SDK's EthNativeSigner
 * and broadcasts exactly once. A dropped connection is never answered with a
 * second broadcast: the hash is computed before sending and looked up on chain.
 *
 * @param mode "classical" only for MsgRegisterPQCKeyV2; everything else is "hybrid".
 * @param fee An explicit fee, or undefined to simulate and price it.
 * @throws When the account does not exist, the simulation or the fee bounds
 *   fail, the chain refuses the transaction, or a hybrid transaction lacks
 *   the chain's verified verdict.
 */
export async function sendTx(account: DrillAccount, mode: "classical" | "hybrid", messages: Messages, memo: string, fee?: Fee): Promise<CommittedTx> {
  const auth = await accountSequence(account.qor1);
  if (auth === undefined) throw new Error(`${account.qor1} does not exist on chain yet: fund it first.`);

  const signer = new EthNativeSigner(account.unified, { signMode: mode, rest: REST });
  const signBytesVersion = mode === "hybrid" ? await signer.resolveSignBytesVersion(CHAIN_ID) : undefined;
  const base = { chainId: CHAIN_ID, accountNumber: auth.accountNumber, sequence: auth.sequence, messages, memo, signBytesVersion };

  const finalFee = fee ?? feeFromSimulation(await simulateGas(signer.sign({ ...base, fee: { amount: [], gas: "0" } }).txRawBytes));
  assertFeeBounds(finalFee);

  const { txRawBytes } = signer.sign({ ...base, fee: finalFee });
  const hash = sha256Hex(txRawBytes).replace(/^0x/, "").toUpperCase();

  const transport = await withRetry(() => StargateClient.connect(RPC), { retries: 4, backoff: 2_000 });
  try {
    await transport.broadcastTx(txRawBytes, 90_000, 3_000);
  } catch (err) {
    if (err instanceof BroadcastTxError) {
      throw new Error(`Refused before inclusion (no fee charged): code ${err.code} ${err.codespace} ${(err.log ?? "").slice(0, 300)}`);
    }
    console.log(`Broadcast of ${hash} did not confirm (${err instanceof Error ? err.message.slice(0, 120) : "unknown error"}); looking it up on chain.`);
  } finally {
    transport.disconnect();
  }

  const committed = await fetchCommitted(hash);
  if (mode === "hybrid") requireHybridVerified(hash, committed);
  const response = committed.tx_response as Json;
  return {
    hash,
    height: String(response.height ?? ""),
    gasUsed: String(response.gas_used ?? ""),
    gasWanted: String(response.gas_wanted ?? ""),
    fee: finalFee,
    hybridVerified: mode === "hybrid",
  };
}
