import { BroadcastTxError, StargateClient } from "@cosmjs/stargate";
import { parseEvmWindow, type EvmWindow } from "@qorechain/evm";
import { EthNativeSigner, QoreHttpError, closeEvmWindowMsg, getJson, openEvmWindowMsg, sha256Hex, type EthTxParams } from "@qorechain/sdk";
import type { Hex } from "viem";
import { CHAIN_ID, DENOM, HTTP, MAX_NATIVE_FEE_UQOR, MIN_GAS_PRICE_MILLI_UQOR, REST, RPC } from "../config.ts";
import { logEvent } from "../log.ts";
import type { RelayerAccount } from "./account.ts";
import { OutOfTime, leftMs, pause, within, type Deadline } from "./deadline.ts";
import { NotBroadcast, type BeforeBroadcast, type TxStatus } from "./evm.ts";

export type Messages = EthTxParams["messages"];
export type Fee = EthTxParams["fee"];

export interface CommittedTx {
  hash: string;
  height: string;
  gasUsed: string;
  gasWanted: string;
  fee: Fee;
}

type Json = Record<string, unknown>;

/** The node refused the transaction before any block included it: no fee was charged and no sequence used. */
export class RefusedBeforeInclusion extends Error {
  readonly code: number;
  readonly codespace: string;

  constructor(code: number, codespace: string) {
    super(`Refused before inclusion (no fee charged): code ${code} ${codespace}`);
    this.name = "RefusedBeforeInclusion";
    this.code = code;
    this.codespace = codespace;
  }
}

/** How often a broadcast transaction is looked up while waiting for its block (blocks are about 1.4 s). */
const COMMIT_POLL_MS = 1_500;

function digits(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}$/.test(value)) throw new Error(`Unexpected ${what} in a chain answer.`);
  return BigInt(value);
}

function ceilDiv(a: bigint, b: bigint): bigint {
  return (a + b - 1n) / b;
}

/**
 * Reads the account number and sequence the next signature must carry. The sequence is the
 * committed one: an EVM transaction still waiting in the mempool is not counted.
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

/** The account's uqor balance from the bank module, 0 for an account the chain has never seen. */
export async function balanceOf(address: string): Promise<bigint> {
  const body = await getJson<{ balances?: unknown }>(`${REST}/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`, HTTP);
  if (!Array.isArray(body.balances)) throw new Error("Unexpected balance answer: no balances list.");
  const coin = body.balances.find((c: { denom?: unknown }) => c?.denom === DENOM) as { amount?: unknown } | undefined;
  if (coin === undefined) return 0n;
  if (typeof coin.amount !== "string" || !/^\d{1,40}$/.test(coin.amount)) throw new Error("Unexpected balance amount.");
  return BigInt(coin.amount);
}

/**
 * The account's EVM window, read straight from the chain's REST (never through our own proxy
 * handler) and parsed by the SDK's own parser.
 */
export async function readEvmWindow(qor1: string): Promise<EvmWindow> {
  return parseEvmWindow(await getJson<unknown>(`${REST}/qorechain/pqc/v1/evm_window/${encodeURIComponent(qor1)}`, HTTP));
}

function assertFeeBounds(fee: Fee): bigint {
  const coin = fee.amount.length === 1 ? fee.amount[0] : undefined;
  if (coin === undefined || coin.denom !== DENOM) throw new Error(`A fee must be a single ${DENOM} amount.`);
  const amount = digits(coin.amount, "fee amount");
  const gas = digits(fee.gas, "gas limit");
  if (amount < ceilDiv(gas * MIN_GAS_PRICE_MILLI_UQOR, 1000n)) throw new Error(`Fee ${amount} uqor is under the 0.1 uqor per gas floor for ${gas} gas.`);
  if (amount > MAX_NATIVE_FEE_UQOR) throw new Error(`Fee ${amount} uqor is above the ${MAX_NATIVE_FEE_UQOR} uqor cap. Refusing to send.`);
  return amount;
}

/**
 * Looks a broadcast transaction up over REST until it is indexed or the deadline passes, and
 * requires code 0. Running out of time is not a refusal: the transaction may still land.
 */
async function fetchCommitted(hash: string, deadline: Deadline): Promise<Json> {
  for (;;) {
    try {
      const body = await within(deadline, getJson<Json>(`${REST}/cosmos/tx/v1beta1/txs/${hash}`, HTTP), "the commit lookup");
      const response = body.tx_response as Json | undefined;
      if (response === undefined || typeof response.code !== "number") throw new Error(`Transaction ${hash}: answer has no result code.`);
      if (response.code !== 0) throw new Error(`Transaction ${hash} failed on chain (the fee was charged): code ${response.code} ${String(response.codespace ?? "")}`);
      return body;
    } catch (err) {
      const notYet = err instanceof QoreHttpError && err.status === 404;
      if (!notYet && !(err instanceof OutOfTime)) throw err;
      if (leftMs(deadline) <= COMMIT_POLL_MS) throw new Error(`Transaction ${hash} was not seen on chain in time. Look it up before sending anything again.`);
      await pause(COMMIT_POLL_MS);
    }
  }
}

/**
 * The public proof a transaction was hybrid-signed, as the docs define it: a pqc_hybrid_verify
 * event with status verified, and a 4,627-byte ML-DSA-87 signature in the PQCHybridSignature extension.
 */
function requireHybridVerified(hash: string, body: Json): void {
  const events = (body.tx_response as Json).events;
  const verified =
    Array.isArray(events) &&
    events.some(
      (e: Json) => e.type === "pqc_hybrid_verify" && Array.isArray(e.attributes) && e.attributes.some((a: Json) => a.key === "status" && a.value === "verified"),
    );
  if (!verified) throw new Error(`Transaction ${hash} has no pqc_hybrid_verify event with status verified.`);
  const txBody = ((body.tx as Json | undefined)?.body ?? {}) as Json;
  const extensions = [txBody.extension_options, txBody.non_critical_extension_options].flatMap((x) => (Array.isArray(x) ? x : []));
  const hybrid = extensions.find((x: Json) => String(x["@type"]).endsWith("PQCHybridSignature")) as Json | undefined;
  const size = typeof hybrid?.pqc_signature === "string" ? Buffer.from(hybrid.pqc_signature, "base64").length : 0;
  if (size !== 4627) throw new Error(`Transaction ${hash} does not carry a 4,627-byte ML-DSA-87 signature (found ${size} bytes).`);
}

/**
 * Signs `messages` with the relayer through the SDK's EthNativeSigner, with an explicit fee, and
 * broadcasts exactly once. A dropped connection is never answered with a second broadcast: the hash
 * is computed before sending and looked up on chain. Every wait ends by `deadline`.
 *
 * @param mode "classical" only for MsgRegisterPQCKeyV2; everything else is "hybrid".
 * @param beforeBroadcast Given the sequence and hash once signed, before the broadcast (threat model
 *   C24). If it throws, nothing is sent.
 * @throws OutOfTime before the broadcast (nothing was sent). NotBroadcast when beforeBroadcast threw
 *   (nothing was sent). RefusedBeforeInclusion when the node refused it at broadcast (no fee
 *   charged). An Error when the account does not exist, the fee is outside its bounds, the chain
 *   refuses the transaction in a block, it is not seen in time, or a hybrid transaction lacks the
 *   chain's verified verdict.
 */
export async function sendNative(
  account: RelayerAccount,
  mode: "classical" | "hybrid",
  messages: Messages,
  fee: Fee,
  deadline: Deadline,
  beforeBroadcast?: BeforeBroadcast,
): Promise<CommittedTx> {
  assertFeeBounds(fee);
  const auth = await within(deadline, accountSequence(account.qor1), "reading the sequence");
  if (auth === undefined) throw new Error(`${account.qor1} does not exist on chain yet: fund it first.`);

  const signer = new EthNativeSigner(account.unified, { signMode: mode, rest: REST });
  const signBytesVersion = mode === "hybrid" ? await within(deadline, signer.resolveSignBytesVersion(CHAIN_ID), "resolving the sign bytes") : undefined;
  const { txRawBytes } = signer.sign({ chainId: CHAIN_ID, accountNumber: auth.accountNumber, sequence: auth.sequence, messages, memo: "", fee, signBytesVersion });
  const hash = sha256Hex(txRawBytes).replace(/^0x/, "").toUpperCase();
  try {
    await beforeBroadcast?.({ kind: "native", nonce: auth.sequence, hash });
  } catch {
    throw new NotBroadcast("The native transaction could not be recorded before its broadcast: nothing was sent.");
  }

  const transport = await within(deadline, StargateClient.connect(RPC), "connecting to the RPC");
  const waitMs = leftMs(deadline);
  if (waitMs <= COMMIT_POLL_MS) {
    transport.disconnect();
    throw new OutOfTime("the broadcast");
  }
  try {
    await transport.broadcastTx(txRawBytes, waitMs, COMMIT_POLL_MS);
  } catch (err) {
    if (err instanceof BroadcastTxError) throw new RefusedBeforeInclusion(err.code, err.codespace);
    logEvent("native_broadcast_unconfirmed", { hash });
  } finally {
    transport.disconnect();
  }

  const committed = await fetchCommitted(hash, deadline);
  if (mode === "hybrid") requireHybridVerified(hash, committed);
  const response = committed.tx_response as Json;
  return { hash, height: String(response.height ?? ""), gasUsed: String(response.gas_used ?? ""), gasWanted: String(response.gas_wanted ?? ""), fee };
}

/**
 * Where the relayer's native transaction `hash` (64 hex digits) stands: "landed" when the chain's
 * REST holds it at a block height, whatever its result code, because a failed transaction still
 * used its sequence; "unknown" on a 404. The REST shows no pool, so this never answers "pending".
 * Any other answer, or one naming another transaction, is thrown.
 */
export async function nativeTxStatus(hash: string): Promise<TxStatus> {
  if (!/^[0-9A-F]{64}$/.test(hash)) throw new Error("A native transaction hash is 64 uppercase hex digits.");
  let body: Json;
  try {
    body = await getJson<Json>(`${REST}/cosmos/tx/v1beta1/txs/${hash}`, HTTP);
  } catch (err) {
    if (err instanceof QoreHttpError && err.status === 404) return "unknown";
    throw err;
  }
  const response = body.tx_response as Json | undefined;
  const named = typeof response?.txhash === "string" ? response.txhash.toUpperCase() : undefined;
  if (named !== hash || typeof response?.height !== "string" || !/^[1-9]\d{0,19}$/.test(response.height)) {
    throw new Error(`Transaction ${hash}: the lookup answered with something else.`);
  }
  return "landed";
}

export interface WindowRequest {
  blocks: number;
  maxTxs: number;
  maxValue: bigint;
  allowedTargets: readonly Hex[];
}

/**
 * Opens (and so replaces) the relayer's EVM window with exactly these bounds, by a hybrid-signed
 * MsgOpenEVMWindow at the given explicit fee. A window with no targets would be unscoped, so an
 * empty list is refused here and never reaches the chain; nativeOnly is never set. `beforeBroadcast`
 * is sendNative's.
 */
export async function openWindowTx(account: RelayerAccount, request: WindowRequest, fee: Fee, deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<CommittedTx> {
  if (request.allowedTargets.length === 0) throw new Error("Refusing to open an unscoped window.");
  const message = openEvmWindowMsg({
    sender: account.qor1,
    blocks: request.blocks,
    maxTxs: request.maxTxs,
    maxValue: request.maxValue,
    allowedTargets: [...request.allowedTargets],
  });
  return sendNative(account, "hybrid", [message], fee, deadline, beforeBroadcast);
}

/**
 * Closes the relayer's window at once by a hybrid-signed MsgCloseEVMWindow; the chain refuses what it
 * admitted from the next block. `beforeBroadcast` is sendNative's.
 */
export async function closeWindowTx(account: RelayerAccount, fee: Fee, deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<CommittedTx> {
  return sendNative(account, "hybrid", [closeEvmWindowMsg(account.qor1)], fee, deadline, beforeBroadcast);
}
