import { CHAIN_ID } from "@ava/core";
import { EthNativeSigner, sha256Hex, type EthTxParams } from "@qorechain/sdk";
import type { GuestAccount } from "./identity";
import { ChainHttpError, DENOM, accountSequence, chainGet, chainPost, proxyFetch, proxyRest } from "./proxy";
import { OutOfTime, leftMs, pause, throwIfStopped, type Deadline } from "./time";

export type Messages = EthTxParams["messages"];
export type Fee = EthTxParams["fee"];

export interface CommittedTx {
  /** 64 uppercase hex digits, as the chain's REST writes it. */
  hash: string;
  height: string;
  gasUsed: string;
  gasWanted: string;
}

/** No native-lane fee may exceed this, whatever a caller passes (packages/server/src/config.ts MAX_NATIVE_FEE_UQOR). */
const MAX_NATIVE_FEE_UQOR = 200_000n;
/** The chain refuses any native transaction priced under 0.1 uqor per gas, kept in thousandths of a uqor. */
const MIN_GAS_PRICE_MILLI_UQOR = 100n;
/**
 * How often a broadcast transaction is looked up while waiting for its block. Blocks are about
 * 1.4 s; 2 s keeps one wait under the proxy's 60 requests a minute shared by everything on this IP.
 */
const COMMIT_POLL_MS = 2_000;
const ML_DSA_87_SIGNATURE = 4_627;

type Json = Record<string, unknown>;

/** The node refused the transaction before any block included it: no fee was charged and no sequence used. */
export class RefusedBeforeInclusion extends Error {
  readonly code: number;
  readonly codespace: string;

  constructor(code: number, codespace: string) {
    super(`The chain refused the transaction before any block (no fee charged): code ${code} ${codespace}`.trim());
    this.name = "RefusedBeforeInclusion";
    this.code = code;
    this.codespace = codespace;
  }
}

function digits(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}$/.test(value)) throw new Error(`Unexpected ${what} in a fee.`);
  return BigInt(value);
}

function assertFeeBounds(fee: Fee): void {
  const coin = fee.amount.length === 1 ? fee.amount[0] : undefined;
  if (coin === undefined || coin.denom !== DENOM) throw new Error(`A fee must be a single ${DENOM} amount.`);
  const amount = digits(coin.amount, "fee amount");
  const gas = digits(fee.gas, "gas limit");
  if (amount * 1000n < gas * MIN_GAS_PRICE_MILLI_UQOR) throw new Error(`Fee ${amount} uqor is under the 0.1 uqor per gas floor for ${gas} gas.`);
  if (amount > MAX_NATIVE_FEE_UQOR) throw new Error(`Fee ${amount} uqor is above the ${MAX_NATIVE_FEE_UQOR} uqor cap. Refusing to send.`);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function base64Length(value: string): number {
  try {
    return atob(value).length;
  } catch {
    return 0;
  }
}

/**
 * Broadcasts once in BROADCAST_MODE_SYNC through the proxy. A non-zero code is the node's CheckTx
 * refusal, before any block. A lost or failed answer from upstream may still have reached the node,
 * so it is never answered with a second broadcast: the caller looks the hash up instead.
 *
 * @returns "sent" when the node accepted it, "unknown" when the answer was lost.
 * @throws RefusedBeforeInclusion for a CheckTx refusal or a proxy refusal that never went upstream.
 */
async function broadcastOnce(txRawBytes: Uint8Array, hash: string, signal: AbortSignal): Promise<"sent" | "unknown"> {
  let body: Json;
  try {
    body = await chainPost("/cosmos/tx/v1beta1/txs", { tx_bytes: toBase64(txRawBytes), mode: "BROADCAST_MODE_SYNC" }, signal);
  } catch (error) {
    if (signal.aborted) throw error;
    // A 502 or 504 means the proxy reached for upstream and lost the answer; a network failure may have
    // lost it after sending. Every other status is a refusal made before anything went upstream.
    if (error instanceof ChainHttpError && error.status !== 502 && error.status !== 504) throw new RefusedBeforeInclusion(error.status, error.error ?? "proxy");
    return "unknown";
  }
  const response = body.tx_response as Json | undefined;
  if (response === undefined || typeof response.code !== "number") return "unknown";
  if (response.code !== 0) throw new RefusedBeforeInclusion(response.code, String(response.codespace ?? ""));
  if (typeof response.txhash !== "string" || response.txhash.toUpperCase() !== hash) {
    throw new Error(`The node answered for another transaction than ${hash}. Look it up before sending anything again.`);
  }
  return "sent";
}

/**
 * Looks the transaction up through the proxy until it is in a block or the deadline passes, and
 * requires code 0. A 404 is "not yet"; a rate limit or a lost upstream answer is waited out, because
 * after a broadcast running out of patience is not a refusal: the transaction may still land.
 */
async function fetchCommitted(hash: string, deadline: Deadline, signal: AbortSignal): Promise<Json> {
  for (;;) {
    throwIfStopped(signal);
    try {
      const body = await chainGet(`/cosmos/tx/v1beta1/txs/${hash}`, signal);
      const response = body.tx_response as Json | undefined;
      if (response === undefined || typeof response.code !== "number") throw new Error(`Transaction ${hash}: the answer has no result code.`);
      if (typeof response.txhash !== "string" || response.txhash.toUpperCase() !== hash) throw new Error(`Transaction ${hash}: the lookup answered with something else.`);
      if (response.code !== 0) throw new Error(`Transaction ${hash} failed on chain (the fee was charged): code ${response.code} ${String(response.codespace ?? "")}`.trim());
      return body;
    } catch (error) {
      const waitable = error instanceof ChainHttpError && [404, 429, 502, 504].includes(error.status);
      if (!waitable) throw error;
      if (leftMs(deadline) <= COMMIT_POLL_MS) throw new Error(`Transaction ${hash} was not seen on chain in time. Look it up before sending anything again.`);
      await pause(COMMIT_POLL_MS, signal);
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
  const size = typeof hybrid?.pqc_signature === "string" ? base64Length(hybrid.pqc_signature) : 0;
  if (size !== ML_DSA_87_SIGNATURE) throw new Error(`Transaction ${hash} does not carry a 4,627-byte ML-DSA-87 signature (found ${size} bytes).`);
}

/**
 * The browser's port of the server's sendNative: signs `messages` with the guest through the SDK's
 * EthNativeSigner at an explicit fee, broadcasts exactly once through the chain proxy, and waits
 * for its block. The account number and sequence come from the proxy's accounts route, and the
 * hybrid sign-bytes form from the SDK's own lookup through the same proxy. The hash is computed
 * before sending, so a lost answer is looked up, never sent again.
 *
 * @param mode "classical" only for MsgRegisterPQCKeyV2; everything else is "hybrid".
 * @param onSigned Given the hash once signed, before the broadcast, so the page can show it.
 * @throws OutOfTime before the broadcast (nothing was sent). RefusedBeforeInclusion when the node
 *   or the proxy refused it before any block (no fee charged). An Error when the account does not
 *   exist, the fee is outside its bounds, the chain refuses it in a block, it is not seen in time,
 *   or a hybrid transaction lacks the chain's verified verdict. Stopped when `signal` fires.
 */
export async function sendNative(
  guest: GuestAccount,
  mode: "classical" | "hybrid",
  messages: Messages,
  fee: Fee,
  deadline: Deadline,
  signal: AbortSignal,
  onSigned?: (hash: string) => void,
): Promise<CommittedTx> {
  assertFeeBounds(fee);
  const qor1 = guest.identity.qor1;
  const auth = await accountSequence(qor1, signal);
  if (auth === undefined) throw new Error(`${qor1} does not exist on chain yet: fund it first.`);

  const signer = new EthNativeSigner(guest.unified, { signMode: mode, rest: proxyRest(), fetch: proxyFetch });
  const signBytesVersion = mode === "hybrid" ? await signer.resolveSignBytesVersion(CHAIN_ID) : undefined;
  const { txRawBytes } = signer.sign({ chainId: CHAIN_ID, accountNumber: auth.accountNumber, sequence: auth.sequence, messages, memo: "", fee, signBytesVersion });
  const hash = sha256Hex(txRawBytes).replace(/^0x/, "").toUpperCase();
  throwIfStopped(signal);
  if (leftMs(deadline) <= COMMIT_POLL_MS) throw new OutOfTime("before the broadcast");
  onSigned?.(hash);

  await broadcastOnce(txRawBytes, hash, signal);
  const committed = await fetchCommitted(hash, deadline, signal);
  if (mode === "hybrid") requireHybridVerified(hash, committed);
  const response = committed.tx_response as Json;
  return { hash, height: String(response.height ?? ""), gasUsed: String(response.gas_used ?? ""), gasWanted: String(response.gas_wanted ?? "") };
}
