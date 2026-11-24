import { leaveMessage, sameAccount, signLeave } from "@ava/core";
import { bytesToHex, parseAbi, parseEventLogs, type Hex, type Log } from "viem";
import { api } from "../api";
import { BOARD_ID, REGISTRY, client } from "../chain";
import type { GuestAccount } from "./identity";
import { pause, throwIfStopped } from "./time";

/** Tries after an answer that says the bot could not act yet, each on a fresh request, before the page says so. */
const MAX_RETRIES = 4;
/** The server asks for 30 s; a retry-after outside 1 to 120 s is not one it sends for these, so 30 s is used. */
const DEFAULT_RETRY_S = 30;
const RECEIPT_WAIT_MS = 90_000;
/** Refusals that pass on their own: the board's lock was held, a key lookup failed, or the chain did not answer. */
const PASSING = new Set(["busy", "kem_unavailable", "leave_failed", "store_unavailable", "chain_unreachable"]);
const memberRemoved = parseAbi(["event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)"]);

/** A leave request as the demo bot issued it, checked field by field before anything is signed. */
export interface LeaveRequest {
  registry: string;
  boardId: bigint;
  botNonce: Hex;
  expiry: bigint;
  /** The 224 bytes the guest signs, as the bot sent them. */
  message: Hex;
}

interface LeaveBody {
  guest: Hex;
  botNonce: Hex;
  expiry: string;
  signature: Hex;
}

/** The demo bot refused the leave, with its own short reason. */
export class LeaveRefused extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(`The demo bot refused: HTTP ${status} ${reason}.`);
    this.name = "LeaveRefused";
    this.status = status;
    this.reason = reason;
  }
}

export type LeaveProgress =
  | { kind: "request"; request: LeaveRequest }
  | { kind: "retrying"; reason: string; seconds: number; attempt: number; of: number }
  | { kind: "sent"; txHash: Hex };

type Json = Record<string, unknown>;

async function readAnswer(response: Response): Promise<Json> {
  try {
    const body: unknown = await response.json();
    return body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Json) : {};
  } catch {
    return {};
  }
}

function reasonOf(body: Json): string {
  return typeof body.error === "string" && /^[A-Za-z0-9_]{1,64}$/.test(body.error) ? body.error : "unknown";
}

/**
 * Decides whether a leave request the bot sent may be signed (threat model C45, C47). The page
 * never signs bytes because a server supplied them: the bytes must be the spec's leave message,
 * rebuilt here with leaveMessage from the fields beside them, for this guest's own account and the
 * registry and demo board this page knows. A join challenge for the same fields carries another
 * tag, so it is refused here like any other bytes.
 *
 * @throws Error when the answer is not in the bot's shape, or its bytes are not that encoding.
 */
export function checkLeaveRequest(body: Record<string, unknown>, expected: { registry: string; boardId: bigint; guest: Hex }): LeaveRequest {
  const { registry, boardId, botNonce, expiry, message } = body;
  if (
    typeof registry !== "string" ||
    typeof boardId !== "string" ||
    !/^[1-9]\d{0,19}$/.test(boardId) ||
    typeof botNonce !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(botNonce) ||
    typeof expiry !== "string" ||
    !/^[1-9]\d{0,19}$/.test(expiry) ||
    typeof message !== "string" ||
    !/^0x[0-9a-fA-F]+$/.test(message)
  ) {
    throw new Error("The leave request is not in the shape the bot sends.");
  }
  const request: LeaveRequest = { registry, boardId: BigInt(boardId), botNonce: botNonce as Hex, expiry: BigInt(expiry), message: message.toLowerCase() as Hex };
  let rebuilt: string | undefined;
  try {
    rebuilt = bytesToHex(leaveMessage({ registry: request.registry, boardId: request.boardId, guest: expected.guest, botNonce: request.botNonce, expiry: request.expiry }));
  } catch {
    rebuilt = undefined;
  }
  if (request.boardId !== expected.boardId || !sameAccount(request.registry, expected.registry) || rebuilt !== request.message) {
    throw new Error("The leave request's bytes are not the spec's encoding of the fields it names, for this account, registry and demo board. Refusing to sign.");
  }
  return request;
}

/**
 * The registry's own record that this account was removed from this board, read from a receipt's
 * logs (threat model C26): a MemberRemoved event emitted by the registry itself, for this board and
 * this member. The same event from any other contract, or for anyone else, does not count.
 *
 * @returns The epoch the removal moved the board to, or undefined when the logs hold no such event.
 */
export function removalIn(logs: readonly Log[], expected: { registry: string; boardId: bigint; guest: Hex }): { epoch: bigint } | undefined {
  const fromRegistry = logs.filter((log) => sameAccount(log.address, expected.registry));
  const event = parseEventLogs({ abi: memberRemoved, logs: [...fromRegistry], eventName: "MemberRemoved" }).find((e) => e.args.boardId === expected.boardId && sameAccount(e.args.member, expected.guest));
  return event === undefined ? undefined : { epoch: event.args.newEpoch };
}

async function askLeave(guest: GuestAccount, signal: AbortSignal): Promise<LeaveRequest> {
  if (BOARD_ID === null) throw new Error("NEXT_PUBLIC_DEMO_BOARD_ID is not set.");
  const response = await api("/api/demo/leave/challenge", { json: { guest: guest.identity.qor1 }, signal });
  const body = await readAnswer(response);
  if (response.status !== 200) throw new LeaveRefused(response.status, reasonOf(body));
  return checkLeaveRequest(body, { registry: REGISTRY, boardId: BOARD_ID, guest: guest.identity.evm });
}

/** Signs the leave with the guest's ML-DSA-87 key through signLeave, against the latest block's timestamp, never the device clock. */
async function signRequest(guest: GuestAccount, request: LeaveRequest): Promise<LeaveBody> {
  const latest = await client.getBlock({ blockTag: "latest" });
  const signed = signLeave(guest.identity.mldsa.secretKey, {
    registry: REGISTRY,
    boardId: request.boardId,
    guest: guest.identity.evm,
    botNonce: request.botNonce,
    expiry: request.expiry,
    latestBlockTimestamp: latest.timestamp,
  });
  if (bytesToHex(signed.message) !== request.message) throw new Error("The signed leave is not the request the bot issued. Stopping.");
  return { guest: guest.identity.evm, botNonce: request.botNonce, expiry: request.expiry.toString(), signature: bytesToHex(signed.signature) };
}

function retryAfterMs(response: Response): number {
  const raw = response.headers.get("retry-after");
  const seconds = raw !== null && /^\d{1,3}$/.test(raw) ? Number(raw) : DEFAULT_RETRY_S;
  return (seconds >= 1 && seconds <= 120 ? seconds : DEFAULT_RETRY_S) * 1000;
}

/**
 * Asks the bot for a leave request, signs it and sends it, until the bot answers that the removal
 * was sent or refuses for a reason the guest has to see. A leave request is used up before the bot
 * takes the board's lock, so every retry asks for a fresh one: after a refusal that passes on its
 * own (the lock was held, a key lookup failed), at most four times, and once after a no_challenge,
 * which is what a second click or a request that ran out meets. demo_busy lasts until the hour
 * turns, so it is thrown for the page to say.
 *
 * @returns The removeMember's EVM hash: the bot's claim that it was sent, which the caller confirms.
 * @throws LeaveRefused for a refusal, or once the retries are spent. Error when a request fails its checks.
 */
export async function requestLeave(guest: GuestAccount, signal: AbortSignal, progress: (p: LeaveProgress) => void): Promise<Hex> {
  const fresh = async (): Promise<LeaveBody> => {
    const request = await askLeave(guest, signal);
    progress({ kind: "request", request });
    return signRequest(guest, request);
  };
  let body = await fresh();
  let retries = 0;
  let askedAgain = false;
  for (;;) {
    throwIfStopped(signal);
    const response = await api("/api/demo/leave", { json: body, signal });
    const answer = await readAnswer(response);
    if (response.status === 202) {
      const txHash = answer.txHash;
      if (typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error("The bot's answer carries no transaction hash.");
      progress({ kind: "sent", txHash: txHash.toLowerCase() as Hex });
      return txHash.toLowerCase() as Hex;
    }
    const reason = reasonOf(answer);
    if (reason === "no_challenge" && !askedAgain) {
      askedAgain = true;
      body = await fresh();
      continue;
    }
    if (!PASSING.has(reason) || (response.status !== 503 && response.status !== 502)) throw new LeaveRefused(response.status, reason);
    if (retries >= MAX_RETRIES) throw new LeaveRefused(response.status, `${reason}, still after ${MAX_RETRIES} retries`);
    retries++;
    const waitMs = retryAfterMs(response);
    progress({ kind: "retrying", reason, seconds: waitMs / 1000, attempt: retries, of: MAX_RETRIES });
    await pause(waitMs, signal);
    body = await fresh();
  }
}

/**
 * Waits for the removeMember's receipt on the public EVM RPC and confirms it is this guest's own
 * removal (threat model C26): the hash the bot answered with is only a claim, so the receipt must
 * show success and carry the registry's MemberRemoved event for this board and this account.
 *
 * @returns The block it landed in and the epoch it moved the board to.
 * @throws Error when it reverted, was not seen within 90 s, or does not remove this account.
 */
export async function confirmLeave(txHash: Hex, guest: Hex, boardId: bigint): Promise<{ block: bigint; epoch: bigint }> {
  let receipt;
  try {
    receipt = await client.waitForTransactionReceipt({ hash: txHash, timeout: RECEIPT_WAIT_MS, pollingInterval: 1_500 });
  } catch {
    throw new Error(`The removeMember ${txHash} was not seen on chain within ${RECEIPT_WAIT_MS / 1000} s.`);
  }
  if (receipt.status !== "success") throw new Error(`The removeMember ${txHash} reverted.`);
  const removed = removalIn(receipt.logs, { registry: REGISTRY, boardId, guest });
  if (removed === undefined) throw new Error(`The transaction ${txHash} succeeded but does not remove this account from board ${boardId}.`);
  return { block: receipt.blockNumber, epoch: removed.epoch };
}
