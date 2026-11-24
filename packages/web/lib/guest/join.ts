import { challengeMessage, sameAccount, signChallenge } from "@ava/core";
import { bytesToHex, parseAbi, parseEventLogs, type Hex } from "viem";
import { api } from "../api";
import { BOARD_ID, REGISTRY, client } from "../chain";
import type { GuestAccount } from "./identity";
import { pause, throwIfStopped } from "./time";

/** A full board answers before the join is read, so the same signed join is sent again after this. */
const BOARD_FULL_WAIT_MS = 30_000;
/** Tries after a board_full or an admission_unsettled answer before the page gives up and says so. */
const MAX_RETRIES = 6;
/** The server asks for 30 s; a retry-after outside 1 to 120 s is not one it sends, so 30 s is used. */
const DEFAULT_RETRY_S = 30;
const RECEIPT_WAIT_MS = 90_000;
const memberAdded = parseAbi(["event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)"]);

/** A challenge as the demo bot issued it, checked field by field before anything is signed. */
export interface Challenge {
  registry: string;
  boardId: bigint;
  botNonce: Hex;
  expiry: bigint;
  /** The 224 bytes the guest signs, as the bot sent them. */
  message: Hex;
}

/** The join body the server reads: the guest, its challenge and the ML-DSA-87 signature over it. */
interface JoinBody {
  guest: Hex;
  botNonce: Hex;
  expiry: string;
  signature: Hex;
}

/** The demo bot refused, with its own short reason; shown to the guest as it came. */
export class JoinRefused extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(`The demo bot refused: HTTP ${status} ${reason}.`);
    this.name = "JoinRefused";
    this.status = status;
    this.reason = reason;
  }
}

/** What the join is doing, for the page's line. */
export type JoinProgress =
  | { kind: "challenge"; challenge: Challenge }
  | { kind: "retrying"; reason: "board_full" | "admission_unsettled"; seconds: number; attempt: number; of: number }
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
 * Asks the bot for this guest's challenge and refuses to go on unless the bytes it sent are the
 * spec's encoding of the fields it names, rebuilt here with challengeMessage, for the registry and
 * demo board this page knows, as live-demo-check.ts does.
 */
async function askChallenge(guest: GuestAccount, signal: AbortSignal): Promise<Challenge> {
  const response = await api("/api/demo/challenge", { json: { guest: guest.identity.qor1 }, signal });
  const body = await readAnswer(response);
  if (response.status !== 200) throw new JoinRefused(response.status, reasonOf(body));
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
    throw new Error("The challenge answer is not in the shape the bot sends.");
  }
  const challenge: Challenge = { registry, boardId: BigInt(boardId), botNonce: botNonce as Hex, expiry: BigInt(expiry), message: message.toLowerCase() as Hex };
  const rebuilt = challengeMessage({ registry: challenge.registry, boardId: challenge.boardId, guest: guest.identity.evm, botNonce: challenge.botNonce, expiry: challenge.expiry });
  if (BOARD_ID === null || challenge.boardId !== BOARD_ID || !sameAccount(challenge.registry, REGISTRY) || bytesToHex(rebuilt) !== challenge.message) {
    throw new Error("The challenge bytes are not the spec's encoding of the fields it names, for this registry and demo board. Refusing to sign.");
  }
  return challenge;
}

/** Signs the challenge with the guest's ML-DSA-87 key against the latest block's timestamp, never the device clock. */
async function signJoin(guest: GuestAccount, challenge: Challenge): Promise<JoinBody> {
  const latest = await client.getBlock({ blockTag: "latest" });
  const signed = signChallenge(guest.identity.mldsa.secretKey, {
    registry: REGISTRY,
    boardId: challenge.boardId,
    guest: guest.identity.evm,
    botNonce: challenge.botNonce,
    expiry: challenge.expiry,
    latestBlockTimestamp: latest.timestamp,
  });
  if (bytesToHex(signed.message) !== challenge.message) throw new Error("The signed challenge is not the one the bot issued. Stopping.");
  return { guest: guest.identity.evm, botNonce: challenge.botNonce, expiry: challenge.expiry.toString(), signature: bytesToHex(signed.signature) };
}

function retryAfterMs(response: Response): number {
  const raw = response.headers.get("retry-after");
  const seconds = raw !== null && /^\d{1,3}$/.test(raw) ? Number(raw) : DEFAULT_RETRY_S;
  return (seconds >= 1 && seconds <= 120 ? seconds : DEFAULT_RETRY_S) * 1000;
}

/**
 * Asks for a challenge, signs it and asks to join, until the bot admits the guest or refuses for a
 * reason the guest has to see. board_full is answered before the join is read, with nothing
 * consumed, so the same signed join goes again after 30 s, at most six times. admission_unsettled
 * comes after the challenge was consumed, so the next try waits its retry-after and signs a fresh
 * challenge. A board that filled while the bot held its lock also answers board_full, but after the
 * challenge was consumed; the resend then meets no_challenge, and only right after a board_full is
 * that taken as the cue for a fresh challenge. Every other refusal is thrown as it came.
 *
 * @returns The addMember's EVM hash: the bot's claim that it was sent, which the caller confirms.
 * @throws JoinRefused for a refusal, or once the retries are spent. Error when a challenge fails
 *   its checks.
 */
export async function challengeAndJoin(guest: GuestAccount, signal: AbortSignal, progress: (p: JoinProgress) => void): Promise<Hex> {
  const fresh = async (): Promise<JoinBody> => {
    const challenge = await askChallenge(guest, signal);
    progress({ kind: "challenge", challenge });
    return signJoin(guest, challenge);
  };
  let body = await fresh();
  let retries = 0;
  let afterBoardFull = false;
  for (;;) {
    throwIfStopped(signal);
    const response = await api("/api/demo/join", { json: body, signal });
    const answer = await readAnswer(response);
    if (response.status === 202) {
      const txHash = answer.txHash;
      if (typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error("The bot's answer carries no transaction hash.");
      progress({ kind: "sent", txHash: txHash.toLowerCase() as Hex });
      return txHash.toLowerCase() as Hex;
    }
    const reason = reasonOf(answer);
    if (reason === "no_challenge" && afterBoardFull) {
      afterBoardFull = false;
      body = await fresh();
      continue;
    }
    if (response.status !== 503 || (reason !== "board_full" && reason !== "admission_unsettled")) throw new JoinRefused(response.status, reason);
    if (retries >= MAX_RETRIES) throw new JoinRefused(response.status, `${reason}, still after ${MAX_RETRIES} retries`);
    retries++;
    const waitMs = reason === "board_full" ? BOARD_FULL_WAIT_MS : retryAfterMs(response);
    progress({ kind: "retrying", reason, seconds: waitMs / 1000, attempt: retries, of: MAX_RETRIES });
    await pause(waitMs, signal);
    afterBoardFull = reason === "board_full";
    if (reason === "admission_unsettled") body = await fresh();
  }
}

/**
 * Waits for the addMember's receipt on the public EVM RPC and confirms it is this guest's own
 * admission (threat model C26): the hash the bot answered with is only a claim, so the receipt must
 * show success and carry the registry's MemberAdded event for this board and this account. Any
 * other successful transaction, or the right event from another contract, does not count.
 *
 * @throws Error when it reverted, was not seen within 90 s, or does not admit this account.
 */
export async function confirmJoin(txHash: Hex, guest: Hex, boardId: bigint): Promise<bigint> {
  let receipt;
  try {
    receipt = await client.waitForTransactionReceipt({ hash: txHash, timeout: RECEIPT_WAIT_MS, pollingInterval: 1_500 });
  } catch {
    throw new Error(`The addMember ${txHash} was not seen on chain within ${RECEIPT_WAIT_MS / 1000} s.`);
  }
  if (receipt.status !== "success") throw new Error(`The addMember ${txHash} reverted.`);
  const fromRegistry = receipt.logs.filter((log) => sameAccount(log.address, REGISTRY));
  const admitted = parseEventLogs({ abi: memberAdded, logs: fromRegistry, eventName: "MemberAdded" }).some((event) => event.args.boardId === boardId && sameAccount(event.args.member, guest));
  if (!admitted) throw new Error(`The transaction ${txHash} succeeded but does not admit this account to board ${boardId}.`);
  return receipt.blockNumber;
}
