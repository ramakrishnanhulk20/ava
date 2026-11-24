import { Action, deadlineFrom, sameAccount, sameHash, signBoardAction, type BoardActionInput, type Mode } from "@ava/core";
import { bytesToHex, parseAbi, parseEventLogs, type Hex, type Log } from "viem";
import { api } from "../api";
import { REGISTRY, client } from "../chain";
import { throwIfStopped } from "../guest/time";

/** How long a chair's signature stays good: long enough for an upload and a slow relay, far inside the registry's hour. */
const DEADLINE_SECONDS = 600;
const RECEIPT_WAIT_MS = 90_000;

const registryEvents = parseAbi([
  "event BoardCreated(uint256 indexed boardId, address indexed chair, bytes32 boardRef, uint64 createNonce)",
  "event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)",
  "event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)",
  "event EpochRotated(uint256 indexed boardId, uint64 indexed newEpoch, uint64 nonce)",
  "event DocumentPosted(uint256 indexed boardId, uint256 indexed docId, bytes32 docRef, uint64 epoch, bytes32 cipherHash, uint64 cipherSize, uint64 nonce)",
]);

/** One board change as the chair's screens state it: typed fields only, never bytes. */
export type ChairAction =
  | { action: "create"; chair: Hex; boardRef: Hex; envelopeHash: Hex; envelopeSize: number }
  | { action: "add"; boardId: bigint; member: Hex; mode: Mode; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint }
  | { action: "remove"; boardId: bigint; member: Hex; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint }
  | { action: "rotate"; boardId: bigint; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint }
  | { action: "post"; boardId: bigint; docRef: Hex; cipherHash: Hex; cipherSize: bigint; epoch: bigint };

/** What the page waits for before it calls an action done. */
export type Expected =
  | { registry: string; action: "create"; chair: Hex; boardRef: Hex; nonce: bigint }
  | { registry: string; action: "add" | "remove"; boardId: bigint; member: Hex; nonce: bigint }
  | { registry: string; action: "rotate"; boardId: bigint; nonce: bigint }
  | { registry: string; action: "post"; boardId: bigint; docRef: Hex; nonce: bigint };

/** The relay refused, with its own short reason. */
export class RelayRefused extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(`The relay refused: HTTP ${status} ${reason}.`);
    this.name = "RelayRefused";
    this.status = status;
    this.reason = reason;
  }
}

function input(a: ChairAction): { boardId: bigint; typed: BoardActionInput; params: Record<string, string> } {
  switch (a.action) {
    case "create":
      return {
        boardId: 0n,
        typed: { action: Action.CREATE, chair: a.chair, boardRef: a.boardRef, envelopeHash: a.envelopeHash, envelopeSize: a.envelopeSize },
        params: { chair: a.chair, boardRef: a.boardRef, envelopeHash: a.envelopeHash, envelopeSize: String(a.envelopeSize) },
      };
    case "add":
      return {
        boardId: a.boardId,
        typed: { action: Action.ADD, member: a.member, mode: a.mode, envelopeHash: a.envelopeHash, envelopeSize: a.envelopeSize, epochAfter: a.epochAfter },
        params: { member: a.member, mode: String(a.mode), envelopeHash: a.envelopeHash, envelopeSize: String(a.envelopeSize), epochAfter: a.epochAfter.toString() },
      };
    case "remove":
      return {
        boardId: a.boardId,
        typed: { action: Action.REMOVE, member: a.member, envelopeHash: a.envelopeHash, envelopeSize: a.envelopeSize, epochAfter: a.epochAfter },
        params: { member: a.member, envelopeHash: a.envelopeHash, envelopeSize: String(a.envelopeSize), epochAfter: a.epochAfter.toString() },
      };
    case "rotate":
      return {
        boardId: a.boardId,
        typed: { action: Action.ROTATE, envelopeHash: a.envelopeHash, envelopeSize: a.envelopeSize, epochAfter: a.epochAfter },
        params: { envelopeHash: a.envelopeHash, envelopeSize: String(a.envelopeSize), epochAfter: a.epochAfter.toString() },
      };
    case "post":
      return {
        boardId: a.boardId,
        typed: { action: Action.POST, docRef: a.docRef, cipherHash: a.cipherHash, cipherSize: a.cipherSize, epoch: a.epoch },
        params: { docRef: a.docRef, cipherHash: a.cipherHash, cipherSize: a.cipherSize.toString(), epoch: a.epoch.toString() },
      };
  }
}

/**
 * Signs one board change with the chair's ML-DSA-87 key and builds the relay body for it (threat
 * model C2, C45). The signature comes from signBoardAction over typed fields this page chose, and
 * the body states those same fields, so what is sent is exactly what was signed and nothing a
 * server supplied is ever signed as bytes.
 *
 * @param at.nonce The chair's create nonce for a create, the board's nonce for everything else, read at the block the action was built from.
 * @param at.latestBlockTimestamp The latest block's timestamp, never the device clock.
 * @param at.seconds How long the signature stays good; 600 unless given, at most 3,600.
 * @returns The JSON body for POST /api/relay.
 * @throws ActionError or AddressError as signBoardAction refuses a field or a deadline.
 */
export function signedRelayBody(mldsaSecretKey: Uint8Array, a: ChairAction, at: { registry: string; nonce: bigint; latestBlockTimestamp: bigint; seconds?: number }): Record<string, unknown> {
  const { boardId, typed, params } = input(a);
  const deadline = deadlineFrom(at.latestBlockTimestamp, at.seconds ?? DEADLINE_SECONDS);
  const signed = signBoardAction(mldsaSecretKey, { ...typed, registry: at.registry, boardId, nonce: at.nonce, deadline, latestBlockTimestamp: at.latestBlockTimestamp });
  return { action: a.action, ...(a.action === "create" ? {} : { boardId: boardId.toString() }), params, deadline: deadline.toString(), signature: bytesToHex(signed.signature) };
}

/**
 * Whether a receipt's logs show that this very action landed (threat model C26): the registry's own
 * event for the action, matched on the board and the nonce the chair signed, and on what the action
 * names (the chair and boardRef of a create, the member of an add or a removal, the docRef of a
 * post). The same event from another contract does not count, and EnvelopeGranted is never read: its
 * nonce field means two different things.
 *
 * @returns The board the event names, and the new document's id for a post; undefined when no such event is there.
 */
export function landed(logs: readonly Log[], expected: Expected): { boardId: bigint; docId?: bigint } | undefined {
  const mine = parseEventLogs({ abi: registryEvents, logs: logs.filter((l) => sameAccount(l.address, expected.registry)) });
  for (const event of mine) {
    if (expected.action === "create" && event.eventName === "BoardCreated") {
      const { boardId, chair, boardRef, createNonce } = event.args;
      if (sameAccount(chair, expected.chair) && sameHash(boardRef, expected.boardRef) && createNonce === expected.nonce) return { boardId };
    }
    if (expected.action === "add" && event.eventName === "MemberAdded") {
      const { boardId, member, nonce } = event.args;
      if (boardId === expected.boardId && sameAccount(member, expected.member) && nonce === expected.nonce) return { boardId };
    }
    if (expected.action === "remove" && event.eventName === "MemberRemoved") {
      const { boardId, member, nonce } = event.args;
      if (boardId === expected.boardId && sameAccount(member, expected.member) && nonce === expected.nonce) return { boardId };
    }
    if (expected.action === "rotate" && event.eventName === "EpochRotated") {
      const { boardId, nonce } = event.args;
      if (boardId === expected.boardId && nonce === expected.nonce) return { boardId };
    }
    if (expected.action === "post" && event.eventName === "DocumentPosted") {
      const { boardId, docId, docRef, nonce } = event.args;
      if (boardId === expected.boardId && sameHash(docRef, expected.docRef) && nonce === expected.nonce) return { boardId, docId };
    }
  }
  return undefined;
}

/**
 * Hands a signed action to our relay.
 *
 * @returns The transaction hash the relay answers with: a claim it was sent, which `confirm` checks.
 * @throws RelayRefused with the relay's own status and reason.
 */
export async function relay(body: Record<string, unknown>, signal: AbortSignal): Promise<Hex> {
  throwIfStopped(signal);
  const response = await api("/api/relay", { json: body, signal });
  let answer: Record<string, unknown> = {};
  try {
    const parsed: unknown = await response.json();
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) answer = parsed as Record<string, unknown>;
  } catch {
    answer = {};
  }
  if (response.status !== 202) {
    const reason = typeof answer.error === "string" && /^[A-Za-z0-9_]{1,64}$/.test(answer.error) ? answer.error : "unknown";
    throw new RelayRefused(response.status, reason);
  }
  const txHash = answer.txHash;
  if (typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error("The relay's answer carries no transaction hash.");
  return txHash.toLowerCase() as Hex;
}

/**
 * Waits for a relayed action's receipt on the public EVM RPC and confirms it is the action the
 * chair signed (threat model C26): success, and the registry's own event for it (`landed`).
 *
 * @throws Error when it reverted, was not seen within 90 s, or carries no such event.
 */
export async function confirm(txHash: Hex, expected: Expected): Promise<{ block: bigint; boardId: bigint; docId?: bigint }> {
  let receipt;
  try {
    receipt = await client.waitForTransactionReceipt({ hash: txHash, timeout: RECEIPT_WAIT_MS, pollingInterval: 1_500 });
  } catch {
    throw new Error(`The transaction ${txHash} was not seen on chain within ${RECEIPT_WAIT_MS / 1000} s.`);
  }
  if (receipt.status !== "success") throw new Error(`The transaction ${txHash} reverted.`);
  const found = landed(receipt.logs, expected);
  if (found === undefined) throw new Error(`The transaction ${txHash} succeeded but is not the ${expected.action} this page signed.`);
  return { block: receipt.blockNumber, ...found };
}

export { REGISTRY };
