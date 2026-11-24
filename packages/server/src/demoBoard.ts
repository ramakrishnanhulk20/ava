import {
  Action,
  HashMismatch,
  ML_DSA_87_PUBKEY,
  Mode,
  assertHash,
  deadlineFrom,
  fetchKemKey,
  openEpochKey,
  sameAccount,
  sameHash,
  sha256,
  signBoardAction,
  type BoardActionInput,
  type Identity,
  type KemRecipient,
  type OpenedEpochKey,
} from "@ava/core";
import { parseEnvelope, recipientHint } from "@qorechain/qoreseal";
import { bytesToHex, decodeAbiParameters, encodeFunctionData, getAbiItem, hexToBytes, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "./abi/boardRegistry.ts";
import { handleUpload, sameUrl, type BlobBackend, type UploadContext } from "./blob.ts";
import { evmClient } from "./chain/evm.ts";
import { DEMO_ACTION_SECONDS, DEMO_GUEST_CAP, REGISTRY_ADDRESS, REGISTRY_DEPLOY_BLOCK } from "./config.ts";
import { isHttpsOrigin } from "./env.ts";
import { handleRelay, type RelayContext } from "./relay.ts";

/**
 * The pqcKeyStatus precompile with all four return values, as packages/contracts/src/interfaces/
 * IQorePQC.sol declares them. The @qorechain/evm helper decodes only three and drops
 * possessionProven, so it is never used for a decision about who may act.
 */
export const PQC_STATUS_ADDRESS = "0x0000000000000000000000000000000000000a02";
const PQC_STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;
/** The registry refuses a shorter answer too: an inactive precompile answers success with empty data. */
const MIN_STATUS_BYTES = 160;
const ML_DSA_87 = 1;
/** One ROTATE grant starts every epoch; this bounds the envelopes tried if the list holds more. */
const MAX_ENVELOPES_TRIED = 4;
/**
 * An epoch's grants are one ROTATE grant plus one per guest admitted in it, so at most
 * DEMO_GUEST_CAP of them on the demo board. Reading more than twice that stops instead.
 */
const MAX_GRANTS_READ = 2 * DEMO_GUEST_CAP;
const ENVELOPES_PARALLEL = 4;
const ENVELOPE_GRANTED = getAbiItem({ abi: boardRegistryAbi, name: "EnvelopeGranted" });
/** The most blocks one eth_getLogs read covers on the testnet RPC, as in envelopeSweep.ts. */
const GRANT_LOG_PAGE_BLOCKS = 10_000n;
/**
 * A grant search reads at most 50 pages back, about eight days at 1.4 s a block. A member no page
 * names was granted before the oldest block read, which is long past a guest's six hours.
 */
const MAX_GRANT_LOG_PAGES = 50;
const BLOCKS_PARALLEL = 4;

/** A step of a demo board action that cannot go on. `reason` is a short code this package chose. */
export class DemoStop extends Error {
  readonly status: number;
  readonly reason: string;

  constructor(status: number, reason: string) {
    super(`The demo board action stopped: ${reason}.`);
    this.name = "DemoStop";
    this.status = status;
    this.reason = reason;
  }
}

export interface KeyStatus {
  registered: boolean;
  algorithmId: number;
  pubkey: Uint8Array;
  possessionProven: boolean;
}

/** One envelope the registry recorded for an epoch. `member` is the zero address for a ROTATE grant. */
export interface Grant {
  envelopeHash: Hex;
  envelopeSize: number;
  mode: number;
  member: Hex;
}

/** A board as the registry held it at one block. */
export interface BoardSnapshot {
  boardId: bigint;
  blockNumber: bigint;
  blockTimestamp: bigint;
  chair: Hex;
  boardRef: Hex;
  epoch: bigint;
  nonce: bigint;
  members: readonly Hex[];
  /** Every grant of the current epoch, in the order the registry appended them. */
  grants: readonly Grant[];
  /** getBoard's documentCount: how many documents the board holds. */
  documentCount: number;
  /** The epoch of the board's latest document, getDocument at documentCount - 1; undefined when it holds none. */
  latestDocumentEpoch: bigint | undefined;
}

/** What the demo bot reads from the chain. Every method throws when its read fails, so callers fail closed. */
export interface DemoChain {
  /** getBoard, getMembers, the current epoch's getGrants and the latest getDocument, all at the latest block's number. */
  board(boardId: bigint): Promise<BoardSnapshot>;
  /** The account's pqcKeyStatus, all four values. */
  keyStatus(account: Hex): Promise<KeyStatus>;
  /** The account and its ML-KEM-1024 key from qor_getKEMKey, as the pair @ava/core's fetchKemKey builds (threat model C15). */
  kemKey(account: Hex): Promise<KemRecipient>;
  /** The receipt's status, or undefined when the transaction has not landed within `timeoutMs`. */
  receipt(hash: Hex, timeoutMs: number): Promise<"success" | "reverted" | undefined>;
  /**
   * For each of `members`, in order, the block timestamp in Unix seconds of the latest EnvelopeGranted
   * on this board naming it (threat model C34). A member named by none of the logs read gets the
   * timestamp of the oldest block read: it has been a member at least since then.
   */
  grantTimes(boardId: bigint, members: readonly Hex[]): Promise<bigint[]>;
}

/**
 * The latest EnvelopeGranted block naming each member, read backwards from the latest block a page
 * at a time until every member is found, the deploy block is reached, or MAX_GRANT_LOG_PAGES are
 * read. Each log is checked like an input: emitted by the registry, not removed, for this board.
 */
async function readGrantTimes(client: PublicClient, boardId: bigint, members: readonly Hex[]): Promise<bigint[]> {
  const found: (bigint | undefined)[] = members.map(() => undefined);
  let to = await client.getBlockNumber();
  let oldest = to;
  for (let page = 0; page < MAX_GRANT_LOG_PAGES && to >= REGISTRY_DEPLOY_BLOCK && found.includes(undefined); page++) {
    const from = to - GRANT_LOG_PAGE_BLOCKS + 1n > REGISTRY_DEPLOY_BLOCK ? to - GRANT_LOG_PAGE_BLOCKS + 1n : REGISTRY_DEPLOY_BLOCK;
    const logs = await client.getLogs({ address: REGISTRY_ADDRESS, event: ENVELOPE_GRANTED, args: { boardId }, fromBlock: from, toBlock: to, strict: false });
    for (const log of logs) {
      const { member } = log.args;
      if (log.removed || !sameAccount(log.address, REGISTRY_ADDRESS) || log.args.boardId !== boardId || typeof member !== "string" || typeof log.blockNumber !== "bigint") {
        throw new Error("A log is not an EnvelopeGranted event of the registry for this board.");
      }
      members.forEach((m, i) => {
        const seen = found[i];
        if (sameAccount(m, member) && (seen === undefined || log.blockNumber > seen)) found[i] = log.blockNumber;
      });
    }
    oldest = from;
    to = from - 1n;
  }
  const blocks = [...new Set(found.map((b) => b ?? oldest))];
  const times = new Map<bigint, bigint>();
  for (let start = 0; start < blocks.length; start += BLOCKS_PARALLEL) {
    await Promise.all(
      blocks.slice(start, start + BLOCKS_PARALLEL).map(async (number) => {
        const block = await client.getBlock({ blockNumber: number });
        if (block.number !== number) throw new Error("The node answered with another block.");
        times.set(number, block.timestamp);
      }),
    );
  }
  return found.map((b) => times.get(b ?? oldest) as bigint);
}

/** pqcKeyStatus read straight from the precompile with the four-value layout. Throws on empty or short data. */
export async function readKeyStatus(client: PublicClient, account: Hex): Promise<KeyStatus> {
  const { data } = await client.call({ to: PQC_STATUS_ADDRESS, data: encodeFunctionData({ abi: PQC_STATUS_ABI, functionName: "pqcKeyStatus", args: [account] }) });
  if (data === undefined || (data.length - 2) / 2 < MIN_STATUS_BYTES) throw new Error("pqcKeyStatus answered with empty or short data.");
  const [registered, algorithmId, pubkey, possessionProven] = decodeAbiParameters(PQC_STATUS_ABI[0].outputs, data);
  return { registered, algorithmId, pubkey: hexToBytes(pubkey), possessionProven };
}

/**
 * The account's ML-DSA-87 public key when, and only when, its status passes the registry's own
 * test (threat model C1): registered, algorithm 1, possession proven, exactly 2,592 bytes.
 */
export function provenMldsaKey(status: KeyStatus): Uint8Array | undefined {
  const ok = status.registered === true && status.algorithmId === ML_DSA_87 && status.possessionProven === true && status.pubkey.length === ML_DSA_87_PUBKEY;
  return ok ? status.pubkey : undefined;
}

/** The demo bot's chain reads on the live testnet, over the public EVM JSON-RPC. */
export function liveDemoChain(client: PublicClient = evmClient()): DemoChain {
  return {
    board: async (boardId) => {
      const block = await client.getBlock({ blockTag: "latest" });
      const at = { address: REGISTRY_ADDRESS, abi: boardRegistryAbi, blockNumber: block.number } as const;
      const [board, members] = await Promise.all([
        client.readContract({ ...at, functionName: "getBoard", args: [boardId] }),
        client.readContract({ ...at, functionName: "getMembers", args: [boardId] }),
      ]);
      const [grants, latest] = await Promise.all([
        client.readContract({ ...at, functionName: "getGrants", args: [boardId, board.epoch] }),
        board.documentCount > 0 ? client.readContract({ ...at, functionName: "getDocument", args: [boardId, BigInt(board.documentCount - 1)] }) : undefined,
      ]);
      return {
        boardId,
        blockNumber: block.number,
        blockTimestamp: block.timestamp,
        chair: board.chair,
        boardRef: board.boardRef,
        epoch: board.epoch,
        nonce: board.nonce,
        members,
        grants: grants.map((g) => ({ envelopeHash: g.envelopeHash, envelopeSize: g.envelopeSize, mode: g.mode, member: g.member })),
        documentCount: board.documentCount,
        latestDocumentEpoch: latest?.epoch,
      };
    },
    keyStatus: (account) => readKeyStatus(client, account),
    kemKey: (account) => fetchKemKey(account),
    grantTimes: (boardId, members) => readGrantTimes(client, boardId, members),
    receipt: async (hash, timeoutMs) => {
      if (timeoutMs <= 0) return undefined;
      try {
        return (await client.waitForTransactionReceipt({ hash, timeout: timeoutMs, pollingInterval: 1_500 })).status;
      } catch {
        return undefined;
      }
    },
  };
}

/** Where an envelope with this on-chain hash is stored: always built from the hash and BLOB_ORIGIN (C30). */
export function envelopeUrl(blobOrigin: string, envelopeHash: Hex): URL {
  if (!isHttpsOrigin(blobOrigin)) throw new DemoStop(500, "server_misconfigured");
  if (!/^0x[0-9a-fA-F]{64}$/.test(envelopeHash)) throw new DemoStop(502, "bad_envelope_hash");
  return new URL(`${blobOrigin}/envelope/${envelopeHash.slice(2).toLowerCase()}`);
}

function isNotRecipient(error: unknown): boolean {
  return error instanceof Error && (error as { code?: unknown }).code === "NOT_A_RECIPIENT";
}

/**
 * The current epoch's key, opened with the chair's QoreSeal keys (threat model C12, C35). Only
 * grants the chair can hold are tried: ROTATE grants, sealed to every member at the time, and any
 * grant naming the chair. Each envelope is downloaded from BLOB_ORIGIN by its on-chain hash,
 * stopping at its on-chain size, and openEpochKey refuses it unless its size and SHA-256 equal the
 * registry's record and its payload names this epoch, before any key is used.
 *
 * @returns An OpenedEpochKey: the one key type a document may be encrypted under (C12).
 * @throws DemoStop: envelope_unavailable when an envelope is missing or cannot be read,
 *   envelope_mismatch on any size, hash or payload failure (the join stops there), and
 *   chair_not_recipient when no grant opens.
 */
export async function openCurrentEpochKey(p: { snapshot: BoardSnapshot; sealKeys: Identity["seal"]; blobs: BlobBackend; blobOrigin: string; signal?: AbortSignal }): Promise<OpenedEpochKey> {
  const { snapshot } = p;
  const candidates = snapshot.grants.filter((g) => g.mode === Mode.ROTATE || sameAccount(g.member, snapshot.chair)).slice(0, MAX_ENVELOPES_TRIED);
  for (const grant of candidates) {
    let bytes: Uint8Array | null;
    try {
      bytes = await p.blobs.read(envelopeUrl(p.blobOrigin, grant.envelopeHash), grant.envelopeSize, p.signal);
    } catch (error) {
      if (error instanceof DemoStop) throw error;
      throw new DemoStop(502, "envelope_unavailable");
    }
    if (bytes === null) throw new DemoStop(502, "envelope_unavailable");
    try {
      return openEpochKey({
        registry: REGISTRY_ADDRESS,
        boardRef: snapshot.boardRef,
        epoch: snapshot.epoch,
        envelope: bytes,
        expectedHash: grant.envelopeHash,
        expectedSize: grant.envelopeSize,
        sealKeys: p.sealKeys,
      });
    } catch (error) {
      if (isNotRecipient(error)) continue;
      throw new DemoStop(502, "envelope_mismatch");
    }
  }
  throw new DemoStop(503, "chair_not_recipient");
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

async function hintsOf(grant: Grant, p: { blobs: BlobBackend; blobOrigin: string; signal?: AbortSignal }): Promise<{ salt: Uint8Array; hints: Uint8Array[] }> {
  let bytes: Uint8Array | null;
  try {
    bytes = await p.blobs.read(envelopeUrl(p.blobOrigin, grant.envelopeHash), grant.envelopeSize, p.signal);
  } catch (error) {
    if (error instanceof DemoStop) throw error;
    throw new DemoStop(502, "envelope_unavailable");
  }
  if (bytes === null) throw new DemoStop(502, "envelope_unavailable");
  try {
    if (bytes.length !== grant.envelopeSize) throw new HashMismatch();
    assertHash(bytes, grant.envelopeHash);
    const { salt, entries } = parseEnvelope(bytes);
    return { salt, hints: entries.map((entry) => entry.hint) };
  } catch {
    throw new DemoStop(502, "envelope_mismatch");
  }
}

/**
 * A test of which ML-KEM keys the current epoch's key was sealed to (threat model C39, C42): true
 * for a key whose recipient hint is in any envelope the registry recorded for this epoch, the test
 * anyone holding the public key can run. Each envelope is downloaded from BLOB_ORIGIN by its
 * on-chain hash, stopping at its on-chain size, and read only once its size and SHA-256 match the
 * record (C12).
 *
 * Covers a member who registered another key after the board was sealed to them. Does not cover an
 * anonymous envelope, whose entries carry no hints, so every key tests false against it.
 *
 * @throws DemoStop: too_many_grants past twice DEMO_GUEST_CAP grants, envelope_unavailable when an
 *   envelope is missing or cannot be read, envelope_mismatch when it is not the recorded bytes or
 *   does not parse as a QoreSeal envelope.
 */
export async function sealedTo(p: { snapshot: BoardSnapshot; blobs: BlobBackend; blobOrigin: string; signal?: AbortSignal }): Promise<(kemPublicKey: Uint8Array) => boolean> {
  const { grants } = p.snapshot;
  if (grants.length > MAX_GRANTS_READ) throw new DemoStop(503, "too_many_grants");
  const envelopes: { salt: Uint8Array; hints: Uint8Array[] }[] = [];
  for (let start = 0; start < grants.length; start += ENVELOPES_PARALLEL) {
    envelopes.push(...(await Promise.all(grants.slice(start, start + ENVELOPES_PARALLEL).map((grant) => hintsOf(grant, p)))));
  }
  return (kemPublicKey) =>
    envelopes.some(({ salt, hints }) => {
      const mine = recipientHint(salt, kemPublicKey);
      return hints.some((hint) => sameBytes(hint, mine));
    });
}

/**
 * Uploads an envelope through the server's own envelope path (handleUpload, threat model C28), then
 * checks its answer as an input: the hash and size must be those of the bytes sent, and the URL the
 * one built from that hash and BLOB_ORIGIN.
 *
 * @throws DemoStop upload_failed for any refusal, upload_mismatch for any other answer.
 */
export async function uploadEnvelope(envelope: Uint8Array, ctx: UploadContext): Promise<{ hash: Hex; size: number }> {
  const request = new Request("http://internal/api/upload?kind=envelope", { method: "POST", headers: { "content-type": "application/octet-stream" }, body: Uint8Array.from(envelope) });
  const response = await handleUpload(request, ctx);
  if (response.status !== 200 && response.status !== 201) throw new DemoStop(response.status === 429 ? 429 : 502, "upload_failed");
  const answer = (await response.json()) as { sha256?: unknown; size?: unknown; url?: unknown };
  const hash = bytesToHex(sha256(envelope));
  const expected = envelopeUrl(ctx.blobOrigin, hash);
  // Both hashes go through one parser and are compared as bytes, never as hex strings (C.7, standard 2).
  const sameAsSent = typeof answer.sha256 === "string" && /^[0-9a-fA-F]{64}$/.test(answer.sha256) && sameHash(`0x${answer.sha256}`, hash);
  if (!sameAsSent || answer.size !== envelope.length || typeof answer.url !== "string" || !sameUrl(answer.url, expected.href)) {
    throw new DemoStop(502, "upload_mismatch");
  }
  return { hash, size: envelope.length };
}

export interface RelayOutcome {
  status: number;
  txHash?: Hex;
  /** The relay's own short refusal code; never text from a caller or the chain. */
  error?: string;
}

/**
 * Submits one signed action through the one relay pipeline (handleRelay); there is no second sender.
 * The request carries x-ava as our app does, so a script's public relay passes the cross-site check;
 * the bot's own relays, scoped "demo", skip it.
 */
export async function relayAction(body: RelayBody, ctx: RelayContext): Promise<RelayOutcome> {
  const request = new Request("http://internal/api/relay", { method: "POST", headers: { "content-type": "application/json", "x-ava": "1" }, body: JSON.stringify(body) });
  const response = await handleRelay(request, ctx);
  const answer = (await response.json().catch(() => ({}))) as { txHash?: unknown; error?: unknown };
  if (response.status === 202 && typeof answer.txHash === "string" && /^0x[0-9a-f]{64}$/.test(answer.txHash)) return { status: 202, txHash: answer.txHash as Hex };
  const error = typeof answer.error === "string" && /^[A-Za-z_]{1,64}$/.test(answer.error) ? answer.error : "unknown";
  return { status: response.status === 202 ? 502 : response.status, error };
}

/** The parameters of one board action, before it is signed. */
export type ActionSpec =
  | { kind: "create"; boardRef: Hex; envelopeHash: Hex; envelopeSize: number }
  | { kind: "add"; member: Hex; mode: Mode; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint }
  | { kind: "remove"; member: Hex; envelopeHash: Hex; envelopeSize: number; epochAfter: bigint }
  | { kind: "post"; docRef: Hex; cipherHash: Hex; cipherSize: bigint; epoch: bigint };

/** The JSON body handleRelay takes: every integer as a decimal string. */
export interface RelayBody {
  action: ActionSpec["kind"];
  boardId?: string;
  params: Record<string, string>;
  deadline: string;
  signature: Hex;
}

/**
 * Builds one action from values the signer read itself (threat model C2, C4, C33), signs it with
 * the chair's ML-DSA-87 key through signBoardAction, which rebuilds the exact message from these
 * typed fields, and returns the relay body. The nonce is the board's (or, for create, the chair's
 * creation nonce), and the deadline is DEMO_ACTION_SECONDS after the latest block's timestamp,
 * never the device clock.
 *
 * @param at For create: boardId 0n and the creation nonce. Otherwise the snapshot the action was
 *   built from. `blockTimestamp` is the latest block's, from the same chain read.
 * @throws ActionError or AddressError from signBoardAction for a field outside its type.
 */
export function signedAction(chair: Identity, at: { boardId: bigint; nonce: bigint; blockTimestamp: bigint }, spec: ActionSpec): RelayBody {
  const deadline = deadlineFrom(at.blockTimestamp, DEMO_ACTION_SECONDS);
  let input: BoardActionInput;
  let params: Record<string, string>;
  switch (spec.kind) {
    case "create":
      input = { action: Action.CREATE, chair: chair.evm, boardRef: spec.boardRef, envelopeHash: spec.envelopeHash, envelopeSize: spec.envelopeSize };
      params = { chair: chair.evm, boardRef: spec.boardRef, envelopeHash: spec.envelopeHash, envelopeSize: String(spec.envelopeSize) };
      break;
    case "add":
      input = { action: Action.ADD, member: spec.member, mode: spec.mode, envelopeHash: spec.envelopeHash, envelopeSize: spec.envelopeSize, epochAfter: spec.epochAfter };
      params = { member: spec.member, mode: String(spec.mode), envelopeHash: spec.envelopeHash, envelopeSize: String(spec.envelopeSize), epochAfter: spec.epochAfter.toString() };
      break;
    case "remove":
      input = { action: Action.REMOVE, member: spec.member, envelopeHash: spec.envelopeHash, envelopeSize: spec.envelopeSize, epochAfter: spec.epochAfter };
      params = { member: spec.member, envelopeHash: spec.envelopeHash, envelopeSize: String(spec.envelopeSize), epochAfter: spec.epochAfter.toString() };
      break;
    case "post":
      input = { action: Action.POST, docRef: spec.docRef, cipherHash: spec.cipherHash, cipherSize: spec.cipherSize, epoch: spec.epoch };
      params = { docRef: spec.docRef, cipherHash: spec.cipherHash, cipherSize: spec.cipherSize.toString(), epoch: spec.epoch.toString() };
      break;
  }
  const { signature } = signBoardAction(chair.mldsa.secretKey, {
    ...input,
    registry: REGISTRY_ADDRESS,
    boardId: at.boardId,
    nonce: at.nonce,
    deadline,
    latestBlockTimestamp: at.blockTimestamp,
  });
  const body: RelayBody = { action: spec.kind, params, deadline: deadline.toString(), signature: bytesToHex(signature) };
  if (spec.kind !== "create") body.boardId = at.boardId.toString();
  return body;
}
