import { sameAccount } from "@ava/core";
import { readEventsPage } from "../boardHistory";
import { tenuresByMember, type HistoryEvent } from "../boardRules";
import { REGISTRY, client } from "../chain";
import { pause, throwIfStopped } from "../guest/time";
import { REGISTRY_DEPLOY_BLOCK, pagesBetween } from "./myBoards";

const PAGE_BLOCKS = 10_000n;
const PAGES_AT_ONCE = 4;
const PAGE_TRIES = 3;
const PAGE_RETRY_MS = 1_500;
const STORAGE_PREFIX = "ava.board-history.v1.";

/** One board's events, in chain order, and how far its history has been read. */
export interface BoardHistoryRead {
  /** Every block up to and including this one has been read. */
  through: bigint;
  events: HistoryEvent[];
}

/** One posted pack as the registry records it: never its name or its content. */
export interface PackRecord {
  index: number;
  docRef: `0x${string}`;
  cipherHash: `0x${string}`;
  cipherSize: bigint;
  epoch: number;
  /** Unix seconds of the block it was posted in. */
  postedAt: number;
}

const getDocumentAbi = [
  {
    type: "function",
    name: "getDocument",
    stateMutability: "view",
    inputs: [
      { name: "boardId", type: "uint256" },
      { name: "docId", type: "uint256" },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "docRef", type: "bytes32" },
          { name: "cipherHash", type: "bytes32" },
          { name: "cipherSize", type: "uint64" },
          { name: "epoch", type: "uint64" },
          { name: "postedAt", type: "uint64" },
        ],
      },
    ],
  },
] as const;

const byChainOrder = (a: HistoryEvent, b: HistoryEvent): number => a.block - b.block || a.index - b.index;

/** Who sits on the board according to its events alone: the chair from its creation, and everyone added and not removed since. */
export function membersFromEvents(events: readonly HistoryEvent[]): string[] {
  return [...tenuresByMember([...events])].filter(([, tenures]) => tenures.at(-1)?.endEpoch === null).map(([member]) => member);
}

/** Whether two member lists name the same accounts, each once, in any order (threat model C38). */
export function sameMembers(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const left = new Set(a.map((m) => m.toLowerCase()));
  const right = new Set(b.map((m) => m.toLowerCase()));
  return left.size === a.length && right.size === b.length && [...left].every((m) => right.has(m));
}

export function serialiseHistory(read: BoardHistoryRead): string {
  return JSON.stringify({ through: read.through.toString(), events: read.events });
}

const DECIMAL = /^(0|[1-9]\d{0,30})$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const TX = /^0x[0-9a-fA-F]{64}$/;
const count = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const address = (v: unknown): v is `0x${string}` => typeof v === "string" && ADDRESS.test(v);

function eventOf(raw: unknown): HistoryEvent | undefined {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const e = raw as Record<string, unknown>;
  if (typeof e.tx !== "string" || !TX.test(e.tx) || !count(e.block) || !count(e.index)) return undefined;
  const placed = { tx: e.tx as `0x${string}`, block: e.block, index: e.index };
  switch (e.name) {
    case "BoardCreated":
      return address(e.chair) ? { name: "BoardCreated", chair: e.chair, ...placed } : undefined;
    case "MemberAdded":
      return address(e.member) && count(e.epoch) && count(e.mode) ? { name: "MemberAdded", member: e.member, epoch: e.epoch, mode: e.mode, ...placed } : undefined;
    case "MemberRemoved":
      return address(e.member) && count(e.newEpoch) ? { name: "MemberRemoved", member: e.member, newEpoch: e.newEpoch, ...placed } : undefined;
    case "EpochRotated":
      return count(e.newEpoch) ? { name: "EpochRotated", newEpoch: e.newEpoch, ...placed } : undefined;
    case "EnvelopeGranted":
      return address(e.member) && count(e.epoch) && count(e.mode) ? { name: "EnvelopeGranted", epoch: e.epoch, mode: e.mode, member: e.member, ...placed } : undefined;
    case "DocumentPosted":
      return count(e.docId) && count(e.epoch) ? { name: "DocumentPosted", docId: e.docId, epoch: e.epoch, ...placed } : undefined;
    default:
      return undefined;
  }
}

/** A history as storage holds it, or undefined for anything that is not exactly that shape. It is public chain data and only a cache. */
export function parseHistory(raw: string | null): BoardHistoryRead | undefined {
  if (raw === null) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const { through, events } = parsed as Record<string, unknown>;
  if (typeof through !== "string" || !DECIMAL.test(through) || !Array.isArray(events)) return undefined;
  const out: HistoryEvent[] = [];
  for (const raw of events) {
    const event = eventOf(raw);
    if (event === undefined) return undefined;
    out.push(event);
  }
  return { through: BigInt(through), events: out };
}

const storageKey = (boardId: bigint): string => `${STORAGE_PREFIX}${boardId.toString()}`;

export function rememberedHistory(boardId: bigint): BoardHistoryRead | undefined {
  try {
    return parseHistory(window.localStorage.getItem(storageKey(boardId)));
  } catch {
    return undefined;
  }
}

export function rememberHistory(boardId: bigint, read: BoardHistoryRead): void {
  try {
    window.localStorage.setItem(storageKey(boardId), serialiseHistory(read));
  } catch {
    // Storage is only a cache here.
  }
}

export function forgetHistory(boardId: bigint): void {
  try {
    window.localStorage.removeItem(storageKey(boardId));
  } catch {
    // Nothing to forget.
  }
}

async function page(boardId: bigint, range: { from: bigint; to: bigint }, signal: AbortSignal): Promise<HistoryEvent[]> {
  for (let tried = 1; ; tried++) {
    throwIfStopped(signal);
    try {
      return await readEventsPage(Number(range.from), Number(range.to), boardId);
    } catch (error) {
      if (signal.aborted || tried >= PAGE_TRIES) throw error;
      await pause(PAGE_RETRY_MS, signal);
    }
  }
}

type BlockRange = { from: bigint; to: bigint };

/**
 * Reads the pages newest first, a few at a time, and stops asking for older ones once a page holds
 * the board's creation: nothing about a board is older than the block that made it. Every page from
 * that one up to the newest is read in full, so the history comes back whole or the read fails.
 *
 * @param pages In block order, oldest first.
 * @param onPage Told after each page: how many of the pages that matter are read, of how many.
 */
export async function readBackToCreation(pages: readonly BlockRange[], read: (range: BlockRange) => Promise<HistoryEvent[]>, onPage: (done: number, total: number) => void): Promise<HistoryEvent[]> {
  const found: HistoryEvent[] = [];
  const finished: number[] = [];
  let next = pages.length - 1;
  let oldestNeeded = 0;
  onPage(0, pages.length);
  await Promise.all(
    Array.from({ length: Math.min(PAGES_AT_ONCE, pages.length) }, async () => {
      while (next >= oldestNeeded) {
        const index = next--;
        const events = await read(pages[index] as BlockRange);
        found.push(...events);
        finished.push(index);
        if (index > oldestNeeded && events.some((event) => event.name === "BoardCreated")) oldestNeeded = index;
        onPage(finished.filter((read) => read >= oldestNeeded).length, pages.length - oldestNeeded);
      }
    }),
  );
  return found;
}

/**
 * Reads one board's events from the public EVM RPC, from where an earlier read stopped up to
 * `toBlock`, the block the caller read the board's live record at, so the history and the record
 * describe one moment. A page that cannot be read after three tries fails the whole read: the page
 * then says the history is incomplete instead of showing a shorter one (threat model C38).
 *
 * @param known What an earlier read found, to continue from; left out, the read works back from `toBlock` to the board's creation.
 * @param onPage Told after each page: how many are read, of how many.
 */
export async function readHistory(boardId: bigint, toBlock: bigint, known: BoardHistoryRead | undefined, signal: AbortSignal, onPage: (done: number, total: number) => void = () => undefined): Promise<BoardHistoryRead> {
  if (known !== undefined && known.through >= toBlock) return known;
  const pages = pagesBetween(known === undefined ? REGISTRY_DEPLOY_BLOCK : known.through + 1n, toBlock, PAGE_BLOCKS);
  const found = await readBackToCreation(pages, (range) => page(boardId, range, signal), onPage);
  const seen = new Set<string>();
  const events = [...(known?.events ?? []), ...found].filter((e) => {
    const key = `${e.tx}:${e.index}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { through: toBlock, events: events.sort(byChainOrder) };
}

/** Every pack's record, read at one block. */
export async function readPackRecords(boardId: bigint, documentCount: number, blockNumber: bigint): Promise<PackRecord[]> {
  return Promise.all(
    Array.from({ length: documentCount }, async (_, index): Promise<PackRecord> => {
      const doc = await client.readContract({ address: REGISTRY, abi: getDocumentAbi, functionName: "getDocument", args: [boardId, BigInt(index)], blockNumber });
      return { index, docRef: doc.docRef, cipherHash: doc.cipherHash, cipherSize: doc.cipherSize, epoch: Number(doc.epoch), postedAt: Number(doc.postedAt) };
    }),
  );
}

/** Whether this account's own event trail says it could ever have been on the board: its chair, or added at some point. */
export function everOnBoard(events: readonly HistoryEvent[], account: string): boolean {
  return events.some((e) => (e.name === "BoardCreated" && sameAccount(e.chair, account)) || (e.name === "MemberAdded" && sameAccount(e.member, account)));
}
