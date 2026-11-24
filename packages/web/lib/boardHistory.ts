import { useMemo, useSyncExternalStore } from "react";
import { decodeEventLog, getAddress, isAddress, pad, parseAbi, toEventSelector, toHex } from "viem";
import { BOARD_ID, REGISTRY, client, getBoardAbi } from "./chain";
import {
  buildProofModel,
  type Address,
  type Director,
  type HistoryEvent,
  type PackInfo,
  type ProofModel,
} from "./boardRules";

const PAGE_BLOCKS = 10_000;
const PAGES_IN_FLIGHT = 4;
const REFRESH_MS = 60_000;
const RETRY_MS = 15_000;
const CACHE_VERSION = "v1";

const eventAbi = parseAbi([
  "event BoardCreated(uint256 indexed boardId, address indexed chair, bytes32 boardRef, uint64 createNonce)",
  "event EnvelopeGranted(uint256 indexed boardId, uint64 indexed epoch, bytes32 envelopeHash, uint32 envelopeSize, uint8 mode, address member, uint64 nonce)",
  "event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)",
  "event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)",
  "event EpochRotated(uint256 indexed boardId, uint64 indexed newEpoch, uint64 nonce)",
  "event DocumentPosted(uint256 indexed boardId, uint256 indexed docId, bytes32 docRef, uint64 epoch, bytes32 cipherHash, uint64 cipherSize, uint64 nonce)",
]);

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

const SELECTORS = eventAbi.map((item) => toEventSelector(item));

function parseBlock(raw: string | undefined): number | null {
  return raw && /^\d+$/.test(raw) ? Number(raw) : null;
}

/** "Name=0x...,Name=0x..." from the environment. The names are the demo's own personas, so they never appear in a component. */
export function parseDirectors(raw: string | undefined): Director[] {
  if (!raw) return [];
  const out: Director[] = [];
  for (const part of raw.split(",")) {
    const [name, address] = part.split("=").map((piece) => piece.trim());
    if (name && address && isAddress(address)) out.push({ name, address: getAddress(address) });
  }
  return out;
}

export const DIRECTORS = parseDirectors(process.env.NEXT_PUBLIC_DEMO_DIRECTORS);
export const FROM_BLOCK = parseBlock(process.env.NEXT_PUBLIC_DEMO_FROM_BLOCK);

type BoardSummary = { chair: Address; epoch: number; memberCount: number; documentCount: number };

export type BoardHistory = {
  /** "loading" until every page of the first read is in. */
  phase: "loading" | "ready";
  board: BoardSummary | null;
  packs: PackInfo[];
  events: HistoryEvent[];
  /** The last block whose logs are all in `events`. */
  lastBlock: number | null;
  pagesDone: number;
  pagesTotal: number;
  /** When the next retry fires, in milliseconds since the epoch, or null while nothing is failing. */
  retryAt: number | null;
  boardId: string;
  fromBlock: number | null;
  directors: Director[];
  model: ProofModel | null;
};

type Store = Omit<BoardHistory, "boardId" | "fromBlock" | "directors" | "model">;

const EMPTY: Store = {
  phase: "loading",
  board: null,
  packs: [],
  events: [],
  lastBlock: null,
  pagesDone: 0,
  pagesTotal: 0,
  retryAt: null,
};

let store: Store = EMPTY;
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setTimeout> | undefined;
let running = false;
const seen = new Set<string>();

function publish(next: Partial<Store>) {
  store = { ...store, ...next };
  for (const listener of listeners) listener();
}

function cacheKey(): string | null {
  return BOARD_ID === null || FROM_BLOCK === null ? null : `ava.history.${CACHE_VERSION}.${BOARD_ID}.${FROM_BLOCK}`;
}

function loadCache(): { lastBlock: number; events: HistoryEvent[] } | null {
  const key = cacheKey();
  if (!key) return null;
  try {
    const parsed: unknown = JSON.parse(sessionStorage.getItem(key) ?? "null");
    if (!parsed || typeof parsed !== "object") return null;
    const { lastBlock, events } = parsed as { lastBlock?: unknown; events?: unknown };
    return typeof lastBlock === "number" && Array.isArray(events)
      ? { lastBlock, events: events as HistoryEvent[] }
      : null;
  } catch {
    return null;
  }
}

function saveCache(lastBlock: number, events: HistoryEvent[]) {
  const key = cacheKey();
  if (!key) return;
  try {
    sessionStorage.setItem(key, JSON.stringify({ lastBlock, events }));
  } catch {
    // A full or blocked sessionStorage only costs a slower next visit.
  }
}

function toEvent(log: {
  data: `0x${string}`;
  topics: `0x${string}`[];
  transactionHash: `0x${string}` | null;
  blockNumber: `0x${string}` | null;
  logIndex: `0x${string}` | null;
}): HistoryEvent | null {
  if (!log.transactionHash || !log.blockNumber || !log.logIndex) return null;
  const placed = {
    tx: log.transactionHash,
    block: Number(BigInt(log.blockNumber)),
    index: Number(BigInt(log.logIndex)),
  };
  const decoded = decodeEventLog({
    abi: eventAbi,
    data: log.data,
    topics: log.topics as [`0x${string}`, ...`0x${string}`[]],
  });
  switch (decoded.eventName) {
    case "BoardCreated":
      return { name: "BoardCreated", chair: decoded.args.chair, ...placed };
    case "MemberAdded":
      return {
        name: "MemberAdded",
        member: decoded.args.member,
        epoch: Number(decoded.args.epoch),
        mode: decoded.args.mode,
        ...placed,
      };
    case "MemberRemoved":
      return { name: "MemberRemoved", member: decoded.args.member, newEpoch: Number(decoded.args.newEpoch), ...placed };
    case "EpochRotated":
      return { name: "EpochRotated", newEpoch: Number(decoded.args.newEpoch), ...placed };
    case "EnvelopeGranted":
      return {
        name: "EnvelopeGranted",
        epoch: Number(decoded.args.epoch),
        mode: decoded.args.mode,
        member: decoded.args.member,
        ...placed,
      };
    case "DocumentPosted":
      return {
        name: "DocumentPosted",
        docId: Number(decoded.args.docId),
        epoch: Number(decoded.args.epoch),
        ...placed,
      };
    default:
      return null;
  }
}

/** One page of one board's registry events, decoded. The board room reads any board with it; the home page reads the demo board. */
export async function readEventsPage(from: number, to: number, boardId: bigint): Promise<HistoryEvent[]> {
  const logs = await client.request({
    method: "eth_getLogs",
    params: [
      {
        address: REGISTRY,
        fromBlock: toHex(from),
        toBlock: toHex(to),
        topics: [SELECTORS, pad(toHex(boardId), { size: 32 })],
      },
    ],
  });
  const out: HistoryEvent[] = [];
  for (const log of logs) {
    const event = toEvent(log);
    if (event) out.push(event);
  }
  return out;
}

function keyOf(event: HistoryEvent) {
  return `${event.tx}:${event.index}`;
}

function merge(incoming: HistoryEvent[]): HistoryEvent[] {
  const next = [...store.events];
  for (const event of incoming) {
    const key = keyOf(event);
    if (seen.has(key)) continue;
    seen.add(key);
    next.push(event);
  }
  return next.sort((a, b) => a.block - b.block || a.index - b.index);
}

async function readPacks(boardId: bigint, count: number) {
  const known = store.packs.length;
  if (count <= known) return;
  const added = await Promise.all(
    Array.from({ length: count - known }, async (_, offset) => {
      const index = known + offset;
      const doc = await client.readContract({
        address: REGISTRY,
        abi: getDocumentAbi,
        functionName: "getDocument",
        args: [boardId, BigInt(index)],
      });
      return { index, epoch: Number(doc.epoch), postedAt: Number(doc.postedAt) } satisfies PackInfo;
    }),
  );
  publish({ packs: [...store.packs, ...added] });
}

async function refresh() {
  if (running) return;
  running = true;
  try {
    if (BOARD_ID === null || FROM_BLOCK === null) throw new Error("demo board is not configured");
    const boardId = BOARD_ID;
    const latest = Number(await client.getBlockNumber());

    const board = await client.readContract({
      address: REGISTRY,
      abi: getBoardAbi,
      functionName: "getBoard",
      args: [boardId],
    });
    publish({
      board: {
        chair: board.chair,
        epoch: Number(board.epoch),
        memberCount: board.memberCount,
        documentCount: board.documentCount,
      },
    });
    await readPacks(boardId, board.documentCount);

    const from = store.lastBlock === null ? FROM_BLOCK : store.lastBlock + 1;
    const pages: Array<[number, number]> = [];
    for (let start = from; start <= latest; start += PAGE_BLOCKS)
      pages.push([start, Math.min(start + PAGE_BLOCKS - 1, latest)]);

    publish({ pagesDone: 0, pagesTotal: pages.length });
    let next = 0;
    let done = 0;
    const worker = async () => {
      while (next < pages.length) {
        const page = pages[next++];
        if (!page) return;
        const events = await readEventsPage(page[0], page[1], boardId);
        done += 1;
        publish({ events: merge(events), pagesDone: done });
      }
    };
    await Promise.all(Array.from({ length: Math.min(PAGES_IN_FLIGHT, pages.length) }, worker));

    saveCache(latest, store.events);
    publish({ phase: "ready", lastBlock: latest, retryAt: null });
    schedule(REFRESH_MS);
  } catch {
    publish({ retryAt: Date.now() + RETRY_MS });
    schedule(RETRY_MS);
  } finally {
    running = false;
  }
}

function schedule(ms: number) {
  clearTimeout(timer);
  if (document.visibilityState === "hidden") return;
  timer = setTimeout(() => void refresh(), ms);
}

function onVisibility() {
  if (document.visibilityState === "hidden") clearTimeout(timer);
  else if (!running) void refresh();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    const cached = loadCache();
    if (cached && store.lastBlock === null) {
      for (const event of cached.events) seen.add(keyOf(event));
      publish({ events: cached.events, lastBlock: cached.lastBlock, phase: "ready" });
    }
    document.addEventListener("visibilitychange", onVisibility);
    if (document.visibilityState === "visible") void refresh();
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      document.removeEventListener("visibilitychange", onVisibility);
      clearTimeout(timer);
    }
  };
}

export function useBoardHistory(): BoardHistory {
  const snapshot = useSyncExternalStore(
    subscribe,
    () => store,
    () => EMPTY,
  );
  return useMemo(() => {
    const model =
      snapshot.phase === "ready" && snapshot.board
        ? buildProofModel(snapshot.events, snapshot.packs, DIRECTORS, snapshot.board.chair)
        : null;
    return {
      ...snapshot,
      boardId: BOARD_ID === null ? "" : BOARD_ID.toString(),
      fromBlock: FROM_BLOCK,
      directors: DIRECTORS,
      model,
    };
  }, [snapshot]);
}

if (process.env.NODE_ENV === "development" && typeof window !== "undefined") {
  void import("./boardRules.check").then(
    (checks) => console.info(`[ava] board rule checks passed: ${checks.runRuleChecks().length}`),
    (error: unknown) => console.error("[ava] board rule checks failed", error),
  );
}
