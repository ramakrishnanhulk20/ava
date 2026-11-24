import { EVM_CHAIN_ID, EVM_RPC } from "@ava/core";
import { useSyncExternalStore } from "react";
import { createPublicClient, defineChain, http, type Address } from "viem";

// Copied from packages/contracts/deployments/testnet.json, the BoardRegistry entry.
export const REGISTRY: Address = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa";

const BLOCK_EVERY_MS = 6_000;
const BOARD_EVERY_MS = 12_000;

export const getBoardAbi = [
  {
    type: "function",
    name: "getBoard",
    stateMutability: "view",
    inputs: [{ name: "boardId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "chair", type: "address" },
          { name: "boardRef", type: "bytes32" },
          { name: "epoch", type: "uint64" },
          { name: "nonce", type: "uint64" },
          { name: "memberCount", type: "uint32" },
          { name: "documentCount", type: "uint32" },
        ],
      },
    ],
  },
] as const;

const qorechainTestnet = defineChain({
  id: EVM_CHAIN_ID,
  name: "QoreChain testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [EVM_RPC] } },
});

export const client = createPublicClient({ chain: qorechainTestnet, transport: http(EVM_RPC) });

function parseBoardId(raw: string | undefined): bigint | null {
  if (!raw || !/^\d+$/.test(raw)) return null;
  return BigInt(raw);
}

export const BOARD_ID = parseBoardId(process.env.NEXT_PUBLIC_DEMO_BOARD_ID);

type Board = { epoch: bigint; nonce: bigint; memberCount: number; documentCount: number };

type Store = {
  block: bigint | null;
  board: Board | null;
  blockFailing: boolean;
  boardFailing: boolean;
};

export type DemoBoard = {
  /** "loading" until the first answer, "live" while reads succeed, "retrying" when a read failed
   * but earlier values are kept, "down" when nothing has ever been read. */
  status: "loading" | "live" | "retrying" | "down";
  id: string;
  block: bigint | null;
  epoch: bigint | null;
  /** The board nonce: every signed board change moves it up by one. */
  nonce: bigint | null;
  memberCount: number | null;
  documentCount: number | null;
};

const EMPTY: Store = { block: null, board: null, blockFailing: false, boardFailing: false };

let store: Store = EMPTY;
let snapshot: DemoBoard = derive(store);
const listeners = new Set<() => void>();
let blockTimer: ReturnType<typeof setInterval> | undefined;
let boardTimer: ReturnType<typeof setInterval> | undefined;

function derive(s: Store): DemoBoard {
  const complete = s.block !== null && s.board !== null;
  const failing = s.blockFailing || s.boardFailing;
  const status: DemoBoard["status"] = complete ? (failing ? "retrying" : "live") : failing ? "down" : "loading";
  return {
    status,
    id: BOARD_ID === null ? "" : BOARD_ID.toString(),
    block: s.block,
    epoch: s.board?.epoch ?? null,
    nonce: s.board?.nonce ?? null,
    memberCount: s.board?.memberCount ?? null,
    documentCount: s.board?.documentCount ?? null,
  };
}

function publish(next: Store) {
  store = next;
  snapshot = derive(next);
  for (const listener of listeners) listener();
}

async function readBlock() {
  try {
    const block = await client.getBlockNumber();
    publish({ ...store, block, blockFailing: false });
  } catch {
    publish({ ...store, blockFailing: true });
  }
}

async function readBoard() {
  if (BOARD_ID === null) {
    publish({ ...store, boardFailing: true });
    return;
  }
  try {
    const result = await client.readContract({
      address: REGISTRY,
      abi: getBoardAbi,
      functionName: "getBoard",
      args: [BOARD_ID],
    });
    publish({
      ...store,
      board: {
        epoch: result.epoch,
        nonce: result.nonce,
        memberCount: result.memberCount,
        documentCount: result.documentCount,
      },
      boardFailing: false,
    });
  } catch {
    publish({ ...store, boardFailing: true });
  }
}

function startPolling() {
  void readBlock();
  void readBoard();
  blockTimer = setInterval(() => void readBlock(), BLOCK_EVERY_MS);
  boardTimer = setInterval(() => void readBoard(), BOARD_EVERY_MS);
}

function stopPolling() {
  clearInterval(blockTimer);
  clearInterval(boardTimer);
  blockTimer = undefined;
  boardTimer = undefined;
}

function onVisibility() {
  if (document.visibilityState === "hidden") {
    stopPolling();
  } else if (blockTimer === undefined) {
    startPolling();
  }
}

// One shared poller feeds every component that shows the board, so two readers never double the traffic.
function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    document.addEventListener("visibilitychange", onVisibility);
    if (document.visibilityState === "visible") startPolling();
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      document.removeEventListener("visibilitychange", onVisibility);
      stopPolling();
    }
  };
}

const serverSnapshot: DemoBoard = derive(EMPTY);

export function useDemoBoard(): DemoBoard {
  return useSyncExternalStore(
    subscribe,
    () => snapshot,
    () => serverSnapshot,
  );
}

export function formatCount(value: bigint | number): string {
  return value.toLocaleString("en-US");
}
