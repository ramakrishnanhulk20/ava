// Not covered here: the live chain. Every chain answer comes from a stub that records what the relay
// handler asked of it, so whether the registry really accepts a signed action, and what the relayed
// transaction really costs, are checked by scripts/live-relay-check.ts. Signatures are not verified
// by the server at all: the registry checks them in the eth_call, and the stub stands in for it.
import { readFileSync } from "node:fs";
import { evmWindowCost, weiToUqorCeil, type EvmWindow } from "@qorechain/evm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TransactionNotFoundError, TransactionReceiptNotFoundError, bytesToHex, decodeFunctionData, encodeErrorResult, encodeFunctionData, encodeFunctionResult, getAddress, keccak256, toFunctionSelector, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import { NotBroadcast, evmTxStatus } from "../src/chain/evm.ts";
import type { BeforeBroadcast, CallOutcome, EvmSend, FeeQuote, RelayChain, TxRequest, WindowRequest } from "../src/chain/types.ts";
import {
  CHAIRS_DAILY_CEILING_UQOR,
  DAILY_SPEND_CEILING_UQOR,
  DEMO_DAILY_CEILING_UQOR,
  DEMO_RELAYS_PER_HOUR,
  GAS_CEILING,
  LOCK_TTL_SECONDS,
  MAX_FEE_PER_GAS,
  NATIVE_TX_BUDGET_MS,
  OPEN_CUTOFF_MS,
  PER_CHAIR_DAILY_POST_BYTES,
  PER_CHAIR_DAILY_UQOR,
  REGISTRY_ADDRESS,
  REGISTRY_CODE_KECCAK,
  RELAY_DEADLINE_MS,
  RELAY_LIMITS,
  SEND_CUTOFF_MS,
  SEND_LOCK_WAIT_MS,
  TOTAL_DAILY_POST_BYTES,
  WAIT_AFTER_WINDOW_MS,
  WINDOW_LOCK_WAIT_MS,
  WINDOW_OPEN_FEE_UQOR,
} from "../src/config.ts";
import { VERIFIED_SECONDS } from "../src/docupload.ts";
import { handleRelay, reserveDemoRelays, type RelayContext } from "../src/relay.ts";
import { LOCK_MAX_WAIT_MS, MemoryStore, type SharedStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";
import { clearHalt, haltKey, ledgerFor, nonceKey, recordWindowSend, spendKey, spentOn, spentToday } from "../src/window.ts";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const RELAYER = { qor1: "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq", evm: "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973" } as const;
const CHAIR = getAddress("0x64b85c422776d173a324fa72cc72f7fffdd42d82");
const MEMBER_LOWER = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
const MEMBER = getAddress(MEMBER_LOWER);
const OTHER = "0x624b5C35E3665eB9ade6d75BBbca1218a09E00D1";
const H1: Hex = `0x${"11".repeat(32)}`;
const H2: Hex = `0x${"22".repeat(32)}`;
const SIG = bytesToHex(new Uint8Array(4627).fill(0xa7));
const DEADLINE = 1_800_000_000n;
const GWEI = 1_000_000_000n;
const QUOTE: FeeQuote = { baseFeePerGas: 100n * GWEI, maxPriorityFeePerGas: GWEI };
const GET_BOARD = toFunctionSelector("getBoard(uint256)");
const CREATE_NONCES = toFunctionSelector("createNonces(address)");

function healthyWindow(over: Partial<EvmWindow> = {}): EvmWindow {
  const value = 40n * evmWindowCost({ gas: 650_000n, maxFeePerGas: 250n * GWEI });
  return {
    found: true,
    live: true,
    openedHeight: 1_000n,
    expiryHeight: 13_000n,
    maxTxs: 40n,
    usedTxs: 0n,
    maxValue: value,
    usedValue: 0n,
    remainingBlocks: 12_000n,
    remainingTxs: 40n,
    remainingValue: value,
    nativeOnly: false,
    allowedTargets: [REGISTRY_ADDRESS.toLowerCase()],
    ...over,
  };
}

interface StubOptions {
  outcome?: (req: TxRequest) => CallOutcome;
  board?: (boardId: bigint) => CallOutcome | undefined;
  gas?: bigint;
  window?: EvmWindow;
  sendDelayMs?: number;
  /** Runs inside an open, so a test can move its clock as a slow open would. */
  onOpen?: () => void;
  /** What every receipt reports the chain charged. Without it no receipt is ever found. */
  fee?: { gasUsed: bigint; effectiveGasPrice: bigint };
  /** The keccak of the code at the registry address; the deployed code's by default, undefined for no code. */
  registry?: { codeHash: Hex | undefined };
  /**
   * What happens to each send the node takes: "moves" (the default) lands and moves the board's
   * nonce or the chair's create nonce, "reverts" lands without moving it and txStatus then answers
   * "reverted", "pending" waits unmined.
   */
  landing?: "moves" | "reverts" | "pending";
}

/** Stands in for the chain and the registry, and records every request in the order it came. */
function stubChain(options: StubOptions = {}) {
  const calls: TxRequest[] = [];
  const estimates: TxRequest[] = [];
  const sends: EvmSend[] = [];
  const opens: WindowRequest[] = [];
  const events: string[] = [];
  let window = options.window ?? healthyWindow();
  let count = 0;
  let closes = 0;
  let height = window.openedHeight;
  // One counter for the account's EVM nonce and native sequence: every send, open and close moves it.
  let nonce = 0n;
  let codeReads = 0;
  let natives = 0;
  // Every hash of ours the chain holds in a block, and every one still unmined, as txStatus answers for them.
  const landed = new Set<string>();
  const pending = new Set<string>();
  const reverted = new Set<string>();
  // The registry's own nonces: one per board, one per chair for createBoard. Only a landed action moves them.
  const boardNonces = new Map<bigint, bigint>();
  const createNonces = new Map<string, bigint>();
  const land = (tx: EvmSend) => {
    const { functionName, args } = decodeFunctionData({ abi: boardRegistryAbi, data: tx.data });
    if (functionName === "createBoard") {
      const chair = String(args[0]).toLowerCase();
      createNonces.set(chair, (createNonces.get(chair) ?? 0n) + 1n);
    } else {
      const boardId = args[0] as bigint;
      boardNonces.set(boardId, (boardNonces.get(boardId) ?? 9n) + 1n);
    }
  };
  /** What the real chain does between signing and broadcasting: a hook that throws means nothing is sent. */
  const signed = async (kind: "evm" | "native", hash: string, beforeBroadcast?: BeforeBroadcast) => {
    try {
      await beforeBroadcast?.({ kind, nonce, hash });
    } catch {
      throw new NotBroadcast("not recorded");
    }
  };
  const nativeHash = () => (++natives).toString(16).toUpperCase().padStart(64, "C");
  const chain: RelayChain = {
    readWindow: async () => {
      events.push("window");
      return window;
    },
    openWindow: async (request, _deadline, beforeBroadcast) => {
      const hash = nativeHash();
      await signed("native", hash, beforeBroadcast);
      opens.push(request);
      options.onOpen?.();
      height += 100n;
      nonce += 1n;
      landed.add(hash);
      window = healthyWindow({ openedHeight: height, expiryHeight: height + 12_000n, maxValue: request.maxValue, remainingValue: request.maxValue });
      return { hash };
    },
    closeWindow: async (_deadline, beforeBroadcast) => {
      const hash = nativeHash();
      await signed("native", hash, beforeBroadcast);
      closes += 1;
      nonce += 1n;
      landed.add(hash);
      window = healthyWindow({ found: false, live: false, allowedTargets: [] });
      return { hash };
    },
    call: async (req) => {
      if (req.data.startsWith(GET_BOARD)) {
        const boardId = BigInt(`0x${req.data.slice(10)}`);
        const answer = options.board?.(boardId);
        if (answer !== undefined) return answer;
        const result = { chair: CHAIR, boardRef: H1, epoch: 3n, nonce: boardNonces.get(boardId) ?? 9n, memberCount: 2, documentCount: 1 };
        return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
      }
      if (req.data.startsWith(CREATE_NONCES)) {
        const chair = `0x${req.data.slice(34, 74)}`.toLowerCase();
        return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "createNonces", result: createNonces.get(chair) ?? 0n }) };
      }
      calls.push(req);
      return options.outcome?.(req) ?? { ok: true, data: "0x" };
    },
    estimateGas: async (req) => {
      events.push("estimate");
      estimates.push(req);
      return options.gas ?? 300_000n;
    },
    feeQuote: async () => QUOTE,
    send: async (tx, _deadline, beforeBroadcast) => {
      const hash: Hex = `0x${(count + 1).toString(16).padStart(64, "0")}`;
      await signed("evm", hash, beforeBroadcast);
      events.push("send:start");
      sends.push(tx);
      // The chain charges the window gas limit times fee cap for every transaction it admits.
      const cost = evmWindowCost({ gas: tx.gas, maxFeePerGas: tx.maxFeePerGas });
      window = { ...window, remainingTxs: window.remainingTxs - 1n, usedTxs: window.usedTxs + 1n, remainingValue: window.remainingValue - cost, usedValue: window.usedValue + cost };
      await new Promise((resolve) => setTimeout(resolve, options.sendDelayMs ?? 0));
      events.push("send:end");
      nonce += 1n;
      count += 1;
      if (options.landing === "pending") {
        pending.add(hash);
      } else {
        landed.add(hash);
        if (options.landing === "reverts") reverted.add(hash);
        else land(tx);
      }
      return hash;
    },
    nonce: async () => nonce,
    txStatus: async (_kind, hash) => (reverted.has(hash) ? "reverted" : landed.has(hash) ? "landed" : pending.has(hash) ? "pending" : "unknown"),
    registryCodeHash: async () => {
      codeReads += 1;
      return options.registry === undefined ? REGISTRY_CODE_KECCAK : options.registry.codeHash;
    },
    ...(options.fee === undefined ? {} : { receipt: async (hash: Hex) => (landed.has(hash) ? options.fee : undefined) }),
  };
  const touched = () => calls.length + estimates.length + sends.length + opens.length + events.length + closes;
  /** Spending through the window that never went through our relay: what a leaked classical key does. */
  const foreign = (txs: bigint, value: bigint) => {
    nonce += txs;
    window = { ...window, remainingTxs: window.remainingTxs - txs, usedTxs: window.usedTxs + txs, remainingValue: window.remainingValue - value, usedValue: window.usedValue + value };
  };
  /** A transaction signed with the relayer's key outside every window, such as a native one: it moves the nonce and nothing else. */
  const foreignNonce = () => {
    nonce += 1n;
  };
  /** Every send of ours still waiting reaches a block. */
  const mine = () => {
    for (const hash of pending) landed.add(hash);
    pending.clear();
  };
  /** A transaction of ours, spending `value` through the window, that reached a block after the node had said it refused it. */
  const lands = (hash: string, value: bigint) => {
    foreign(1n, value);
    landed.add(hash);
  };
  return { chain, calls, estimates, sends, opens, events, touched, closes: () => closes, foreign, foreignNonce, lands, mine, codeReads: () => codeReads, nonce: () => nonce };
}

/** Our own earlier sends through a test window that already shows `n` transactions used. */
async function ourSends(store: MemoryStore, n: number, openedHeight = 1_000n): Promise<MemoryStore> {
  for (let i = 0; i < n; i++) await recordWindowSend(store, openedHeight, evmWindowCost({ gas: 650_000n, maxFeePerGas: 250n * GWEI }));
  return store;
}

/** The mark a verify leaves once it has hashed the stored document: its size under its SHA-256, as docupload.ts verifiedSize reads it. */
async function verified(store: SharedStore, cipherHash: Hex, size: number | bigint): Promise<void> {
  await store.setIfAbsent(`verified:${cipherHash.slice(2)}`, size.toString(), VERIFIED_SECONDS);
}

function context(chain: RelayChain, over: Partial<RelayContext> = {}): RelayContext {
  return { clientIp: "203.0.113.7", now: NOW, store: new MemoryStore(), relayer: RELAYER, chain, sleep: async () => undefined, ...over };
}

function post(body: unknown): Request {
  return new Request("http://app.local/api/relay", {
    method: "POST",
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { "content-type": "application/json", "x-ava": "1" },
  });
}

const signed = { deadline: DEADLINE.toString(), signature: SIG };

/** One valid body per action, and the function and arguments viem must encode for it. */
const CASES = [
  {
    body: { action: "create", params: { chair: CHAIR, boardRef: H1, envelopeHash: H2, envelopeSize: "1700" }, ...signed },
    functionName: "createBoard",
    args: [CHAIR, H1, H2, 1700, DEADLINE, SIG],
  },
  {
    body: { action: "add", boardId: "7", params: { member: MEMBER, mode: "1", envelopeHash: H2, envelopeSize: "3300", epochAfter: "4" }, ...signed },
    functionName: "addMember",
    args: [7n, MEMBER, 1, H2, 3300, 4n, DEADLINE, SIG],
  },
  {
    body: { action: "remove", boardId: "7", params: { member: MEMBER, envelopeHash: H2, envelopeSize: "1700", epochAfter: "4" }, ...signed },
    functionName: "removeMember",
    args: [7n, MEMBER, H2, 1700, 4n, DEADLINE, SIG],
  },
  {
    body: { action: "rotate", boardId: "7", params: { envelopeHash: H2, envelopeSize: "1700", epochAfter: "4" }, ...signed },
    functionName: "rotateEpoch",
    args: [7n, H2, 1700, 4n, DEADLINE, SIG],
  },
  {
    body: { action: "post", boardId: "7", params: { docRef: H1, cipherHash: H2, cipherSize: "26214400", epoch: "3" }, ...signed },
    functionName: "postDocument",
    args: [7n, H1, H2, 26_214_400n, 3n, DEADLINE, SIG],
  },
  {
    body: { action: "transfer", boardId: "7", params: { newChair: MEMBER }, ...signed },
    functionName: "transferChair",
    args: [7n, MEMBER, DEADLINE, SIG],
  },
] as const;

const ROTATE = CASES[3].body;
const rotateOn = (boardId: number) => ({ ...ROTATE, boardId: String(boardId) });
const createBy = (chair: string) => ({ ...CASES[0].body, params: { ...CASES[0].body.params, chair } });

let logged: string[] = [];

beforeEach(() => {
  logged = [];
  vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    logged.push(String(line));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("handleRelay: what it sends", () => {
  it("builds exactly the calldata viem encodes for each of the six actions, sends it to the registry, and answers only a hash", async () => {
    for (const c of CASES) {
      const stub = stubChain();
      const store = new MemoryStore();
      await verified(store, H2, 26_214_400);
      const response = await handleRelay(post(c.body), context(stub.chain, { store }));
      expect(response.status).toBe(202);
      expect(Object.keys(await response.json())).toEqual(["txHash"]);
      const expected = encodeFunctionData({ abi: boardRegistryAbi, functionName: c.functionName, args: c.args } as Parameters<typeof encodeFunctionData>[0]);
      // Once before anything is counted, and once more under the send lock, right before the send.
      const tx = { from: RELAYER.evm, to: REGISTRY_ADDRESS, data: expected };
      expect(stub.calls).toEqual([tx, tx]);
      expect(stub.estimates).toEqual([tx]);
      expect(stub.sends).toEqual([{ to: REGISTRY_ADDRESS, data: expected, gas: GAS_CEILING[c.body.action], maxFeePerGas: 201n * GWEI, maxPriorityFeePerGas: GWEI }]);
    }
    expect(logged.every((line) => !line.includes(SIG.slice(2, 66)))).toBe(true);
  });

  it("ignores a body that names another target, gas or value: those fields do not exist", async () => {
    const stub = stubChain();
    const body = { ...ROTATE, target: OTHER, to: OTHER, gas: "30000000", value: "1000000" };
    expect((await handleRelay(post(body), context(stub.chain))).status).toBe(202);
    expect(stub.sends.map((s) => [s.to, s.gas])).toEqual([[REGISTRY_ADDRESS, GAS_CEILING.rotate]]);
  });

  it("records the worst case, gas ceiling times fee cap, against the day before sending, and holds the fee cap at 250 gwei", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const hot = { ...stub.chain, feeQuote: async () => ({ baseFeePerGas: 130n * GWEI, maxPriorityFeePerGas: 2n * GWEI }) };
    expect((await handleRelay(post(ROTATE), context(hot, { store }))).status).toBe(202);
    expect(stub.sends[0]?.maxFeePerGas).toBe(MAX_FEE_PER_GAS);
    expect(await spentToday(store, NOW)).toBe(evmWindowCost({ gas: GAS_CEILING.rotate, maxFeePerGas: MAX_FEE_PER_GAS }));
    const cold = { ...stub.chain, feeQuote: async () => ({ baseFeePerGas: 249n * GWEI, maxPriorityFeePerGas: 2n * GWEI }) };
    expect(await (await handleRelay(post(rotateOn(8)), context(cold, { store }))).json()).toEqual({ error: "fee_above_ceiling" });
    expect(stub.sends).toHaveLength(1);
  });
});

describe("handleRelay: refusals before any chain call", () => {
  it("refuses a body over 16 KB, another method and another content type", async () => {
    const stub = stubChain();
    const big = { ...ROTATE, padding: "x".repeat(16_384) };
    expect((await handleRelay(post(big), context(stub.chain))).status).toBe(413);
    expect((await handleRelay(new Request("http://app.local/api/relay", { headers: { "x-ava": "1" } }), context(stub.chain))).status).toBe(405);
    const text = new Request("http://app.local/api/relay", { method: "POST", body: JSON.stringify(ROTATE), headers: { "content-type": "text/plain", "x-ava": "1" } });
    expect((await handleRelay(text, context(stub.chain))).status).toBe(415);
    expect(stub.touched()).toBe(0);
  });

  it("refuses a malformed address, hash, integer, board id, signature length or extra parameter", async () => {
    const add = CASES[1].body;
    const withParams = (params: Record<string, unknown>) => ({ ...add, params: { ...add.params, ...params } });
    const bad: unknown[] = [
      withParams({ member: "0x3c44cdddb6a900fa2b585dd299e03d12fa4293b" }),
      withParams({ member: "0x3C44cdddb6a900fa2b585dd299e03d12fa4293bc" }),
      withParams({ member: MEMBER_LOWER }),
      withParams({ member: "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq" }),
      withParams({ envelopeHash: H2.slice(0, -1) }),
      withParams({ envelopeHash: `0x${"zz".repeat(32)}` }),
      withParams({ envelopeSize: "-1" }),
      withParams({ envelopeSize: "1.5" }),
      withParams({ envelopeSize: "01700" }),
      withParams({ envelopeSize: "4294967296" }),
      withParams({ envelopeSize: 1700 }),
      withParams({ epochAfter: "18446744073709551616" }),
      withParams({ extra: "1" }),
      { ...add, deadline: "18446744073709551616" },
      { ...add, boardId: "0" },
      { ...add, boardId: undefined },
      { ...CASES[0].body, boardId: "7" },
      { ...add, signature: bytesToHex(new Uint8Array(4626)) },
      { ...add, signature: bytesToHex(new Uint8Array(4628)) },
      { ...add, signature: SIG.slice(2) },
      { ...add, action: "upgrade" },
      "not json",
    ];
    for (const body of bad) {
      const stub = stubChain();
      const response = await handleRelay(post(body), context(stub.chain));
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "bad_body" });
      expect(stub.touched()).toBe(0);
    }
  });
});

describe("handleRelay: the registry and the money decide", () => {
  it("answers 422 with the registry's error name and nothing else when eth_call reverts, and never sends", async () => {
    const badSignature = encodeErrorResult({ abi: boardRegistryAbi, errorName: "BadSignature", args: [CHAIR] });
    for (const [revertData, name] of [
      [badSignature, "BadSignature"],
      ["0xdeadbeef", "reverted"],
      [undefined, "reverted"],
    ] as const) {
      const stub = stubChain({ outcome: () => ({ ok: false, revertData }) });
      const response = await handleRelay(post(ROTATE), context(stub.chain));
      expect(response.status).toBe(422);
      expect(await response.json()).toEqual({ error: name });
      expect(stub.sends).toHaveLength(0);
    }
    const unknownBoard = encodeErrorResult({ abi: boardRegistryAbi, errorName: "UnknownBoard", args: [99n] });
    const stub = stubChain({ board: () => ({ ok: false, revertData: unknownBoard }) });
    expect(await (await handleRelay(post(rotateOn(99)), context(stub.chain))).json()).toEqual({ error: "UnknownBoard" });
    expect(stub.sends).toHaveLength(0);
  });

  it("never sends when the gas estimate is above the action's ceiling", async () => {
    const stub = stubChain({ gas: GAS_CEILING.rotate + 1n });
    const response = await handleRelay(post(ROTATE), context(stub.chain));
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "gas_above_ceiling" });
    expect(stub.sends).toHaveLength(0);
  });

  it("closes a window it did not ask for, refuses, and sends nothing", async () => {
    for (const odd of [{ allowedTargets: [] }, { nativeOnly: true }, { allowedTargets: [REGISTRY_ADDRESS, OTHER] }]) {
      const stub = stubChain({ window: healthyWindow(odd) });
      const response = await handleRelay(post(ROTATE), context(stub.chain));
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "window_unavailable" });
      expect(stub.closes()).toBe(1);
      expect(stub.calls).toHaveLength(1);
      expect(stub.estimates).toHaveLength(0);
      expect(stub.sends).toHaveLength(0);
    }
  });

  it("with less than one worst-case transaction left today opens no window and refuses", async () => {
    const store = new MemoryStore();
    await store.incrWindow(spendKey(NOW), 172_800, Number(DAILY_SPEND_CEILING_UQOR - 100_000n));
    const stub = stubChain({ window: healthyWindow({ found: false, live: false }) });
    const response = await handleRelay(post(ROTATE), context(stub.chain, { store }));
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "daily_ceiling" });
    expect(stub.opens).toHaveLength(0);
    expect(stub.sends).toHaveLength(0);
  });

  it("with 0.5 QOR left today opens a window of at most 0.5 QOR minus the open fee", async () => {
    const store = new MemoryStore();
    await store.incrWindow(spendKey(NOW), 172_800, Number(DAILY_SPEND_CEILING_UQOR - 500_000n));
    const stub = stubChain({ window: healthyWindow({ found: false, live: false }) });
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store }))).status).toBe(202);
    expect(stub.opens.map((o) => o.maxValue)).toEqual([500_000n - WINDOW_OPEN_FEE_UQOR]);
    expect(await spentToday(store, NOW)).toBeLessThanOrEqual(DAILY_SPEND_CEILING_UQOR);
  });

  it("refuses once the daily ceiling is reached, and does not renew the window either", async () => {
    const store = new MemoryStore();
    const worst = evmWindowCost({ gas: GAS_CEILING.rotate, maxFeePerGas: 201n * GWEI });
    await store.incrWindow(spendKey(NOW), 172_800, Number(DAILY_SPEND_CEILING_UQOR - worst + 1n));
    const stub = stubChain();
    const response = await handleRelay(post(ROTATE), context(stub.chain, { store }));
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "daily_ceiling" });
    expect(stub.sends).toHaveLength(0);

    const low = stubChain({ window: healthyWindow({ remainingTxs: 2n }) });
    await ourSends(store, 38);
    expect(await (await handleRelay(post(ROTATE), context(low.chain, { store }))).json()).toEqual({ error: "daily_ceiling" });
    expect(low.opens).toHaveLength(0);
    expect(low.sends).toHaveLength(0);
  });

  it("serialises two concurrent relays on the shared send lock", async () => {
    const stub = stubChain({ sendDelayMs: 300 });
    const store = new MemoryStore();
    const [a, b] = await Promise.all([
      handleRelay(post(rotateOn(1)), context(stub.chain, { store, clientIp: "198.51.100.1" })),
      handleRelay(post(rotateOn(2)), context(stub.chain, { store, clientIp: "198.51.100.2" })),
    ]);
    expect([a.status, b.status]).toEqual([202, 202]);
    expect(stub.events).toEqual(["window", "estimate", "send:start", "send:end", "window", "estimate", "send:start", "send:end"]);
  });
});

describe("handleRelay: time", () => {
  it("keeps every lock at 60 s or less, every wait at 20 s or less, and the whole path inside 55 s", () => {
    expect(LOCK_TTL_SECONDS).toBeLessThanOrEqual(60);
    expect(Math.max(SEND_LOCK_WAIT_MS, WINDOW_LOCK_WAIT_MS, LOCK_MAX_WAIT_MS)).toBeLessThanOrEqual(20_000);
    expect(RELAY_DEADLINE_MS).toBeLessThanOrEqual(55_000);
    expect(OPEN_CUTOFF_MS + NATIVE_TX_BUDGET_MS + WAIT_AFTER_WINDOW_MS).toBeLessThanOrEqual(SEND_CUTOFF_MS);
    expect(SEND_CUTOFF_MS + 10_000).toBeLessThanOrEqual(RELAY_DEADLINE_MS);
  });

  it("refuses rather than starts a send when a renewal leaves it past 45 s", async () => {
    let clock = 0;
    const stub = stubChain({ window: healthyWindow({ remainingTxs: 2n }), onOpen: () => (clock += 36_000) });
    const sleep = async (ms: number) => {
      clock += ms;
    };
    const response = await handleRelay(post(ROTATE), context(stub.chain, { clock: () => clock, sleep, store: await ourSends(new MemoryStore(), 38) }));
    expect(clock).toBeGreaterThan(45_000);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "out_of_time" });
    expect(stub.opens).toHaveLength(1);
    expect(stub.sends).toHaveLength(0);
  });

  it("does not start a renewal after 20 s, but still sends through a window that needs none", async () => {
    let clock = 0;
    const late = { board: () => ((clock = 21_000), undefined) };
    const low = stubChain({ ...late, window: healthyWindow({ remainingTxs: 2n }) });
    const refused = await handleRelay(post(ROTATE), context(low.chain, { clock: () => clock, store: await ourSends(new MemoryStore(), 38) }));
    expect(await refused.json()).toEqual({ error: "out_of_time" });
    expect(low.opens).toHaveLength(0);
    expect(low.sends).toHaveLength(0);

    clock = 0;
    const healthy = stubChain(late);
    expect((await handleRelay(post(ROTATE), context(healthy.chain, { clock: () => clock }))).status).toBe(202);
    expect(healthy.sends).toHaveLength(1);
  });
});

describe("handleRelay: someone else spending the window", () => {
  it("never trips on our own sends through one window", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses = [];
    for (let i = 1; i <= 5; i++) statuses.push((await handleRelay(post(rotateOn(i)), context(stub.chain, { store, clientIp: `198.51.100.${i}` }))).status);
    expect(statuses).toEqual([202, 202, 202, 202, 202]);
    expect(stub.closes()).toBe(0);
    expect(await store.get(haltKey(NOW))).toBeNull();
  });

  it("trips on the next read after one transaction or 1 uqor spent outside our record: closes, halts, answers 503", async () => {
    for (const [txs, value] of [
      [1n, 0n],
      [0n, 1n],
    ] as const) {
      const stub = stubChain();
      const store = new MemoryStore();
      for (let i = 1; i <= 2; i++) expect((await handleRelay(post(rotateOn(i)), context(stub.chain, { store, clientIp: `198.51.100.${i}` }))).status).toBe(202);
      stub.foreign(txs, value);
      const response = await handleRelay(post(rotateOn(3)), context(stub.chain, { store, clientIp: "198.51.100.3" }));
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "halted" });
      expect(stub.closes()).toBe(1);
      expect(stub.sends).toHaveLength(2);
      expect(await store.get(haltKey(NOW))).toBe("suspected_key_leak");
      expect(logged.some((line) => line.includes("relayer_window_closed") && line.includes("suspected_key_leak"))).toBe(true);
    }
  });

  it("halts and closes when a transaction lands between the window read and its renewal, where no window counter can see it", async () => {
    const stub = stubChain({ window: healthyWindow({ remainingBlocks: 599n }) });
    const store = new MemoryStore();
    const chain: RelayChain = {
      ...stub.chain,
      openWindow: async (request, deadline, beforeBroadcast) => {
        stub.foreign(1n, 6_000_000n);
        return stub.chain.openWindow(request, deadline, beforeBroadcast);
      },
    };
    const response = await handleRelay(post(ROTATE), context(chain, { store }));
    expect(await response.json()).toEqual({ error: "halted" });
    expect(response.status).toBe(503);
    expect(stub.opens).toHaveLength(1);
    expect(stub.closes()).toBe(1);
    expect(stub.sends).toHaveLength(0);
    expect(await store.get(haltKey(NOW))).toBe("suspected_key_leak");
  });

  it("on a halted day tries the failed close again before answering, and still holds the halt the next UTC day", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    let tries = 0;
    const chain: RelayChain = {
      ...stub.chain,
      closeWindow: async (deadline, beforeBroadcast) => {
        tries += 1;
        if (tries === 1) throw new Error("the node did not take the close");
        return stub.chain.closeWindow(deadline, beforeBroadcast);
      },
    };
    expect((await handleRelay(post(rotateOn(1)), context(chain, { store }))).status).toBe(202);
    stub.foreign(1n, 0n);
    expect(await (await handleRelay(post(rotateOn(2)), context(chain, { store }))).json()).toEqual({ error: "halted" });
    expect(await (await handleRelay(post(rotateOn(3)), context(chain, { store }))).json()).toEqual({ error: "halted" });
    expect(tries).toBeGreaterThanOrEqual(2);
    expect(stub.closes()).toBe(1);

    const nextDay = await handleRelay(post(rotateOn(4)), context(chain, { store, now: Date.parse("2026-11-18T00:00:01Z") }));
    expect(await nextDay.json()).toEqual({ error: "halted" });
    expect(stub.opens).toHaveLength(0);
    expect(stub.sends).toHaveLength(1);
  });

  it("holds a leak halt on every later day until an operator clears it, then serves again", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store }))).status).toBe(202);
    stub.foreign(1n, 0n);
    expect((await handleRelay(post(rotateOn(2)), context(stub.chain, { store }))).status).toBe(503);
    for (const day of ["2026-11-17T23:59:59Z", "2026-11-18T00:00:01Z", "2026-12-25T09:00:00Z"]) {
      expect(await (await handleRelay(post(rotateOn(3)), context(stub.chain, { store, now: Date.parse(day) }))).json()).toEqual({ error: "halted" });
    }
    expect(stub.opens).toHaveLength(0);
    expect(stub.sends).toHaveLength(1);

    const cleared = await clearHalt(store, RELAYER.evm, NOW);
    expect(cleared.halt).toBe("suspected_key_leak");
    expect((await handleRelay(post(rotateOn(4)), context(stub.chain, { store }))).status).toBe(202);
    expect(stub.opens).toHaveLength(1);
    expect(stub.sends).toHaveLength(2);
  });
});

describe("handleRelay: the relayer's nonce", () => {
  const worstRotate = evmWindowCost({ gas: GAS_CEILING.rotate, maxFeePerGas: 201n * GWEI });

  it("halts on the next relay when a send the node refused lost its nonce to someone else's transaction", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const refused: RelayChain = {
      ...stub.chain,
      send: async (_tx, _deadline, beforeBroadcast) => {
        await beforeBroadcast?.({ kind: "evm", nonce: stub.nonce(), hash: `0x${"ab".repeat(32)}` });
        // A leaked key's transaction takes the nonce ours was signed for, spending what ours would have.
        stub.foreign(1n, worstRotate);
        throw new Error(`EVM transaction 0x${"ab".repeat(32)} was refused and is not on chain.`);
      },
    };
    expect(await (await handleRelay(post(rotateOn(1)), context(refused, { store }))).json()).toEqual({ error: "broadcast_failed" });
    const next = await handleRelay(post(rotateOn(2)), context(stub.chain, { store }));
    expect(await next.json()).toEqual({ error: "halted" });
    expect(next.status).toBe(503);
    expect(stub.closes()).toBe(1);
    expect(stub.sends).toHaveLength(0);
    expect(await store.get(haltKey(NOW))).toBe("suspected_key_leak");
  });

  it("does not halt when a send the node said it refused lands after all", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const hash: Hex = `0x${"cd".repeat(32)}`;
    const late: RelayChain = {
      ...stub.chain,
      send: async (_tx, _deadline, beforeBroadcast) => {
        await beforeBroadcast?.({ kind: "evm", nonce: stub.nonce(), hash });
        throw new Error(`EVM transaction ${hash} was refused and is not on chain.`);
      },
    };
    expect(await (await handleRelay(post(rotateOn(1)), context(late, { store }))).json()).toEqual({ error: "broadcast_failed" });
    stub.lands(hash, worstRotate);
    expect((await handleRelay(post(rotateOn(2)), context(stub.chain, { store }))).status).toBe(202);
    expect(stub.closes()).toBe(0);
    expect(await store.get(haltKey(NOW))).toBeNull();
  });

  it("refuses, without halting or moving the stored nonce, while a send of ours still waits for a block, and serves once it lands", async () => {
    const stub = stubChain({ landing: "pending" });
    const store = new MemoryStore();
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store }))).status).toBe(202);
    expect(await (await handleRelay(post(rotateOn(2)), context(stub.chain, { store }))).json()).toEqual({ error: "window_unavailable" });
    expect(await store.get(nonceKey(RELAYER.evm))).toBe("0");
    expect(await store.get(haltKey(NOW))).toBeNull();
    stub.mine();
    expect((await handleRelay(post(rotateOn(2)), context(stub.chain, { store }))).status).toBe(202);
    expect(stub.closes()).toBe(0);
  });

  it("halts when the chain is two nonces past the stored one and only the first is ours", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store }))).status).toBe(202);
    stub.foreignNonce();
    const next = await handleRelay(post(rotateOn(2)), context(stub.chain, { store }));
    expect(await next.json()).toEqual({ error: "halted" });
    expect(stub.sends).toHaveLength(1);
    expect(stub.closes()).toBe(1);
    expect(await store.get(haltKey(NOW))).toBe("suspected_key_leak");
    expect(logged.some((line) => line.includes("relayer_window_closed") && line.includes('"foreignNonce":"1"'))).toBe(true);
  });

  it("never moves the stored nonce twice for one write applied twice, so no nonce is skipped for a foreign transaction to hide in", async () => {
    const store = new MemoryStore();
    // What a request retried after its reply was lost does: the write lands, then lands again.
    const swap = store.compareAndSet.bind(store);
    const add = store.incrWindow.bind(store);
    store.compareAndSet = async (...args) => (await swap(...args), swap(...args));
    store.incrWindow = async (...args) => (await add(...args), add(...args));
    const stub = stubChain();
    const lost: RelayChain = {
      ...stub.chain,
      send: async (_tx, _deadline, beforeBroadcast) => {
        await beforeBroadcast?.({ kind: "evm", nonce: stub.nonce(), hash: `0x${"ef".repeat(32)}` });
        stub.foreign(1n, worstRotate);
        throw new Error(`EVM transaction 0x${"ef".repeat(32)} was refused and is not on chain.`);
      },
    };
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store, clientIp: "198.51.100.1" }))).status).toBe(202);
    expect(await (await handleRelay(post(rotateOn(2)), context(lost, { store, clientIp: "198.51.100.2" }))).json()).toEqual({ error: "broadcast_failed" });
    expect(await store.get(nonceKey(RELAYER.evm))).toBe("1");
    expect(await (await handleRelay(post(rotateOn(3)), context(stub.chain, { store, clientIp: "198.51.100.3" }))).json()).toEqual({ error: "halted" });
  });
});

/** A MemoryStore that also lists the key of every call but a read, whatever methods the store has, so a test can show nothing was counted. */
function recordingStore(): { store: SharedStore; written: string[] } {
  const inner = new MemoryStore();
  const written: string[] = [];
  const store = new Proxy(inner, {
    get(target, property) {
      const value: unknown = Reflect.get(target, property, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        if (property !== "get") written.push(String(args[0]));
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { store, written };
}

describe("handleRelay: the registry's code", () => {
  it("answers every relay 503 registry_mismatch and moves no counter when the registry address holds other code or none, or the code cannot be checked", async () => {
    for (const codeHash of [keccak256("0x6080604052"), undefined, "no reader"] as const) {
      const stub = stubChain(codeHash === "no reader" ? {} : { registry: { codeHash } });
      const { registryCodeHash, ...unchecked } = stub.chain;
      const chain: RelayChain = codeHash === "no reader" ? unchecked : stub.chain;
      const { store, written } = recordingStore();
      const junk = { ...ROTATE, signature: bytesToHex(new Uint8Array(4627)) };
      for (const body of [ROTATE, CASES[0].body, junk, "not json"]) {
        const response = await handleRelay(post(body), context(chain, { store }));
        expect(response.status).toBe(503);
        expect(await response.json()).toEqual({ error: "registry_mismatch" });
      }
      expect(written).toEqual([]);
      expect(stub.codeReads()).toBe(codeHash === "no reader" ? 0 : 1);
      expect(registryCodeHash).toBeTypeOf("function");
      expect(stub.calls).toHaveLength(0);
      expect(stub.sends).toHaveLength(0);
    }
  });
});

describe("handleRelay: copies of one signed action", () => {
  it("relays the first of 60 byte-identical copies from three IPs, answers the rest 409, and counts the chair and board once", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses: number[] = [];
    const answers = new Set<string>();
    for (let i = 0; i < 60; i++) {
      const response = await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: `198.51.100.${(i % 3) + 1}` }));
      statuses.push(response.status);
      if (i > 0) answers.add(JSON.stringify(await response.json()));
    }
    expect(statuses).toEqual([202, ...new Array(59).fill(409)]);
    expect([...answers]).toEqual([JSON.stringify({ error: "duplicate" })]);
    expect(await store.get(`rate:relay:chair:${CHAIR.toLowerCase()}`)).toBe("1");
    expect(await store.get("rate:relay:board:7")).toBe("1");
    expect(await store.get("rate:relay:valid")).toBe("1");
    expect(stub.sends).toHaveLength(1);

    const another = { ...ROTATE, params: { ...ROTATE.params, epochAfter: "5" } };
    expect((await handleRelay(post(another), context(stub.chain, { store, clientIp: "198.51.100.4" }))).status).toBe(202);
    expect(stub.sends).toHaveLength(2);
  });

  it("accepts the same bytes again after a refusal before broadcast, and only once", async () => {
    const stub = stubChain();
    let gas = GAS_CEILING.rotate + 1n;
    const chain: RelayChain = { ...stub.chain, estimateGas: async () => gas };
    const store = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(chain, { store }))).json()).toEqual({ error: "gas_above_ceiling" });
    gas = 300_000n;
    expect((await handleRelay(post(ROTATE), context(chain, { store }))).status).toBe(202);
    expect(await (await handleRelay(post(ROTATE), context(chain, { store }))).json()).toEqual({ error: "duplicate" });
    expect(stub.sends).toHaveLength(1);
  });
});

describe("handleRelay: one action per board nonce in flight", () => {
  const chairKey = `rate:relay:chair:${CHAIR.toLowerCase()}`;
  const resigned = (epochAfter: number) => ({ ...ROTATE, params: { ...ROTATE.params, epochAfter: String(epochAfter) } });

  it("answers a second, different action at a board nonce or create nonce with one in flight 409 nonce_in_flight, and moves no counter", async () => {
    // Each send waits unmined, so each action stays in flight.
    const stub = stubChain({ landing: "pending" });
    const store = new MemoryStore();
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.1" }))).status).toBe(202);
    const second = await handleRelay(post(resigned(5)), context(stub.chain, { store, clientIp: "198.51.100.2" }));
    expect(second.status).toBe(409);
    expect(await second.json()).toEqual({ error: "nonce_in_flight" });
    expect(await store.get("rate:relay:board:7")).toBe("1");
    expect(await store.get(chairKey)).toBe("1");
    expect(await store.get("rate:relay:valid")).toBe("1");
    expect(await (await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.3" }))).json()).toEqual({ error: "duplicate" });
    expect(stub.sends).toHaveLength(1);

    // A fresh relayer, since one of ours waiting for a block holds every later send back.
    const creates = stubChain({ landing: "pending" });
    const createStore = new MemoryStore();
    const create = createBy(SECOND_CHAIR);
    expect((await handleRelay(post(create), context(creates.chain, { store: createStore, clientIp: "198.51.100.4" }))).status).toBe(202);
    const otherCreate = { ...create, params: { ...create.params, boardRef: H2 } };
    expect(await (await handleRelay(post(otherCreate), context(creates.chain, { store: createStore, clientIp: "198.51.100.5" }))).json()).toEqual({ error: "nonce_in_flight" });
    expect(await createStore.get(`rate:relay:chair:${SECOND_CHAIR}`)).toBe("1");
    expect(await createStore.get("rate:relay:valid")).toBe("1");
    expect(creates.sends).toHaveLength(1);
  });

  it("lets a different action, or the same bytes, take a nonce whose marked transaction reverted with the board nonce unchanged, with no receipt seen", async () => {
    for (const later of [resigned(5), ROTATE]) {
      const stub = stubChain({ landing: "reverts" });
      const store = new MemoryStore();
      expect((await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.1" }))).status).toBe(202);
      expect((await handleRelay(post(later), context(stub.chain, { store, clientIp: "198.51.100.2" }))).status).toBe(202);
      expect(stub.sends).toHaveLength(2);
    }
  });

  it("frees the nonce once a receipt is in, even for a revert, and at once for a refusal before broadcast", async () => {
    const reverted = stubChain({ landing: "reverts", fee: { gasUsed: 300_000n, effectiveGasPrice: 101n * GWEI } });
    const store = new MemoryStore();
    expect((await handleRelay(post(ROTATE), context(reverted.chain, { store }))).status).toBe(202);
    expect((await handleRelay(post(resigned(5)), context(reverted.chain, { store }))).status).toBe(202);

    const refused = stubChain({ landing: "reverts", gas: GAS_CEILING.rotate + 1n });
    const fresh = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refused.chain, { store: fresh }))).json()).toEqual({ error: "gas_above_ceiling" });
    const served = stubChain({ landing: "reverts" });
    expect((await handleRelay(post(resigned(5)), context(served.chain, { store: fresh }))).status).toBe(202);
  });

  const lostHash: Hex = `0x${"ab".repeat(32)}`;
  /** A send the node refused: recorded and handed over, then not seen on chain before the deadline. */
  const refusedBy = (chain: RelayChain, nonce: () => bigint): RelayChain => ({
    ...chain,
    send: async (_tx, _deadline, beforeBroadcast) => {
      await beforeBroadcast?.({ kind: "evm", nonce: nonce(), hash: lostHash });
      throw new Error(`EVM transaction ${lostHash} was refused and is not on chain.`);
    },
  });

  it("lets a different action land at a board nonce once the send the node refused there is unknown to the chain, so a chair can cancel by landing (C26)", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(stub.chain, stub.nonce), { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    const cancel = await handleRelay(post(resigned(5)), context(stub.chain, { store, clientIp: "198.51.100.2" }));
    expect(cancel.status).toBe(202);
    expect(stub.sends.map((s) => s.data)).toEqual([encodeFunctionData({ abi: boardRegistryAbi, functionName: "rotateEpoch", args: [7n, H2, 1700, 5n, DEADLINE, SIG] })]);
  });

  it("counts one action once against its board, its chair and the valid total, though its first send was lost and the same bytes were relayed again", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(stub.chain, stub.nonce), { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.2" }))).status).toBe(202);
    expect({ valid: await store.get("rate:relay:valid"), board: await store.get("rate:relay:board:7"), chair: await store.get(chairKey) }).toEqual({ valid: "1", board: "1", chair: "1" });
    // A different action is counted as its own.
    expect((await handleRelay(post(resigned(5)), context(stub.chain, { store, clientIp: "198.51.100.3" }))).status).toBe(202);
    expect(await store.get("rate:relay:board:7")).toBe("2");
  });

  it("still counts one action once when its first send was lost and the same bytes come back after the counting window has ended", async () => {
    let storeClock = NOW;
    const stub = stubChain();
    const store = new MemoryStore({ now: () => storeClock });
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(stub.chain, stub.nonce), { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    const later = NOW + RELAY_LIMITS.windowSeconds * 1000 + 1_000;
    storeClock = later;
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, now: later, clientIp: "198.51.100.2" }))).status).toBe(202);
    expect({ valid: await store.get("rate:relay:valid"), board: await store.get("rate:relay:board:7"), chair: await store.get(chairKey) }).toEqual({ valid: null, board: null, chair: null });
    expect(stub.sends).toHaveLength(1);
  });

  it("lets through the pre-read a byte-identical retry its chair's full hourly count already holds, while a new action of that chair is still refused 429", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const limits = { ...RELAY_LIMITS, perChair: 1 };
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(stub.chain, stub.nonce), { store, limits, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    expect(await store.get(chairKey)).toBe("1");
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, limits, clientIp: "198.51.100.2" }))).status).toBe(202);
    expect(await store.get(chairKey)).toBe("1");
    const fresh = await handleRelay(post(resigned(6)), context(stub.chain, { store, limits, clientIp: "198.51.100.3" }));
    expect(fresh.status).toBe(429);
    expect(await fresh.json()).toEqual({ error: "rate_limited" });
    expect(stub.sends).toHaveLength(1);
  });

  it("relays the same bytes again once the send the node refused is unknown to the chain, and refuses copies and re-signed actions 409 while the chain holds it", async () => {
    const lost = stubChain();
    const store = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(lost.chain, lost.nonce), { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    expect((await handleRelay(post(ROTATE), context(lost.chain, { store, clientIp: "198.51.100.2" }))).status).toBe(202);
    expect(lost.sends).toHaveLength(1);

    const held = stubChain();
    const waiting: RelayChain = { ...held.chain, txStatus: async (kind, hash) => (hash === lostHash ? "pending" : (held.chain.txStatus?.(kind, hash) ?? "unknown")) };
    const heldStore = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(waiting, held.nonce), { store: heldStore, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    expect(await (await handleRelay(post(ROTATE), context(waiting, { store: heldStore, clientIp: "198.51.100.2" }))).json()).toEqual({ error: "duplicate" });
    expect(await (await handleRelay(post(resigned(5)), context(waiting, { store: heldStore, clientIp: "198.51.100.3" }))).json()).toEqual({ error: "nonce_in_flight" });
    expect(held.sends).toHaveLength(0);
  });

  it("holds a mark that has no transaction yet only while its own relay is inside its deadline", async () => {
    for (const [later, answer] of [
      [ROTATE, "duplicate"],
      [resigned(5), "nonce_in_flight"],
    ] as const) {
      const stub = stubChain();
      const store = new MemoryStore();
      // Handed over before any hash was known, as a relay that died after taking its marks leaves them.
      const vanished: RelayChain = {
        ...stub.chain,
        send: async () => {
          throw new Error("the connection dropped");
        },
      };
      expect(await (await handleRelay(post(ROTATE), context(vanished, { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
      expect(await (await handleRelay(post(later), context(stub.chain, { store, clientIp: "198.51.100.2", now: NOW + RELAY_DEADLINE_MS }))).json()).toEqual({ error: answer });
      expect((await handleRelay(post(later), context(stub.chain, { store, clientIp: "198.51.100.3", now: NOW + RELAY_DEADLINE_MS + 1 }))).status).toBe(202);
      expect(stub.sends).toHaveLength(1);
    }
  });

  it("refuses a different action 409 nonce_in_flight, moving no counter, when the send the chain did not know turns up before that action reaches the send lock", async () => {
    const stub = stubChain();
    let lookups = 0;
    const turnsUp: RelayChain = { ...stub.chain, txStatus: async (kind, hash) => (hash === lostHash ? (++lookups === 1 ? "unknown" : "pending") : (stub.chain.txStatus?.(kind, hash) ?? "unknown")) };
    const store = new MemoryStore();
    expect(await (await handleRelay(post(ROTATE), context(refusedBy(turnsUp, stub.nonce), { store, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    const counts = async () => ({ valid: await store.get("rate:relay:valid"), board: await store.get("rate:relay:board:7"), chair: await store.get(chairKey) });
    const before = await counts();
    const second = await handleRelay(post(resigned(5)), context(turnsUp, { store, clientIp: "198.51.100.2" }));
    expect(await second.json()).toEqual({ error: "nonce_in_flight" });
    expect(lookups).toBeGreaterThanOrEqual(2);
    expect(await counts()).toEqual(before);
    expect(await (await handleRelay(post(resigned(6)), context(turnsUp, { store, clientIp: "198.51.100.3" }))).json()).toEqual({ error: "nonce_in_flight" });
    expect(stub.sends).toHaveLength(0);
  });

  it("counts an action against the valid total only once its pre-flight under the send lock passes", async () => {
    let preflights = 0;
    const stub = stubChain({ outcome: () => (++preflights === 2 ? { ok: false, revertData: undefined } : { ok: true, data: "0x" }) });
    const store = new MemoryStore();
    const response = await handleRelay(post(ROTATE), context(stub.chain, { store }));
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "reverted" });
    expect(await store.get("rate:relay:valid")).toBeNull();
    expect(stub.sends).toHaveLength(0);
  });
});

describe("handleRelay: the hourly counters move last", () => {
  const MIB = 1024 * 1024;
  const chairKey = `rate:relay:chair:${CHAIR.toLowerCase()}`;
  const fullPost = { ...CASES[4].body };
  /** Refusals a chair's own action meets under the send lock, each on a fresh store and chain. */
  const causes = [
    {
      body: fullPost,
      answer: { status: 429, error: "post_bytes" },
      chain: () => stubChain(),
      setup: async (store: SharedStore) => {
        await verified(store, H2, 25 * MIB);
        await store.incrWindow(ledgerFor("chair_posts", NOW, CHAIR).key, 172_800, 100 * MIB);
      },
    },
    {
      body: ROTATE,
      answer: { status: 429, error: "rate_limited" },
      chain: () => stubChain(),
      setup: async (store: SharedStore) => void (await store.incrWindow(ledgerFor("chair", NOW, CHAIR).key, 172_800, Number(PER_CHAIR_DAILY_UQOR))),
    },
    {
      body: ROTATE,
      answer: { status: 422, error: "gas_above_ceiling" },
      chain: () => stubChain({ gas: GAS_CEILING.rotate + 1n }),
      setup: async () => undefined,
    },
  ] as const;

  it("moves no per-board, per-chair or valid counter for 60 relays of one chair's action refused for its post bytes, its daily budget or its gas", async () => {
    for (const cause of causes) {
      const stub = cause.chain();
      const store = new MemoryStore();
      await cause.setup(store);
      const answers = new Set<string>();
      for (let i = 0; i < 60; i++) {
        const response = await handleRelay(post(cause.body), context(stub.chain, { store, clientIp: `198.51.100.${(i % 3) + 1}` }));
        answers.add(`${response.status} ${JSON.stringify(await response.json())}`);
      }
      expect([...answers]).toEqual([`${cause.answer.status} ${JSON.stringify({ error: cause.answer.error })}`]);
      expect({ valid: await store.get("rate:relay:valid"), board: await store.get("rate:relay:board:7"), chair: await store.get(chairKey) }).toEqual({ valid: null, board: null, chair: null });
      expect(stub.sends).toHaveLength(0);
    }
  });

  it("gives back the day's booking of a relay its chair's hourly count refuses under the send lock, after both of two relays passed the read before it", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const limits = { ...RELAY_LIMITS, perChair: 1 };
    const [a, b] = await Promise.all([
      handleRelay(post(rotateOn(1)), context(stub.chain, { store, limits, clientIp: "198.51.100.1" })),
      handleRelay(post(rotateOn(2)), context(stub.chain, { store, limits, clientIp: "198.51.100.2" })),
    ]);
    expect([a.status, b.status].sort()).toEqual([202, 429]);
    const worst = evmWindowCost({ gas: GAS_CEILING.rotate, maxFeePerGas: 201n * GWEI });
    expect(await spentOn(store, ledgerFor("chair", NOW, CHAIR))).toBe(worst);
    expect(await spentToday(store, NOW)).toBe(worst);
    expect(stub.sends).toHaveLength(1);
  });

  const hourly = async (store: SharedStore, boardId: number) => ({ valid: await store.get("rate:relay:valid"), board: await store.get(`rate:relay:board:${boardId}`), chair: await store.get(chairKey) });

  it("moves no counter for a relay the nonce check refuses 503 window_unavailable while a send of ours still waits for a block", async () => {
    const stub = stubChain({ landing: "pending" });
    const store = new MemoryStore();
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store, clientIp: "198.51.100.1" }))).status).toBe(202);
    const refused = await handleRelay(post(rotateOn(2)), context(stub.chain, { store, clientIp: "198.51.100.2" }));
    expect(refused.status).toBe(503);
    expect(await refused.json()).toEqual({ error: "window_unavailable" });
    expect(await hourly(store, 2)).toEqual({ valid: "1", board: null, chair: "1" });
    expect(stub.sends).toHaveLength(1);
  });

  it("moves no counter for a relay whose look-up of an earlier send at its nonce, inside the send and before the broadcast, outlasts the relay's time", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    let clock = 0;
    const lostHash: Hex = `0x${"ab".repeat(32)}`;
    const refused: RelayChain = {
      ...stub.chain,
      send: async (_tx, _deadline, beforeBroadcast) => {
        await beforeBroadcast?.({ kind: "evm", nonce: stub.nonce(), hash: lostHash });
        throw new Error(`EVM transaction ${lostHash} was refused and is not on chain.`);
      },
    };
    expect(await (await handleRelay(post(rotateOn(1)), context(refused, { store, clock: () => clock, clientIp: "198.51.100.1" }))).json()).toEqual({ error: "broadcast_failed" });
    const before = await hourly(store, 2);
    // The refused send's record at this nonce is looked up before it is replaced, and the chain answers only after the relay's 55 s.
    const slow: RelayChain = {
      ...stub.chain,
      txStatus: async (kind, hash) => (hash === lostHash ? ((clock = RELAY_DEADLINE_MS - 10), new Promise<never>(() => undefined)) : (stub.chain.txStatus?.(kind, hash) ?? "unknown")),
    };
    const late = await handleRelay(post(rotateOn(2)), context(slow, { store, clock: () => clock, clientIp: "198.51.100.2" }));
    expect(late.status).toBe(502);
    expect(await hourly(store, 2)).toEqual(before);
    expect(stub.sends).toHaveLength(0);
  });

  it("moves no counter for a relay whose nonce check waits it past the 45 s send cutoff, answered 503 out_of_time", async () => {
    const stub = stubChain({ landing: "pending" });
    const store = new MemoryStore();
    let clock = 0;
    const sleep = async (ms: number) => {
      clock += ms;
    };
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store, clock: () => clock, sleep, clientIp: "198.51.100.1" }))).status).toBe(202);
    // The fee quote comes back at 44.9 s; the nonce check then waits one poll for our earlier send to reach a block.
    const slow: RelayChain = {
      ...stub.chain,
      estimateGas: async (req) => ((clock = 44_900), stub.chain.estimateGas(req)),
      txStatus: async (kind, hash) => {
        const status = (await stub.chain.txStatus?.(kind, hash)) ?? "unknown";
        if (status === "pending") stub.mine();
        return status;
      },
    };
    clock = 0;
    const late = await handleRelay(post(rotateOn(2)), context(slow, { store, clock: () => clock, sleep, clientIp: "198.51.100.2" }));
    expect(clock).toBeGreaterThan(SEND_CUTOFF_MS);
    expect(late.status).toBe(503);
    expect(await late.json()).toEqual({ error: "out_of_time" });
    expect(await hourly(store, 2)).toEqual({ valid: "1", board: null, chair: "1" });
    expect(stub.sends).toHaveLength(1);
  });
});

/** A 32-byte value that differs per index, so each signed action is its own bytes. */
const ref = (i: number): Hex => `0x${(i + 1).toString(16).padStart(64, "0")}`;
const SECOND_CHAIR = "0x1111111111111111111111111111111111111111";

describe("handleRelay: the day's budget", () => {
  it("stops one chair at its own daily budget, long before the chairs' share is gone, and still serves a second chair", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses: number[] = [];
    for (let i = 0; i < 60; i++) {
      const body = { ...createBy(CHAIR), params: { ...createBy(CHAIR).params, boardRef: ref(i) } };
      statuses.push((await handleRelay(post(body), context(stub.chain, { store, clientIp: `198.51.100.${(i % 3) + 1}` }))).status);
    }
    const served = statuses.filter((status) => status === 202).length;
    expect(statuses.slice(served)).toEqual(new Array(60 - served).fill(429));
    expect((await handleRelay(post(createBy(SECOND_CHAIR)), context(stub.chain, { store, clientIp: "198.51.100.9" }))).status).toBe(202);

    const worst = evmWindowCost({ gas: GAS_CEILING.create, maxFeePerGas: 201n * GWEI });
    expect(served).toBe(Number(PER_CHAIR_DAILY_UQOR / worst));
    expect(await spentToday(store, NOW)).toBeLessThan(CHAIRS_DAILY_CEILING_UQOR);
    expect(logged.some((line) => line.includes("relay_refused") && line.includes("chair_daily"))).toBe(true);
  });

  it("settles the day's ledger down to each receipt's real fee, so ten adds cost what the chain charged", async () => {
    const fee = { gasUsed: 373_457n, effectiveGasPrice: 101n * GWEI };
    const stub = stubChain({ fee });
    const store = new MemoryStore();
    const add = CASES[1].body;
    for (let i = 0; i < 10; i++) {
      const body = { ...add, params: { ...add.params, epochAfter: String(4 + i) } };
      expect((await handleRelay(post(body), context(stub.chain, { store }))).status).toBe(202);
    }
    const real = weiToUqorCeil(fee.gasUsed * fee.effectiveGasPrice);
    expect(real).toBe(37_720n);
    expect(await spentToday(store, NOW)).toBe(10n * real);
  });
});

describe("handleRelay: the demo bot's share and the chairs' share", () => {
  // Hourly counters high enough that only the day's shares can stop these runs; per IP and per chair stay at their defaults.
  const roomy = { ...RELAY_LIMITS, perBoard: 10_000, total: 10_000 };
  const worstAt201 = (action: keyof typeof GAS_CEILING) => evmWindowCost({ gas: GAS_CEILING[action], maxFeePerGas: 201n * GWEI });
  /** The bot's two actions for guest number `join` at a full board: remove the oldest guest, then add the newcomer. */
  const demoAction = (i: number) => {
    const base = i % 2 === 0 ? CASES[2].body : CASES[1].body;
    return { ...base, boardId: "9", params: { ...base.params, epochAfter: String(10 + Math.floor(i / 2)) } };
  };
  /** How many of `costs`, taken in turn, fit under `ceiling` at their worst case. */
  const fitting = (ceiling: bigint, costOf: (i: number) => bigint): number => {
    let booked = 0n;
    let n = 0;
    while (booked + costOf(n) <= ceiling) booked += costOf(n++);
    return n;
  };
  const chairNumber = (k: number) => `0x${String(k + 1).repeat(40)}`;
  const publicCreate = (i: number) => {
    const body = createBy(chairNumber(Math.floor(i / 10)));
    return { ...body, params: { ...body.params, boardRef: ref(i) } };
  };

  it("stops the bot's relays, one per join and one per pass removal, at its own share, and a chair is still served after", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const served = fitting(DEMO_DAILY_CEILING_UQOR, (i) => worstAt201(i % 2 === 0 ? "remove" : "add"));
    const statuses: number[] = [];
    let last: unknown;
    for (let i = 0; i <= served; i++) {
      const response = await handleRelay(post(demoAction(i)), context(stub.chain, { store, limits: roomy, scope: "demo" }));
      statuses.push(response.status);
      last = await response.json();
    }
    expect(statuses).toEqual([...new Array(served).fill(202), 503]);
    expect(last).toEqual({ error: "daily_ceiling" });
    expect((await handleRelay(post(createBy(SECOND_CHAIR)), context(stub.chain, { store, limits: roomy, clientIp: "198.51.100.9" }))).status).toBe(202);
  });

  it("stops public chair relays at the chairs' share, whatever a body says about scope, and the bot is still served after", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const served = fitting(CHAIRS_DAILY_CEILING_UQOR, () => worstAt201("create"));
    const statuses: number[] = [];
    for (let i = 0; i <= served; i++) {
      statuses.push((await handleRelay(post(publicCreate(i)), context(stub.chain, { store, limits: roomy, clientIp: `198.51.100.${i + 1}` }))).status);
    }
    expect(statuses).toEqual([...new Array(served).fill(202), 503]);
    const claimsDemo = await handleRelay(post({ ...publicCreate(served + 1), scope: "demo" }), context(stub.chain, { store, limits: roomy, clientIp: "198.51.100.250" }));
    expect(await claimsDemo.json()).toEqual({ error: "daily_ceiling" });
    expect((await handleRelay(post(demoAction(0)), context(stub.chain, { store, limits: roomy, scope: "demo" }))).status).toBe(202);
  });
});

describe("handleRelay: the bytes posts keep for good", () => {
  const MIB = 1024 * 1024;
  const POST = CASES[4].body;
  /** A 25 MiB post, the per-document cap, of document number `i` on `boardId`. */
  const postOf = (i: number, boardId = "7") => ({ ...POST, boardId, params: { ...POST.params, docRef: ref(i), cipherSize: String(25 * MIB) } });
  const chairNo = (k: number) => getAddress(`0x${(k + 0x100).toString(16).padStart(40, "0")}`);
  /** Boards 100 and up each have their own chair, four boards to a chair, all at nonce 0. */
  const boards = (boardId: bigint): CallOutcome | undefined => {
    if (boardId < 100n) return undefined;
    const result = { chair: chairNo(Number(boardId - 100n) >> 2), boardRef: H1, epoch: 3n, nonce: 0n, memberCount: 2, documentCount: 1 };
    return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
  };

  it("relays a post only when its signed cipherSize is the document's verified size, refusing 422 size_mismatch before any counter moves, and books that size", async () => {
    const stub = stubChain({ board: boards });
    const { store, written } = recordingStore();
    await verified(store, H2, 25 * MIB);
    written.length = 0;
    const underDeclared = { ...postOf(0), params: { ...postOf(0).params, cipherSize: "1" } };
    const refused = await handleRelay(post(underDeclared), context(stub.chain, { store }));
    expect(refused.status).toBe(422);
    expect(await refused.json()).toEqual({ error: "size_mismatch" });
    expect(written).toEqual(["rate:relay:ip:203.0.113.7"]);
    expect(stub.sends).toHaveLength(0);

    expect((await handleRelay(post(postOf(0)), context(stub.chain, { store }))).status).toBe(202);
    expect(await spentOn(store, ledgerFor("posts", NOW))).toBe(BigInt(25 * MIB));
    expect(await spentOn(store, ledgerFor("chair_posts", NOW, CHAIR))).toBe(BigInt(25 * MIB));
  });

  it("refuses posts of a document never verified 422 document_unverified, moving no counter, so the chair's post bytes stay whole", async () => {
    const stub = stubChain({ board: boards });
    const { store, written } = recordingStore();
    const answers = new Set<string>();
    for (let i = 0; i < 4; i++) {
      const response = await handleRelay(post(postOf(i)), context(stub.chain, { store }));
      answers.add(`${response.status} ${JSON.stringify(await response.json())}`);
    }
    expect([...answers]).toEqual([`422 ${JSON.stringify({ error: "document_unverified" })}`]);
    expect(new Set(written)).toEqual(new Set(["rate:relay:ip:203.0.113.7"]));
    expect(await spentOn(store, ledgerFor("posts", NOW))).toBe(0n);
    expect(stub.sends).toHaveLength(0);

    await verified(store, H2, 25 * MIB);
    for (let i = 4; i < 8; i++) expect((await handleRelay(post(postOf(i)), context(stub.chain, { store, clientIp: "198.51.100.9" }))).status).toBe(202);
  });

  it("refuses a chair's post 429 post_bytes once its bytes posted today plus the new one pass 100 MiB, and still serves another chair", async () => {
    expect(PER_CHAIR_DAILY_POST_BYTES).toBe(BigInt(100 * MIB));
    const stub = stubChain({ board: boards });
    const store = new MemoryStore();
    await verified(store, H2, 25 * MIB);
    const statuses: number[] = [];
    let last: unknown;
    for (let i = 0; i < 5; i++) {
      const response = await handleRelay(post(postOf(i)), context(stub.chain, { store }));
      statuses.push(response.status);
      last = await response.json();
    }
    expect(statuses).toEqual([202, 202, 202, 202, 429]);
    expect(last).toEqual({ error: "post_bytes" });
    expect(stub.sends).toHaveLength(4);
    expect((await handleRelay(post(postOf(5, "100")), context(stub.chain, { store, clientIp: "198.51.100.9" }))).status).toBe(202);
  });

  it("refuses any post 429 post_bytes once the day's posts would pass 1 GiB, whichever chair sends it", async () => {
    expect(TOTAL_DAILY_POST_BYTES).toBe(BigInt(1024 * MIB));
    const stub = stubChain({ board: boards });
    const store = new MemoryStore();
    await verified(store, H2, 25 * MIB);
    const fits = Number(TOTAL_DAILY_POST_BYTES / BigInt(25 * MIB));
    const statuses: number[] = [];
    for (let i = 0; i <= fits; i++) {
      statuses.push((await handleRelay(post(postOf(i, String(100 + i))), context(stub.chain, { store, clientIp: `198.51.100.${i + 1}` }))).status);
    }
    expect(statuses).toEqual([...new Array(fits).fill(202), 429]);
    expect(logged.some((line) => line.includes("relay_refused") && line.includes("post_bytes"))).toBe(true);
  });

  it("gives a post's bytes back when nothing was broadcast", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    await verified(store, H2, 25 * MIB);
    const unsent: RelayChain = {
      ...stub.chain,
      send: async () => {
        throw new NotBroadcast("The EVM transaction could not be prepared: nothing was sent.");
      },
    };
    for (let i = 0; i < 4; i++) expect(await (await handleRelay(post(postOf(i)), context(unsent, { store }))).json()).toEqual({ error: "chain_unreachable" });
    for (let i = 4; i < 8; i++) expect((await handleRelay(post(postOf(i)), context(stub.chain, { store }))).status).toBe(202);
  });
});

describe("the demo bot's own hourly room", () => {
  /** The bot's removal (even steps) and addition (odd steps) on its own board 9, one join per two steps. */
  const demoStep = (i: number) => {
    const base = i % 2 === 0 ? CASES[2].body : CASES[1].body;
    return { ...base, boardId: "9", params: { ...base.params, epochAfter: String(10 + i) } };
  };

  it("never counts the bot's relays per board, per chair or in the valid total, so a whole join lands while the public total refuses", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    await store.incrWindow("rate:relay:valid", RELAY_LIMITS.windowSeconds, RELAY_LIMITS.total - 1);
    for (let i = 0; i < 2; i++) expect((await handleRelay(post(demoStep(i)), context(stub.chain, { store, scope: "demo" }))).status).toBe(202);
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store, clientIp: "198.51.100.1" }))).status).toBe(202);
    const refused = await handleRelay(post(rotateOn(2)), context(stub.chain, { store, clientIp: "198.51.100.2" }));
    expect(refused.status).toBe(429);
    expect(await refused.json()).toEqual({ error: "rate_limited" });
    for (let i = 2; i < 4; i++) expect((await handleRelay(post(demoStep(i)), context(stub.chain, { store, scope: "demo" }))).status).toBe(202);
    // The refused public relay is turned away at the full total without adding to it or to its chair.
    expect(await store.get("rate:relay:valid")).toBe(String(RELAY_LIMITS.total));
    expect(await store.get("rate:relay:board:9")).toBeNull();
    expect(await store.get(`rate:relay:chair:${CHAIR.toLowerCase()}`)).toBe("1");
  });

  it("reserves the hour's demo relays one at a time, refuses any other count and the 121st, and starts afresh the next hour", async () => {
    const store = new MemoryStore();
    expect(DEMO_RELAYS_PER_HOUR).toBe(120);
    // Every caller reserves one relay just before it makes it; a count of two is no call this code makes.
    expect(await reserveDemoRelays(store, NOW, 2 as 1)).toBe(false);
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR; n++) expect(await reserveDemoRelays(store, NOW, 1)).toBe(true);
    expect(await reserveDemoRelays(store, NOW + 59 * 60_000, 1)).toBe(false);
    expect(await reserveDemoRelays(store, NOW + 3_600_000, 1)).toBe(true);
  });

  it("gives two relays racing for the hour's last demo relay one yes and one no, and fails closed on a store error", async () => {
    const store = new MemoryStore();
    for (let n = 0; n < DEMO_RELAYS_PER_HOUR - 1; n++) await reserveDemoRelays(store, NOW, 1);
    const raced = await Promise.all([reserveDemoRelays(store, NOW, 1), reserveDemoRelays(store, NOW, 1)]);
    expect(raced.sort()).toEqual([false, true]);
    expect(await reserveDemoRelays(failingStore(), NOW, 1)).toBe(false);
  });
});

describe("handleRelay: rate limits", () => {
  const limits = { perIp: 2, perChair: 3, perBoard: 2, total: 5, rejected: 100, windowSeconds: 3600 };

  it("defaults to 20 per IP, 60 per chair, 60 per board, 600 valid and 3,000 rejected in total, per hour", () => {
    expect(RELAY_LIMITS).toEqual({ perIp: 20, perChair: 60, perBoard: 60, total: 600, rejected: 3000, windowSeconds: 3600 });
  });

  it("trips per IP", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses = [];
    for (let i = 1; i <= 3; i++) statuses.push((await handleRelay(post(rotateOn(i)), context(stub.chain, { store, limits }))).status);
    expect(statuses).toEqual([202, 202, 429]);
    expect(stub.sends).toHaveLength(2);
  });

  it("counts every /64 of one IPv6 /48 together at 4 times the per-IP limit, so the 81st relay from one /48 is refused", async () => {
    const stub = stubChain({ fee: { gasUsed: 400_000n, effectiveGasPrice: 101n * GWEI } });
    const store = new MemoryStore();
    const statuses: number[] = [];
    for (let i = 0; i <= 4 * RELAY_LIMITS.perIp; i++) {
      const chair = getAddress(`0x${(i + 1).toString(16).padStart(40, "0")}`);
      statuses.push((await handleRelay(post(createBy(chair)), context(stub.chain, { store, clientIp: `2001:db8:aaaa:${i.toString(16)}::1` }))).status);
    }
    expect(statuses).toEqual([...new Array(4 * RELAY_LIMITS.perIp).fill(202), 429]);
    expect(logged.some((line) => line.includes("rate_limited") && line.includes("per_net48"))).toBe(true);
    expect((await handleRelay(post(createBy(SECOND_CHAIR)), context(stub.chain, { store, clientIp: "2001:db8:aaab::1" }))).status).toBe(202);
  });

  it("trips per board, whatever IP sends", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses = [];
    for (let i = 1; i <= 3; i++) {
      const body = { ...rotateOn(7), params: { ...ROTATE.params, epochAfter: String(4 + i) } };
      statuses.push((await handleRelay(post(body), context(stub.chain, { store, limits, clientIp: `198.51.100.${i}` }))).status);
    }
    expect(statuses).toEqual([202, 202, 429]);
    expect(stub.sends).toHaveLength(2);
  });

  it("trips per chair, with the chair read from getBoard for board actions and taken from the parameters for create", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses = [];
    for (let i = 1; i <= 3; i++) statuses.push((await handleRelay(post(rotateOn(i)), context(stub.chain, { store, limits, clientIp: `198.51.100.${i}` }))).status);
    statuses.push((await handleRelay(post(createBy(CHAIR)), context(stub.chain, { store, limits, clientIp: "198.51.100.9" }))).status);
    expect(statuses).toEqual([202, 202, 202, 429]);
    expect(stub.sends).toHaveLength(3);
  });

  const ZERO_SIG = bytesToHex(new Uint8Array(4627));
  const badSignature = encodeErrorResult({ abi: boardRegistryAbi, errorName: "BadSignature", args: [CHAIR] });
  /** The registry's verdict on a zero signature, and acceptance of every other. */
  const refusesZeroSignature = (req: TxRequest): CallOutcome => (req.data.includes(ZERO_SIG.slice(2)) ? { ok: false, revertData: badSignature } : { ok: true, data: "0x" });
  const chairKey = `rate:relay:chair:${CHAIR.toLowerCase()}`;

  it("leaves a chair's and its board's budgets untouched after 60 junk creates naming it from three IPs, so its real action still lands", async () => {
    const stub = stubChain({ outcome: refusesZeroSignature });
    const store = new MemoryStore();
    const junk = { ...createBy(CHAIR), signature: ZERO_SIG };
    const statuses = new Set<number>();
    for (let i = 0; i < 60; i++) statuses.add((await handleRelay(post(junk), context(stub.chain, { store, clientIp: `198.51.100.${(i % 3) + 1}` }))).status);
    expect([...statuses]).toEqual([422]);
    expect(await store.get(chairKey)).toBeNull();
    expect(await store.get("rate:relay:board:7")).toBeNull();
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.4" }))).status).toBe(202);
    expect(stub.sends).toHaveLength(1);
  });

  it("leaves a board's budget untouched after 60 junk actions on it, so its chair's real action still lands", async () => {
    const stub = stubChain({ outcome: refusesZeroSignature });
    const store = new MemoryStore();
    const statuses = new Set<number>();
    for (let i = 0; i < 60; i++) statuses.add((await handleRelay(post({ ...ROTATE, signature: ZERO_SIG }), context(stub.chain, { store, clientIp: `198.51.100.${(i % 3) + 1}` }))).status);
    expect([...statuses]).toEqual([422]);
    expect(await store.get("rate:relay:board:7")).toBeNull();
    expect(await store.get(chairKey)).toBeNull();
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, clientIp: "198.51.100.4" }))).status).toBe(202);
  });

  it("counts a failed pre-flight against its IP and the rejected total only, and the rejected total never blocks a valid action", async () => {
    const stub = stubChain({ outcome: refusesZeroSignature });
    const store = new MemoryStore();
    const tight = { perIp: 100, perChair: 100, perBoard: 100, total: 100, rejected: 2, windowSeconds: 3600 };
    const junk = { ...ROTATE, signature: ZERO_SIG };
    const statuses = [];
    for (let i = 1; i <= 3; i++) statuses.push((await handleRelay(post(junk), context(stub.chain, { store, limits: tight, clientIp: `198.51.100.${i}` }))).status);
    expect(statuses).toEqual([422, 422, 429]);
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store, limits: tight, clientIp: "198.51.100.9" }))).status).toBe(202);
    expect(logged.some((line) => line.includes("relay_refused") && line.includes("rejected"))).toBe(true);

    const perIp = { ...tight, perIp: 2, rejected: 100 };
    const ipStore = new MemoryStore();
    for (let i = 0; i < 2; i++) expect((await handleRelay(post(junk), context(stub.chain, { store: ipStore, limits: perIp }))).status).toBe(422);
    expect((await handleRelay(post(ROTATE), context(stub.chain, { store: ipStore, limits: perIp }))).status).toBe(429);
  });

  it("trips in total across IPs, chairs and boards", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const chairs = ["0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", "0x3333333333333333333333333333333333333333", "0x4444444444444444444444444444444444444444", "0x5555555555555555555555555555555555555555", "0x6666666666666666666666666666666666666666"];
    const statuses = [];
    for (const [i, chair] of chairs.entries()) {
      statuses.push((await handleRelay(post(createBy(chair)), context(stub.chain, { store, limits, clientIp: `198.51.100.${i + 1}` }))).status);
    }
    expect(statuses).toEqual([202, 202, 202, 202, 202, 429]);
  });
});

describe("evmTxStatus", () => {
  const hash: Hex = `0x${"ab".repeat(32)}`;
  /** A node that holds a receipt with `status`, or a transaction only (in block `blockNumber`, or unmined), or nothing. */
  const node = (held: { status: "success" | "reverted" } | { blockNumber: bigint | null } | "nothing") =>
    ({
      getTransactionReceipt: async () => {
        if (held !== "nothing" && "status" in held) return { transactionHash: hash, status: held.status };
        throw new TransactionReceiptNotFoundError({ hash });
      },
      getTransaction: async () => {
        if (held !== "nothing" && "blockNumber" in held) return { hash, blockNumber: held.blockNumber };
        throw new TransactionNotFoundError({ hash });
      },
    }) as unknown as PublicClient;

  it("answers reverted for a transaction whose receipt says so, apart from one that landed, one pending and one the node does not know", async () => {
    expect(await evmTxStatus(node({ status: "reverted" }), hash)).toBe("reverted");
    expect(await evmTxStatus(node({ status: "success" }), hash)).toBe("landed");
    expect(await evmTxStatus(node({ blockNumber: null }), hash)).toBe("pending");
    expect(await evmTxStatus(node("nothing"), hash)).toBe("unknown");
  });
});

describe("relay configuration", () => {
  it("targets the registry recorded at deploy, with the code hash recorded there", () => {
    const deployed = JSON.parse(readFileSync(new URL("../../contracts/deployments/testnet.json", import.meta.url), "utf8")) as {
      BoardRegistry: { address: string; runtimeCodeHash: string };
    };
    expect(REGISTRY_ADDRESS).toBe(deployed.BoardRegistry.address);
    expect(getAddress(REGISTRY_ADDRESS)).toBe(REGISTRY_ADDRESS);
    expect(REGISTRY_CODE_KECCAK).toBe(deployed.BoardRegistry.runtimeCodeHash);
    expect(GAS_CEILING).toEqual({ create: 650_000n, add: 560_000n, remove: 450_000n, rotate: 450_000n, post: 500_000n, transfer: 450_000n });
  });
});
