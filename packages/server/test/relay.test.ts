// Not covered here: the live chain. Every chain answer comes from a stub that records what the relay
// handler asked of it, so whether the registry really accepts a signed action, and what the relayed
// transaction really costs, are checked by scripts/live-relay-check.ts. Signatures are not verified
// by the server at all: the registry checks them in the eth_call, and the stub stands in for it.
import { readFileSync } from "node:fs";
import { evmWindowCost, type EvmWindow } from "@qorechain/evm";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bytesToHex, encodeErrorResult, encodeFunctionData, encodeFunctionResult, getAddress, toFunctionSelector, type Hex } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import type { CallOutcome, EvmSend, FeeQuote, RelayChain, TxRequest, WindowRequest } from "../src/chain/types.ts";
import {
  DAILY_SPEND_CEILING_UQOR,
  GAS_CEILING,
  LOCK_TTL_SECONDS,
  MAX_FEE_PER_GAS,
  NATIVE_TX_BUDGET_MS,
  OPEN_CUTOFF_MS,
  REGISTRY_ADDRESS,
  REGISTRY_CODE_KECCAK,
  RELAY_DEADLINE_MS,
  RELAY_LIMITS,
  SEND_CUTOFF_MS,
  SEND_LOCK_WAIT_MS,
  WAIT_AFTER_WINDOW_MS,
  WINDOW_LOCK_WAIT_MS,
  WINDOW_OPEN_FEE_UQOR,
} from "../src/config.ts";
import { handleRelay, type RelayContext } from "../src/relay.ts";
import { LOCK_MAX_WAIT_MS, MemoryStore } from "../src/store.ts";
import { haltKey, recordWindowSend, spendKey, spentToday } from "../src/window.ts";

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
  const chain: RelayChain = {
    readWindow: async () => {
      events.push("window");
      return window;
    },
    openWindow: async (request) => {
      opens.push(request);
      options.onOpen?.();
      height += 100n;
      window = healthyWindow({ openedHeight: height, expiryHeight: height + 12_000n, maxValue: request.maxValue, remainingValue: request.maxValue });
      return { hash: "CD".repeat(32) };
    },
    closeWindow: async () => {
      closes += 1;
      window = healthyWindow({ found: false, live: false, allowedTargets: [] });
      return { hash: "EF".repeat(32) };
    },
    call: async (req) => {
      if (req.data.startsWith(GET_BOARD)) {
        const boardId = BigInt(`0x${req.data.slice(10)}`);
        const answer = options.board?.(boardId);
        if (answer !== undefined) return answer;
        const result = { chair: CHAIR, boardRef: H1, epoch: 3n, nonce: 9n, memberCount: 2, documentCount: 1 };
        return { ok: true, data: encodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", result }) };
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
    send: async (tx) => {
      events.push("send:start");
      sends.push(tx);
      // The chain charges the window gas limit times fee cap for every transaction it admits.
      const cost = evmWindowCost({ gas: tx.gas, maxFeePerGas: tx.maxFeePerGas });
      window = { ...window, remainingTxs: window.remainingTxs - 1n, usedTxs: window.usedTxs + 1n, remainingValue: window.remainingValue - cost, usedValue: window.usedValue + cost };
      await new Promise((resolve) => setTimeout(resolve, options.sendDelayMs ?? 0));
      events.push("send:end");
      count += 1;
      return `0x${count.toString(16).padStart(64, "0")}`;
    },
  };
  const touched = () => calls.length + estimates.length + sends.length + opens.length + events.length + closes;
  /** Spending through the window that never went through our relay: what a leaked classical key does. */
  const foreign = (txs: bigint, value: bigint) => {
    window = { ...window, remainingTxs: window.remainingTxs - txs, usedTxs: window.usedTxs + txs, remainingValue: window.remainingValue - value, usedValue: window.usedValue + value };
  };
  return { chain, calls, estimates, sends, opens, events, touched, closes: () => closes, foreign };
}

/** Our own earlier sends through a test window that already shows `n` transactions used. */
async function ourSends(store: MemoryStore, n: number, openedHeight = 1_000n): Promise<MemoryStore> {
  for (let i = 0; i < n; i++) await recordWindowSend(store, openedHeight, evmWindowCost({ gas: 650_000n, maxFeePerGas: 250n * GWEI }));
  return store;
}

function context(chain: RelayChain, over: Partial<RelayContext> = {}): RelayContext {
  return { clientIp: "203.0.113.7", now: NOW, store: new MemoryStore(), relayer: RELAYER, chain, sleep: async () => undefined, ...over };
}

function post(body: unknown): Request {
  return new Request("http://app.local/api/relay", {
    method: "POST",
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { "content-type": "application/json" },
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
      const response = await handleRelay(post(c.body), context(stub.chain));
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
    expect(await (await handleRelay(post(ROTATE), context(cold, { store }))).json()).toEqual({ error: "fee_above_ceiling" });
    expect(stub.sends).toHaveLength(1);
  });
});

describe("handleRelay: refusals before any chain call", () => {
  it("refuses a body over 16 KB, another method and another content type", async () => {
    const stub = stubChain();
    const big = { ...ROTATE, padding: "x".repeat(16_384) };
    expect((await handleRelay(post(big), context(stub.chain))).status).toBe(413);
    expect((await handleRelay(new Request("http://app.local/api/relay"), context(stub.chain))).status).toBe(405);
    const text = new Request("http://app.local/api/relay", { method: "POST", body: JSON.stringify(ROTATE), headers: { "content-type": "text/plain" } });
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

  it("keeps the halt for the rest of the UTC day, opening nothing, and lifts it the next day", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    expect((await handleRelay(post(rotateOn(1)), context(stub.chain, { store }))).status).toBe(202);
    stub.foreign(1n, 0n);
    expect((await handleRelay(post(rotateOn(2)), context(stub.chain, { store }))).status).toBe(503);

    const later = await handleRelay(post(rotateOn(3)), context(stub.chain, { store, now: Date.parse("2026-11-17T23:59:59Z") }));
    expect(await later.json()).toEqual({ error: "halted" });
    expect(stub.opens).toHaveLength(0);
    expect(stub.sends).toHaveLength(1);

    const nextDay = await handleRelay(post(rotateOn(4)), context(stub.chain, { store, now: Date.parse("2026-11-18T00:00:01Z") }));
    expect(nextDay.status).toBe(202);
    expect(stub.opens).toHaveLength(1);
    expect(stub.sends).toHaveLength(2);
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

  it("trips per board, whatever IP sends", async () => {
    const stub = stubChain();
    const store = new MemoryStore();
    const statuses = [];
    for (let i = 1; i <= 3; i++) statuses.push((await handleRelay(post(rotateOn(7)), context(stub.chain, { store, limits, clientIp: `198.51.100.${i}` }))).status);
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
