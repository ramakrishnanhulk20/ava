// Not covered here: the live chain. Every chain answer comes from a stub, so whether the hybrid
// MsgSend really lands, what it really costs, and how the REST really reports a key or a balance are
// checked by scripts/live-demo-check.ts, which gets a fresh identity sponsored on testnet.
import { toHex, toQor1 } from "@ava/core";
import { describe, expect, it } from "vitest";
import { SPONSOR_AMOUNT_UQOR, SPONSOR_SEND_FEE_UQOR } from "../src/config.ts";
import { handleSponsor, sponsorDayKeys, sponsoredKey, type SponsorChain, type SponsorContext, type SponsorLimits } from "../src/sponsor.ts";
import { MemoryStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";

const NOW = Date.parse("2026-11-19T12:00:00Z");
const SPONSOR = { qor1: "qor1cwula4nakmmkqvns5r4q49gnwfgvd6ln5yrxuf", evm: "0xc3B9fEd67Db6f7603270a0eA0a95137250c6Ebf3" } as const;
const HASH = "AB".repeat(32);
const COST = SPONSOR_AMOUNT_UQOR + SPONSOR_SEND_FEE_UQOR;

const account = (n: number): Uint8Array => new Uint8Array(20).fill(n);
const GUEST = account(7);

interface StubOptions {
  hasKey?: boolean;
  hasCode?: boolean;
  balance?: bigint;
  down?: boolean;
  send?: (qor1: string) => Promise<string>;
}

function stubChain(options: StubOptions = {}) {
  const reads: string[] = [];
  const sends: string[] = [];
  const chain: SponsorChain = {
    hasPqKey: async (qor1) => {
      reads.push(qor1);
      if (options.down) throw new Error("REST is down");
      return options.hasKey ?? false;
    },
    balance: async (qor1) => {
      reads.push(qor1);
      if (options.down) throw new Error("REST is down");
      return options.balance ?? 0n;
    },
    hasCode: async (evm) => {
      reads.push(evm);
      if (options.down) throw new Error("EVM RPC is down");
      return options.hasCode ?? false;
    },
    send: async (qor1) => {
      sends.push(qor1);
      return options.send === undefined ? HASH : options.send(qor1);
    },
  };
  return { chain, reads, sends };
}

function context(chain: SponsorChain, over: Partial<SponsorContext> = {}): SponsorContext {
  return { clientIp: "203.0.113.9", now: NOW, store: new MemoryStore({ now: () => NOW }), sponsor: SPONSOR, chain, clock: () => 0, ...over };
}

function post(body: unknown, headers: Record<string, string> = { "content-type": "application/json" }): Request {
  return new Request("http://localhost/api/sponsor", { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
}

async function answer(response: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe("handleSponsor", () => {
  it("sends the fixed amount once to an eligible address and answers only the transaction hash", async () => {
    const stub = stubChain();
    const ctx = context(stub.chain);
    const result = await answer(await handleSponsor(post({ address: toHex(GUEST) }), ctx));
    expect(result).toEqual({ status: 202, body: { txHash: HASH } });
    expect(stub.sends).toEqual([toQor1(GUEST)]);
    const day = sponsorDayKeys(NOW);
    expect(await ctx.store.get(day.count)).toBe("1");
    expect(await ctx.store.get(day.spend)).toBe(COST.toString());
  });

  it("writes the once-per-address mark before the send starts", async () => {
    const store = new MemoryStore({ now: () => NOW });
    let markedAtSend: string | null = null;
    const stub = stubChain({
      send: async () => {
        markedAtSend = await store.get(sponsoredKey(GUEST));
        return HASH;
      },
    });
    expect((await handleSponsor(post({ address: toQor1(GUEST) }), context(stub.chain, { store }))).status).toBe(202);
    expect(markedAtSend).toBe(String(NOW));
  });

  it("refuses a malformed address before reading the chain", async () => {
    const stub = stubChain();
    const ctx = context(stub.chain, { limits: { perIp: 100, windowSeconds: 3600, perDay: 100, dailyCapUqor: 25_000_000n } });
    const lower = toHex(GUEST).toLowerCase();
    const bad = [
      { address: `${toQor1(GUEST).slice(0, -1)}x` },
      { address: `cosmos${toQor1(GUEST).slice(3)}` },
      { address: `0x${"aB".repeat(20)}` },
      { address: lower.slice(0, -2) },
      { address: toHex(account(0)) },
      { address: toHex(account(0xab)).toLowerCase() },
      { address: 42 },
      { address: lower, extra: "field" },
      { addr: lower },
    ];
    for (const body of bad) {
      const result = await answer(await handleSponsor(post(body), ctx));
      expect(result.status).toBe(400);
    }
    expect(stub.reads).toEqual([]);
    expect(stub.sends).toEqual([]);
  });

  it("refuses an address that already holds a post-quantum key, and marks nothing", async () => {
    const stub = stubChain({ hasKey: true });
    const ctx = context(stub.chain);
    expect(await answer(await handleSponsor(post({ address: toHex(GUEST) }), ctx))).toEqual({ status: 403, body: { error: "has_pq_key" } });
    expect(stub.sends).toEqual([]);
    expect(await ctx.store.get(sponsoredKey(GUEST))).toBeNull();
  });

  it("refuses an address that holds contract code, read from the EVM lane by its 0x form", async () => {
    const stub = stubChain({ hasCode: true });
    const ctx = context(stub.chain);
    expect(await answer(await handleSponsor(post({ address: toQor1(GUEST) }), ctx))).toEqual({ status: 403, body: { error: "contract_address" } });
    expect(stub.reads).toContain(toHex(GUEST));
    expect(stub.sends).toEqual([]);
    expect(await ctx.store.get(sponsoredKey(GUEST))).toBeNull();
  });

  it("refuses an address that holds any uqor at all, even one", async () => {
    for (const balance of [1n, SPONSOR_AMOUNT_UQOR - 1n, SPONSOR_AMOUNT_UQOR]) {
      const stub = stubChain({ balance });
      expect(await answer(await handleSponsor(post({ address: toHex(GUEST) }), context(stub.chain)))).toEqual({ status: 403, body: { error: "already_funded" } });
      expect(stub.sends).toEqual([]);
    }
  });

  it("answers 409 to a second request for one account in either form, even after the first send failed", async () => {
    const stub = stubChain({
      send: async () => {
        throw new Error("broadcast refused");
      },
    });
    const ctx = context(stub.chain);
    expect(await answer(await handleSponsor(post({ address: toHex(GUEST) }), ctx))).toEqual({ status: 502, body: { error: "send_failed" } });
    expect(await answer(await handleSponsor(post({ address: toQor1(GUEST) }), ctx))).toEqual({ status: 409, body: { error: "already_sponsored" } });
    expect(stub.sends).toEqual([toQor1(GUEST)]);
  });

  it("refuses past three requests per IP in the hour, while another IP is still served", async () => {
    const stub = stubChain();
    const store = new MemoryStore({ now: () => NOW });
    for (let n = 1; n <= 3; n++) expect((await handleSponsor(post({ address: toHex(account(n)) }), context(stub.chain, { store }))).status).toBe(202);
    const fourth = await handleSponsor(post({ address: toHex(account(4)) }), context(stub.chain, { store }));
    expect(fourth.status).toBe(429);
    expect(fourth.headers.get("retry-after")).toBe("3600");
    expect((await handleSponsor(post({ address: toHex(account(4)) }), context(stub.chain, { store, clientIp: "198.51.100.4" }))).status).toBe(202);
    expect(stub.sends).toHaveLength(4);
  });

  it("refuses past the day's send count without using up the address's one chance", async () => {
    const stub = stubChain();
    const store = new MemoryStore({ now: () => NOW });
    const limits: SponsorLimits = { perIp: 100, windowSeconds: 3600, perDay: 2, dailyCapUqor: 25_000_000n };
    for (let n = 1; n <= 2; n++) expect((await handleSponsor(post({ address: toHex(account(n)) }), context(stub.chain, { store, limits }))).status).toBe(202);
    const third = await handleSponsor(post({ address: toHex(account(3)) }), context(stub.chain, { store, limits }));
    expect(await answer(third)).toEqual({ status: 503, body: { error: "daily_limit" } });
    expect(third.headers.get("retry-after")).toBe(String(12 * 3600));
    expect(await store.get(sponsoredKey(account(3)))).toBeNull();
    expect(stub.sends).toHaveLength(2);
  });

  it("refuses past the day's QOR cap, counting amount and fee", async () => {
    const stub = stubChain();
    const store = new MemoryStore({ now: () => NOW });
    const limits: SponsorLimits = { perIp: 100, windowSeconds: 3600, perDay: 100, dailyCapUqor: 2n * COST - 1n };
    expect((await handleSponsor(post({ address: toHex(account(1)) }), context(stub.chain, { store, limits }))).status).toBe(202);
    expect(await answer(await handleSponsor(post({ address: toHex(account(2)) }), context(stub.chain, { store, limits })))).toEqual({ status: 503, body: { error: "daily_limit" } });
    expect(stub.sends).toHaveLength(1);
  });

  it("fails closed when a chain lookup or the store fails", async () => {
    const down = stubChain({ down: true });
    expect(await answer(await handleSponsor(post({ address: toHex(GUEST) }), context(down.chain)))).toEqual({ status: 502, body: { error: "chain_unreachable" } });
    expect(down.sends).toEqual([]);

    const healthy = stubChain();
    expect((await handleSponsor(post({ address: toHex(GUEST) }), context(healthy.chain, { store: failingStore() }))).status).toBe(429);
    expect(healthy.reads).toEqual([]);
    expect(healthy.sends).toEqual([]);
  });

  it("refuses another method, another content type and an oversized body", async () => {
    const stub = stubChain();
    const ctx = context(stub.chain, { limits: { perIp: 100, windowSeconds: 3600, perDay: 100, dailyCapUqor: 25_000_000n } });
    expect((await handleSponsor(new Request("http://localhost/api/sponsor"), ctx)).status).toBe(405);
    expect((await handleSponsor(post({ address: toHex(GUEST) }, { "content-type": "text/plain" }), ctx)).status).toBe(415);
    expect((await handleSponsor(post({ address: "x".repeat(300) }), ctx)).status).toBe(413);
    expect(stub.sends).toEqual([]);
  });
});
