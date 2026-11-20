// Not covered here: that the hosting layer reports the real client IP. These functions trust the
// clientIp they are given; the handler tests show that request headers never change it.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { UPLOAD_LIMITS } from "../src/blob.ts";
import { DEMO_CHALLENGE_LIMITS } from "../src/config.ts";
import { DOCUMENT_TOKEN_LIMITS, DOCUMENT_VERIFY_LIMITS } from "../src/docupload.ts";
import { clientKey, countClient, hasBudget, limit, spendBudget } from "../src/ratelimit.ts";
import { MemoryStore } from "../src/store.ts";
import { failingStore } from "./fixtures.ts";

const RULE = { scope: "proxy", clientIp: "203.0.113.7", perIp: 3, total: 100, windowSeconds: 60 };

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

describe("limit", () => {
  it("trips one IP at perIp and leaves other IPs alone", async () => {
    const store = new MemoryStore();
    for (let i = 0; i < 3; i++) expect(await limit(store, RULE)).toEqual({ ok: true, retryAfter: 0 });
    expect(await limit(store, RULE)).toEqual({ ok: false, retryAfter: 60 });
    expect((await limit(store, { ...RULE, clientIp: "203.0.113.8" })).ok).toBe(true);
  });

  it("trips everyone at total, and per-IP refusals do not use up the total", async () => {
    const store = new MemoryStore();
    const rule = { ...RULE, perIp: 1, total: 3 };
    for (let i = 0; i < 10; i++) await limit(store, { ...rule, clientIp: "198.51.100.1" });
    expect((await limit(store, { ...rule, clientIp: "198.51.100.2" })).ok).toBe(true);
    expect((await limit(store, { ...rule, clientIp: "198.51.100.3" })).ok).toBe(true);
    expect(await limit(store, { ...rule, clientIp: "198.51.100.4" })).toEqual({ ok: false, retryAfter: 60 });
  });

  it("fails closed when the store errors, the IP is not an IP, or the rule is bad", async () => {
    expect(await limit(failingStore(), RULE)).toEqual({ ok: false, retryAfter: 60 });
    const store = new MemoryStore();
    for (const clientIp of ["", "unknown", "203.0.113.7, 10.0.0.1", "fe80::1%eth0"]) {
      expect((await limit(store, { ...RULE, clientIp })).ok).toBe(false);
    }
    expect((await limit(store, { ...RULE, perIp: 0 })).ok).toBe(false);
    expect((await limit(store, { ...RULE, scope: "Proxy:all" })).ok).toBe(false);
  });
});

describe("IPv6 prefixes", () => {
  it("count all 65,536 /64s of one /48 together, refused after 4 x perIp, and leave other /48s alone", async () => {
    const store = new MemoryStore();
    const rule = { ...RULE, perIp: 3, total: 1_000_000 };
    let served = 0;
    for (let i = 0; i < 65_536; i++) {
      if ((await limit(store, { ...rule, clientIp: `2001:db8:aaaa:${i.toString(16)}::1` })).ok) served += 1;
    }
    expect(served).toBe(4 * rule.perIp);
    expect((await limit(store, { ...rule, clientIp: "2001:db8:aaab::1" })).ok).toBe(true);
  });

  it("are not spent by requests one /64 is already refused for", async () => {
    const store = new MemoryStore();
    const rule = { ...RULE, perIp: 3, total: 1_000_000 };
    for (let i = 0; i < 50; i++) await limit(store, { ...rule, clientIp: "2001:db8:bbbb:1::1" });
    let served = 0;
    for (let i = 2; i < 100; i++) if ((await limit(store, { ...rule, clientIp: `2001:db8:bbbb:${i}::1` })).ok) served += 1;
    expect(served).toBe(4 * rule.perIp - rule.perIp);
  });

  it("leave IPv4 unchanged: every address of one /24, and an IPv4-mapped one, gets its own full perIp", async () => {
    const store = new MemoryStore();
    const rule = { ...RULE, perIp: 3, total: 1_000_000 };
    let served = 0;
    for (let host = 0; host < 256; host++) {
      for (let i = 0; i < 4; i++) if ((await limit(store, { ...rule, clientIp: `198.51.100.${host}` })).ok) served += 1;
    }
    expect(served).toBe(256 * rule.perIp);
    const mapped = await Promise.all([1, 2, 3, 4].map(() => limit(store, { ...rule, clientIp: "::ffff:203.0.113.20" })));
    expect(mapped.map((verdict) => verdict.ok)).toEqual([true, true, true, false]);
  });
});

describe("countClient", () => {
  it("counts per IP under limit's own keys and per IPv6 /48 at 4 x perIp, with no total, and fails closed", async () => {
    const store = new MemoryStore();
    const rule = { scope: "relay", perIp: 2, windowSeconds: 60 };
    for (let i = 0; i < 2; i++) expect(await countClient(store, { ...rule, clientIp: "203.0.113.7" })).toEqual({ ok: true, retryAfter: 0 });
    expect(await countClient(store, { ...rule, clientIp: "203.0.113.7" })).toEqual({ ok: false, retryAfter: 60, refusedBy: "per_ip" });
    expect(await store.get("rate:relay:ip:203.0.113.7")).toBe("3");
    let served = 0;
    for (let i = 0; i < 100; i++) if ((await countClient(store, { ...rule, clientIp: `2001:db8:cccc:${i.toString(16)}::1` })).ok) served += 1;
    expect(served).toBe(4 * rule.perIp);
    expect(await store.get("rate:relay:all")).toBeNull();
    expect((await countClient(store, { ...rule, clientIp: "unknown" })).refusedBy).toBe("bad_client_ip");
    expect(await countClient(failingStore(), { ...rule, clientIp: "203.0.113.7" })).toEqual({ ok: false, retryAfter: 60, refusedBy: "store_error" });
  });
});

describe("clientKey", () => {
  it("counts IPv6 per /64, every spelling of one address alike, and IPv4-mapped as IPv4", () => {
    expect(clientKey("2001:db8:1:2:aaaa::1")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:DB8:1:2:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(clientKey("2001:0db8:0001:0002::9")).toBe("2001:db8:1:2::/64");
    expect(clientKey("::ffff:203.0.113.7")).toBe("203.0.113.7");
    expect(clientKey("01.2.3.4")).toBeUndefined();
  });
});

describe("byte budget", () => {
  it("refuses once the spend passes max, and refuses before spending once it is used up", async () => {
    const store = new MemoryStore();
    const rule = { scope: "upload", clientIp: "203.0.113.7", max: 1_000, windowSeconds: 3600 };
    expect((await hasBudget(store, rule)).ok).toBe(true);
    expect((await spendBudget(store, rule, 600)).ok).toBe(true);
    expect((await spendBudget(store, rule, 400)).ok).toBe(true);
    expect((await hasBudget(store, rule)).ok).toBe(false);
    expect(await spendBudget(store, rule, 1)).toEqual({ ok: false, retryAfter: 3600 });
    expect((await hasBudget(store, { ...rule, clientIp: "203.0.113.8" })).ok).toBe(true);
  });

  it("counts every /64 of one IPv6 /48 together at 4 x max, so 10 /64s get at most 4 x one IP's document tokens or upload bytes an hour", async () => {
    const rules = [
      { scope: "doctoken", max: DOCUMENT_TOKEN_LIMITS.tokensPerIp, windowSeconds: DOCUMENT_TOKEN_LIMITS.windowSeconds, unit: 1 },
      { scope: "upload", max: UPLOAD_LIMITS.bytesPerIp, windowSeconds: UPLOAD_LIMITS.windowSeconds, unit: UPLOAD_LIMITS.bytesPerIp / 20 },
    ];
    for (const { unit, ...rule } of rules) {
      const store = new MemoryStore();
      let granted = 0;
      for (let net = 0; net < 10; net++) {
        for (let i = 0; i < rule.max / unit; i++) if ((await spendBudget(store, { ...rule, clientIp: `2001:db8:dddd:${net.toString(16)}::1` }, unit)).ok) granted += unit;
      }
      expect({ scope: rule.scope, granted }).toEqual({ scope: rule.scope, granted: 4 * rule.max });
      expect((await hasBudget(store, { ...rule, clientIp: "2001:db8:dddd:ff::1" })).ok).toBe(false);
      expect((await hasBudget(store, { ...rule, clientIp: "2001:db8:eeee::1" })).ok).toBe(true);
      expect((await spendBudget(store, { ...rule, clientIp: "2001:db8:eeee::1" }, unit)).ok).toBe(true);
    }
  });

  it("fails closed when the store errors", async () => {
    const rule = { scope: "upload", clientIp: "203.0.113.7", max: 1_000, windowSeconds: 3600 };
    expect((await hasBudget(failingStore(), rule)).ok).toBe(false);
    expect((await spendBudget(failingStore(), rule, 1)).ok).toBe(false);
  });
});

describe("unauthenticated totals", () => {
  it("take at least 50 client addresses to reach on the envelope upload, the document token and verify, and the demo challenge", () => {
    const rules = { upload: UPLOAD_LIMITS, doctoken: DOCUMENT_TOKEN_LIMITS, docverify: DOCUMENT_VERIFY_LIMITS, challenge: DEMO_CHALLENGE_LIMITS };
    for (const [name, rule] of Object.entries(rules)) expect({ name, ips: rule.total / rule.perIp }).toEqual({ name, ips: expect.toSatisfy((n: number) => n >= 50) });
  });
});
