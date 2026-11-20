// Not covered here: the real QoreChain REST. Every upstream answer comes from a stub fetch, so the
// shapes of real responses and the upstream's own per-IP limit are checked in the live runs. What
// the undici fetch does with redirect "manual" is Node's promise; the stub returns a raw 302.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  PROXY_BODY_CAP,
  PROXY_RESPONSE_CAP,
  PROXY_TIMEOUT_MS,
  handleChainGet,
  handleChainPost,
  upstreamUrl,
  type ProxyContext,
} from "../src/proxy.ts";
import { MemoryStore } from "../src/store.ts";
import { APP_HEADERS, CROSS_SITE_HEADERS, failingStore, stalledBody } from "./fixtures.ts";

const UPSTREAM = "https://api-testnet.qore.host";
const MOUNT = "/api/chain";
// One account in both forms, as the testnet reported them for the deployer on 16 Nov.
const QOR1 = "qor13gmaduk6r79q0utnt3tgcfs3ypwe86tn8292fq";
const EIP55 = "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973";
const HASH = "ab12".repeat(16);
const TX_BYTES = Buffer.from("a signed transaction").toString("base64");

interface Sent {
  url: URL;
  init: RequestInit;
}

function stubFetch(respond: (init: RequestInit) => Response | Promise<Response> = () => Response.json({ height: "1" })) {
  const sent: Sent[] = [];
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    sent.push({ url: input as URL, init: init ?? {} });
    return respond(init ?? {});
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, sent, calls: () => fetch.mock.calls.length };
}

function context(fetch: typeof globalThis.fetch, extra: Partial<ProxyContext> = {}): ProxyContext {
  return { clientIp: "203.0.113.7", now: Date.now(), store: new MemoryStore(), upstream: UPSTREAM, mount: MOUNT, fetch, ...extra };
}

/** Requests as our app sends them: every one carries the app's own headers. */
function get(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`http://app.local${MOUNT}${path}`, { headers: { ...APP_HEADERS, ...headers } });
}

function post(path: string, body: string, contentType = "application/json"): Request {
  return new Request(`http://app.local${MOUNT}${path}`, { method: "POST", body, headers: { ...APP_HEADERS, "content-type": contentType } });
}

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("handleChainGet", () => {
  it("forwards every allowed route to the URL object it checked, with parameters re-encoded", async () => {
    const cases: [string, string][] = [
      [`/cosmos/auth/v1beta1/accounts/${EIP55}`, `/cosmos/auth/v1beta1/accounts/${QOR1}`],
      [`/cosmos/bank/v1beta1/balances/${QOR1}`, `/cosmos/bank/v1beta1/balances/${QOR1}`],
      [`/qorechain/pqc/v1/account/${EIP55}`, `/qorechain/pqc/v1/account/${QOR1}`],
      [`/qorechain/pqc/v1/evm_window/${QOR1}`, `/qorechain/pqc/v1/evm_window/${QOR1}`],
      [`/cosmos/tx/v1beta1/txs/${HASH}`, `/cosmos/tx/v1beta1/txs/${HASH.toUpperCase()}`],
      ["/cosmos/base/tendermint/v1beta1/blocks/latest", "/cosmos/base/tendermint/v1beta1/blocks/latest"],
      ["/cosmos/base/tendermint/v1beta1/node_info", "/cosmos/base/tendermint/v1beta1/node_info"],
      ["/qorechain/pqc/v1/protocol_features", "/qorechain/pqc/v1/protocol_features"],
      ["/cosmos/upgrade/v1beta1/applied_plan/v3.2.0", "/cosmos/upgrade/v1beta1/applied_plan/v3.2.0"],
      ["/cosmos/upgrade/v1beta1/applied_plan/v3.1.98-rc", "/cosmos/upgrade/v1beta1/applied_plan/v3.1.98-rc"],
    ];
    const upstream = stubFetch(() =>
      Response.json({ height: "1" }, { headers: { "access-control-allow-origin": "*", "x-upstream": "internal" } }),
    );
    const ctx = context(upstream.fetch);
    for (const [path, expected] of cases) {
      const response = await handleChainGet(get(path), ctx);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ height: "1" });
      expect(response.headers.get("content-type")).toBe("application/json");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("access-control-allow-origin")).toBeNull();
      expect(response.headers.get("x-upstream")).toBeNull();
      const last = upstream.sent.at(-1)!;
      expect(last.url).toBeInstanceOf(URL);
      expect(last.url.href).toBe(UPSTREAM + expected);
      expect(last.init.redirect).toBe("manual");
      expect(last.init.method).toBe("GET");
    }
    expect(upstream.calls()).toBe(cases.length);
  });

  it("refuses host tricks, dot segments, encoded slashes, unknown routes, query strings and bad parameters unsent", async () => {
    const badChecksum = QOR1.slice(0, -1) + (QOR1.endsWith("q") ? "p" : "q");
    const flippedCase = EIP55.slice(0, 3) + EIP55[3]!.toLowerCase() + EIP55.slice(4);
    const cases: [string, number][] = [
      ["//evil.example/", 404],
      ["/https://evil.example/x", 404],
      ["/cosmos/../x", 404],
      ["/../../evil", 404],
      ["/cosmos/bank/v1beta1/balances/..%2f..%2fx", 400],
      ["/cosmos/bank/v1beta1/balances%2f" + QOR1, 404],
      ["/cosmos%252fbank/v1beta1/balances/" + QOR1, 404],
      ["/cosmos/bank/v1beta1/balances/%252f", 400],
      ["/cosmos/staking/v1beta1/validators", 404],
      [`/cosmos/bank/v1beta1/balances/${QOR1}/`, 404],
      [`/cosmos/bank/v1beta1/balances/${QOR1}?pagination.limit=1`, 400],
      ["/cosmos/base/tendermint/v1beta1/node_info?", 400],
      [`/cosmos/bank/v1beta1/balances/${badChecksum}`, 400],
      [`/cosmos/auth/v1beta1/accounts/${flippedCase}`, 400],
      [`/qorechain/pqc/v1/account/${EIP55.toLowerCase()}`, 400],
      ["/cosmos/upgrade/v1beta1/applied_plan/V3.2.0", 400],
      ["/cosmos/upgrade/v1beta1/applied_plan/v3.2.0_x", 400],
      ["/cosmos/upgrade/v1beta1/applied_plan/v3%2e2", 400],
      [`/cosmos/upgrade/v1beta1/applied_plan/${"v".repeat(33)}`, 400],
      ["/cosmos/upgrade/v1beta1/applied_plan/", 400],
      ["/cosmos/upgrade/v1beta1/applied_plan/..", 404],
      ["/qorechain/pqc/v1/protocol_features/x", 404],
      [`/cosmos/tx/v1beta1/txs/${HASH.slice(1)}`, 400],
      [`/cosmos/tx/v1beta1/txs/0x${HASH.slice(2)}`, 400],
    ];
    const upstream = stubFetch();
    const ctx = context(upstream.fetch);
    for (const [path, status] of cases) {
      const response = await handleChainGet(get(path), ctx);
      expect({ path, status: response.status }).toEqual({ path, status });
      expect(response.headers.get("content-type")).toBe("application/json");
    }
    expect(upstream.calls()).toBe(0);
  });

  it("builds no URL off the upstream origin, whatever path reaches it", () => {
    const hostTricks = ["//evil.example/", "https://evil.example/x", "\\\\evil.example/x", "/\\evil.example/x", "\\/evil.example/x"];
    for (const path of [...hostTricks, "/cosmos/../x", "/a?b=1", "/a#b"]) {
      expect(upstreamUrl(path, UPSTREAM)).toBeUndefined();
    }
    expect(upstreamUrl("/cosmos/base/tendermint/v1beta1/node_info", UPSTREAM)?.href).toBe(
      `${UPSTREAM}/cosmos/base/tendermint/v1beta1/node_info`,
    );
  });

  it("refuses an upstream redirect without following it", async () => {
    const upstream = stubFetch(() => new Response(null, { status: 302, headers: { location: "https://evil.example/" } }));
    const response = await handleChainGet(get("/cosmos/base/tendermint/v1beta1/node_info"), context(upstream.fetch));
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({ error: "upstream_redirect" });
    expect(response.headers.get("location")).toBeNull();
    expect(upstream.calls()).toBe(1);
  });

  it("refuses an upstream body over 1 MiB and a body that is not JSON", async () => {
    const big = stubFetch(() => new Response(`{"a":"${"x".repeat(PROXY_RESPONSE_CAP)}"}`));
    const tooBig = await handleChainGet(get("/cosmos/base/tendermint/v1beta1/node_info"), context(big.fetch));
    expect(tooBig.status).toBe(502);
    expect(await tooBig.json()).toEqual({ error: "upstream_too_large" });
    for (const body of ["<html><script>alert(1)</script></html>", '"just a string"', "\xff\xfe"]) {
      const html = stubFetch(() => new Response(body, { headers: { "content-type": "application/json" } }));
      const response = await handleChainGet(get("/cosmos/base/tendermint/v1beta1/node_info"), context(html.fetch));
      expect(response.status).toBe(502);
      expect(await response.json()).toEqual({ error: "upstream_not_json" });
    }
  });

  it("passes an upstream 4xx through as JSON and turns a 5xx into 502", async () => {
    const notFound = stubFetch(() => Response.json({ code: 5, message: "not found" }, { status: 404 }));
    const response = await handleChainGet(get(`/cosmos/auth/v1beta1/accounts/${QOR1}`), context(notFound.fetch));
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ code: 5, message: "not found" });
    const broken = stubFetch(() => Response.json({ message: "panic" }, { status: 500 }));
    const fault = await handleChainGet(get(`/cosmos/auth/v1beta1/accounts/${QOR1}`), context(broken.fetch));
    expect(fault.status).toBe(502);
    expect(await fault.json()).toEqual({ error: "upstream_error" });
  });

  it("gives up after 8 seconds with 504", async () => {
    vi.useFakeTimers();
    const hanging = stubFetch(
      (init) =>
        new Promise<Response>((_, reject) => {
          init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        }),
    );
    const pending = handleChainGet(get("/cosmos/base/tendermint/v1beta1/node_info"), context(hanging.fetch));
    let settled = false;
    void pending.then(() => (settled = true));
    // The timer is set just before the upstream call, so once the stub is called the clock may move.
    for (let i = 0; i < 1_000 && hanging.calls() === 0; i++) await Promise.resolve();
    expect(hanging.calls()).toBe(1);
    await vi.advanceTimersByTimeAsync(PROXY_TIMEOUT_MS - 1);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const response = await pending;
    expect(response.status).toBe(504);
    expect(await response.json()).toEqual({ error: "upstream_timeout" });
  });

  it("forwards no request header: Cookie, Authorization and X-Forwarded-For stay behind", async () => {
    const upstream = stubFetch();
    const request = get("/cosmos/base/tendermint/v1beta1/node_info", {
      cookie: "session=abc",
      authorization: "Bearer stolen",
      "x-forwarded-for": "10.0.0.1",
      "x-real-ip": "10.0.0.2",
    });
    expect((await handleChainGet(request, context(upstream.fetch))).status).toBe(200);
    const headers = new Headers(upstream.sent[0]?.init.headers);
    expect([...headers.keys()].sort()).toEqual(["accept", "user-agent"]);
  });

  it("rate limits per IP and in total, ignores X-Forwarded-For, and fails closed on a store error", async () => {
    const upstream = stubFetch();
    const ctx = context(upstream.fetch, { limits: { perIp: 2, total: 3, windowSeconds: 60 } });
    const path = "/cosmos/base/tendermint/v1beta1/node_info";
    const statuses: number[] = [];
    for (const forwarded of ["198.51.100.1", "198.51.100.2", "198.51.100.3"]) {
      statuses.push((await handleChainGet(get(path, { "x-forwarded-for": forwarded }), ctx)).status);
    }
    expect(statuses).toEqual([200, 200, 429]);
    expect((await handleChainGet(get(path), { ...ctx, clientIp: "203.0.113.8" })).status).toBe(200);
    const overTotal = await handleChainGet(get(path), { ...ctx, clientIp: "203.0.113.9" });
    expect(overTotal.status).toBe(429);
    expect(overTotal.headers.get("retry-after")).toBe("60");
    expect(upstream.calls()).toBe(3);
    const down = await handleChainGet(get(path), { ...ctx, store: failingStore() });
    expect(down.status).toBe(429);
    expect(upstream.calls()).toBe(3);
  });
});

describe("handleChainPost", () => {
  it("passes simulate and broadcast upstream as re-serialised JSON", async () => {
    const upstream = stubFetch(() => Response.json({ tx_response: { code: 0 } }));
    const ctx = context(upstream.fetch);
    const simulate = await handleChainPost(post("/cosmos/tx/v1beta1/simulate", `{ "tx_bytes" : "${TX_BYTES}" }`), ctx);
    expect(simulate.status).toBe(200);
    const broadcast = await handleChainPost(
      post("/cosmos/tx/v1beta1/txs", JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_SYNC" }), "application/json; charset=utf-8"),
      ctx,
    );
    expect(broadcast.status).toBe(200);
    expect(await broadcast.json()).toEqual({ tx_response: { code: 0 } });
    expect(upstream.sent.map((s) => [s.url.href, s.init.method, s.init.body])).toEqual([
      [`${UPSTREAM}/cosmos/tx/v1beta1/simulate`, "POST", JSON.stringify({ tx_bytes: TX_BYTES })],
      [`${UPSTREAM}/cosmos/tx/v1beta1/txs`, "POST", JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_SYNC" })],
    ]);
    const headers = new Headers(upstream.sent[1]?.init.headers);
    expect([...headers.keys()].sort()).toEqual(["accept", "content-type", "user-agent"]);
  });

  it("refuses other paths, oversized and non-JSON bodies, and any mode but SYNC, unsent", async () => {
    const upstream = stubFetch();
    const ctx = context(upstream.fetch);
    const sync = (extra: object = {}) => JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_SYNC", ...extra });
    const cases: [Request, number][] = [
      [post("/cosmos/tx/v1beta1/txs/extra", sync()), 404],
      [post(`/cosmos/bank/v1beta1/balances/${QOR1}`, sync()), 404],
      [post("//evil.example/cosmos/tx/v1beta1/txs", sync()), 404],
      [post("/cosmos/tx/v1beta1/txs?mode=x", sync()), 400],
      [post("/cosmos/tx/v1beta1/txs", JSON.stringify({ tx_bytes: "A".repeat(PROXY_BODY_CAP), mode: "BROADCAST_MODE_SYNC" })), 413],
      [post("/cosmos/tx/v1beta1/txs", "tx_bytes=abc"), 400],
      [post("/cosmos/tx/v1beta1/txs", sync(), "text/plain"), 415],
      [post("/cosmos/tx/v1beta1/txs", JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_ASYNC" })), 400],
      [post("/cosmos/tx/v1beta1/txs", JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_BLOCK" })), 400],
      [post("/cosmos/tx/v1beta1/txs", JSON.stringify({ tx_bytes: TX_BYTES })), 400],
      [post("/cosmos/tx/v1beta1/txs", sync({ extra: 1 })), 400],
      [post("/cosmos/tx/v1beta1/simulate", JSON.stringify({ tx_bytes: "not base64!" })), 400],
      [new Request(`http://app.local${MOUNT}/cosmos/tx/v1beta1/txs`, { headers: APP_HEADERS }), 405],
    ];
    for (const [request, status] of cases) {
      expect({ url: request.url, status: (await handleChainPost(request, ctx)).status }).toEqual({ url: request.url, status });
    }
    expect((await handleChainGet(post("/cosmos/tx/v1beta1/txs", sync()), ctx)).status).toBe(405);
    expect(upstream.calls()).toBe(0);
  });
});

describe("request bodies", () => {
  it("that have not ended after 20 seconds are refused with 408, unsent", async () => {
    vi.useFakeTimers();
    const upstream = stubFetch();
    const body = stalledBody();
    const request = new Request(`http://app.local${MOUNT}/cosmos/tx/v1beta1/txs`, {
      method: "POST",
      headers: { ...APP_HEADERS, "content-type": "application/json" },
      body: body.stream,
      duplex: "half",
    } as RequestInit);
    const pending = handleChainPost(request, context(upstream.fetch));
    let settled = false;
    void pending.then(() => (settled = true));
    for (let i = 0; i < 1_000 && !body.waiting(); i++) await Promise.resolve();
    expect(body.waiting()).toBe(true);
    await vi.advanceTimersByTimeAsync(19_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const response = await pending;
    expect(response.status).toBe(408);
    expect(await response.json()).toEqual({ error: "body_timeout" });
    expect(upstream.calls()).toBe(0);
  });
});

describe("cross-site requests", () => {
  it("are refused with 403 on GET and POST, before anything is counted, read or sent upstream", async () => {
    const upstream = stubFetch();
    const ctx = context(upstream.fetch);
    const counted = vi.spyOn(ctx.store, "incrWindow");
    const body = JSON.stringify({ tx_bytes: TX_BYTES, mode: "BROADCAST_MODE_SYNC" });
    for (const headers of CROSS_SITE_HEADERS) {
      const read = await handleChainGet(new Request(`http://app.local${MOUNT}/cosmos/base/tendermint/v1beta1/node_info`, { headers }), ctx);
      expect({ headers, status: read.status }).toEqual({ headers, status: 403 });
      expect(await read.json()).toEqual({ error: "cross_site" });
      const request = new Request(`http://app.local${MOUNT}/cosmos/tx/v1beta1/txs`, { method: "POST", body, headers: { "content-type": "application/json", ...headers } });
      const write = await handleChainPost(request, ctx);
      expect({ headers, status: write.status }).toEqual({ headers, status: 403 });
      expect(await write.json()).toEqual({ error: "cross_site" });
      expect(request.bodyUsed).toBe(false);
    }
    expect(counted).not.toHaveBeenCalled();
    expect(upstream.calls()).toBe(0);
  });
});
