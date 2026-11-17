import { toQor1 } from "@ava/core";
import { z } from "zod";
import { declaredLength, json, pathBelow, readCapped, refuse, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { limit } from "./ratelimit.ts";
import { accountBytesStrict } from "./requestAddress.ts";

export interface ProxyContext extends HandlerContext {
  /** REST_UPSTREAM from loadEnv: the one origin the proxy may reach. */
  upstream: string;
  /** The path the app serves the proxy under, like "/api/chain". No trailing slash. */
  mount: string;
  /** Used for the upstream call; the global fetch by default. Tests pass a stub. */
  fetch?: typeof fetch;
  /** Overrides PROXY_LIMITS. */
  limits?: { perIp: number; total: number; windowSeconds: number };
}

/**
 * Per IP and in total, per minute. QoreChain does not publish the public REST's per-IP budget, so
 * the total is kept to 5 requests a second, well under what a single browser tab is allowed there.
 */
export const PROXY_LIMITS = { perIp: 60, total: 300, windowSeconds: 60 } as const;
export const PROXY_TIMEOUT_MS = 8_000;
/** 1 MiB. Every route the app reads answers in a few kilobytes. */
export const PROXY_RESPONSE_CAP = 1_048_576;
/**
 * 48 KiB. A hybrid-signed key registration, the largest transaction the app sends, is about 16 KB as
 * base64 inside JSON (ML-DSA-87 key and signature plus the classical signature), so this holds one
 * with room to spare and nothing like a general upload.
 */
export const PROXY_BODY_CAP = 49_152;

const USER_AGENT = "ava-chain-proxy";

type Codec = (segment: string) => string | undefined;

/** qor1 or exact EIP-55 0x, decoded to its 20 bytes by the strict shared codec (C16) and sent as qor1. */
const addressCodec: Codec = (segment) => {
  try {
    return toQor1(accountBytesStrict(segment));
  } catch {
    return undefined;
  }
};

/**
 * A transaction hash: exactly 64 hex characters, sent uppercase as the REST writes it. Covers form
 * and length. It cannot cover whether such a transaction exists; the upstream answers that.
 */
const txHashCodec: Codec = (segment) => (/^[0-9a-fA-F]{64}$/.test(segment) ? segment.toUpperCase() : undefined);

/**
 * An upgrade plan name such as `v3.2.0`: 1 to 32 lowercase letters, digits, dots and hyphens, sent
 * as given. Covers form and length. A name of only dots is a dot segment, which the URL parser
 * rewrites, so the exact-path check in upstreamUrl refuses it rather than this codec.
 */
const upgradeNameCodec: Codec = (segment) => (/^[a-z0-9.-]{1,32}$/.test(segment) ? segment : undefined);

const CODECS: ReadonlyMap<string, Codec> = new Map([
  ["{address}", addressCodec],
  ["{hash}", txHashCodec],
  ["{name}", upgradeNameCodec],
]);

/**
 * The only reads the app makes. This list is not the defence against request forgery (origin
 * equality in upstreamUrl is); it keeps the proxy from being a free general-purpose proxy, and it
 * fails closed: a missing route breaks a feature and never opens anything. The last two are the
 * reads the SDK's own choice of the hybrid sign-bytes form makes.
 */
const GET_ROUTES = [
  "/cosmos/auth/v1beta1/accounts/{address}",
  "/cosmos/bank/v1beta1/balances/{address}",
  "/qorechain/pqc/v1/account/{address}",
  "/qorechain/pqc/v1/evm_window/{address}",
  "/cosmos/tx/v1beta1/txs/{hash}",
  "/cosmos/base/tendermint/v1beta1/blocks/latest",
  "/cosmos/base/tendermint/v1beta1/node_info",
  "/qorechain/pqc/v1/protocol_features",
  "/cosmos/upgrade/v1beta1/applied_plan/{name}",
] as const;

const tx_bytes = z.base64().min(1);
const POST_ROUTES: ReadonlyMap<string, z.ZodType> = new Map<string, z.ZodType>([
  ["/cosmos/tx/v1beta1/simulate", z.strictObject({ tx_bytes })],
  ["/cosmos/tx/v1beta1/txs", z.strictObject({ tx_bytes, mode: z.literal("BROADCAST_MODE_SYNC") })],
]);

type Match = { path: string } | { refused: 400 | 404 };

/**
 * Matches a requested path against the GET routes segment by segment. Literal segments must be
 * equal as written (nothing is percent-decoded, so `%2f` and `%252f` never become a slash), and each
 * parameter goes through its own codec. The result is built only from route text and codec output.
 */
export function matchGetRoute(path: string): Match {
  const given = path.split("/");
  for (const route of GET_ROUTES) {
    const parts = route.split("/");
    if (parts.length !== given.length) continue;
    const out: string[] = [];
    let badParameter = false;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i] ?? "";
      const segment = given[i] ?? "";
      const codec = CODECS.get(part);
      if (codec === undefined) {
        if (part !== segment) break;
        out.push(part);
        continue;
      }
      const decoded = codec(segment);
      if (decoded === undefined) {
        badParameter = true;
        break;
      }
      out.push(decoded);
    }
    if (badParameter) return { refused: 400 };
    if (out.length === parts.length) return { path: out.join("/") };
  }
  return { refused: 404 };
}

/**
 * The URL to fetch for `path`, or undefined. `new URL(path, base)` lets a path such as `//host/` or
 * `https://host/` replace the host, so the origin is compared after parsing, and the URL object that
 * passed is the one fetched. The parsed pathname must also equal `path`: if the parser rewrote it
 * (dot segments, backslashes, encoding), what was checked is not what would be sent, so refuse.
 */
export function upstreamUrl(path: string, upstream: string): URL | undefined {
  let base: URL;
  let url: URL;
  try {
    base = new URL(upstream);
    url = new URL(path, base);
  } catch {
    return undefined;
  }
  const exact = url.origin === base.origin && url.pathname === path && url.search === "" && url.hash === "";
  return exact && url.username === "" && url.password === "" ? url : undefined;
}

async function discard(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}

class UpstreamTimeout extends Error {
  constructor() {
    super("The upstream did not answer in time.");
    this.name = "UpstreamTimeout";
  }
}

/**
 * Sends one request upstream with our own headers only, refuses redirects, reads at most
 * PROXY_RESPONSE_CAP within PROXY_TIMEOUT_MS, and answers with the parsed JSON re-serialised under
 * our own headers. Upstream 2xx and 4xx statuses pass through so the app can tell "no such account"
 * from a fault; anything else becomes 502.
 *
 * Cosmos REST writes 64-bit integers as JSON strings, so parsing and re-serialising loses nothing.
 */
async function forward(url: URL, method: "GET" | "POST", body: string | undefined, ctx: ProxyContext): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new UpstreamTimeout()), PROXY_TIMEOUT_MS);
  try {
    const headers = new Headers({ accept: "application/json", "user-agent": USER_AGENT });
    if (body !== undefined) headers.set("content-type", "application/json");
    let upstream: Response;
    try {
      upstream = await (ctx.fetch ?? fetch)(url, { method, headers, body, redirect: "manual", signal: controller.signal });
    } catch {
      logEvent("proxy_refused", { reason: controller.signal.aborted ? "upstream_timeout" : "upstream_unreachable" });
      return controller.signal.aborted ? refuse(504, "upstream_timeout") : refuse(502, "upstream_unreachable");
    }
    const status = upstream.status;
    if (upstream.type === "opaqueredirect" || (status >= 300 && status < 400)) {
      await discard(upstream);
      logEvent("proxy_refused", { reason: "upstream_redirect" });
      return refuse(502, "upstream_redirect");
    }
    if (status < 200 || status >= 500 || upstream.body === null) {
      await discard(upstream);
      logEvent("proxy_refused", { reason: "upstream_error", status });
      return refuse(502, "upstream_error");
    }
    let bytes: Uint8Array;
    try {
      bytes = await readCapped(upstream.body, PROXY_RESPONSE_CAP, controller.signal);
    } catch (error) {
      const reason = error instanceof TooLarge ? "upstream_too_large" : controller.signal.aborted ? "upstream_timeout" : "upstream_error";
      logEvent("proxy_refused", { reason });
      return refuse(reason === "upstream_timeout" ? 504 : 502, reason);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      parsed = undefined;
    }
    if (parsed === null || typeof parsed !== "object") {
      logEvent("proxy_refused", { reason: "upstream_not_json" });
      return refuse(502, "upstream_not_json");
    }
    return json(status, parsed);
  } finally {
    clearTimeout(timer);
  }
}

async function admit(request: Request, ctx: ProxyContext, method: "GET" | "POST"): Promise<Response | string> {
  if (request.method !== method) return refuse(405, "method_not_allowed", { allow: method });
  const rule = ctx.limits ?? PROXY_LIMITS;
  const verdict = await limit(ctx.store, { scope: "proxy", clientIp: ctx.clientIp, ...rule });
  if (!verdict.ok) return refuse(429, "rate_limited", { "retry-after": String(verdict.retryAfter) });
  // No query parameter is accepted on any route, and a bare "?" counts as one.
  if (request.url.includes("?")) return refuse(400, "query_not_allowed");
  const path = pathBelow(request, ctx.mount);
  if (path === undefined) return refuse(404, "unknown_route");
  return path;
}

/**
 * GET proxy to the chain's public REST, for the reads browsers cannot make directly because the
 * REST sends no CORS headers (threat model C22, C23).
 *
 * Answers 405 for another method, 429 over the rate limit or when the limit cannot be checked, 400
 * for a query string or a parameter its codec refuses, 404 for any other path, 502 for an upstream
 * redirect, fault, oversized or non-JSON body, and 504 on timeout. The upstream is never called for
 * a refused request. No request header is forwarded.
 */
export async function handleChainGet(request: Request, ctx: ProxyContext): Promise<Response> {
  const admitted = await admit(request, ctx, "GET");
  if (typeof admitted !== "string") return admitted;
  const match = matchGetRoute(admitted);
  if ("refused" in match) {
    logEvent("proxy_refused", { reason: match.refused === 400 ? "bad_parameter" : "unknown_route" });
    return refuse(match.refused, match.refused === 400 ? "bad_parameter" : "unknown_route");
  }
  const url = upstreamUrl(match.path, ctx.upstream);
  if (url === undefined) return refuse(400, "bad_path");
  return forward(url, "GET", undefined, ctx);
}

/**
 * POST proxy for transaction simulate and broadcast only (threat model C22). The body must be
 * `application/json`, at most PROXY_BODY_CAP bytes (refused 413 while reading, before more is
 * buffered), and match the route's schema exactly: `tx_bytes` in base64, and for broadcast `mode`
 * BROADCAST_MODE_SYNC and nothing else. What goes upstream is the validated object re-serialised,
 * never the raw body.
 *
 * Answers as handleChainGet, plus 415 for another content type and 413 over the cap.
 */
export async function handleChainPost(request: Request, ctx: ProxyContext): Promise<Response> {
  const admitted = await admit(request, ctx, "POST");
  if (typeof admitted !== "string") return admitted;
  const schema = POST_ROUTES.get(admitted);
  if (schema === undefined) return refuse(404, "unknown_route");
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return refuse(415, "json_only");
  const stated = declaredLength(request);
  if (stated !== undefined && stated > PROXY_BODY_CAP) return refuse(413, "body_too_large");
  if (request.body === null) return refuse(400, "bad_body");
  let parsed: unknown;
  try {
    const bytes = await readCapped(request.body, PROXY_BODY_CAP);
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch (error) {
    if (error instanceof TooLarge) return refuse(413, "body_too_large");
    return refuse(400, "bad_body");
  }
  const checked = schema.safeParse(parsed);
  if (!checked.success) {
    logEvent("proxy_refused", { reason: "bad_body" });
    return refuse(400, "bad_body");
  }
  const url = upstreamUrl(admitted, ctx.upstream);
  if (url === undefined) return refuse(400, "bad_path");
  return forward(url, "POST", JSON.stringify(checked.data), ctx);
}
