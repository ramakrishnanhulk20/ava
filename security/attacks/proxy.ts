import { notRun, verdict, type Attack, type Probe, type Result } from "../lib/attack.ts";
import type { Ctx } from "../lib/context.ts";
import { dev, devOrReset, notConfigured, ownHeaders, said, type DevAnswer } from "../lib/dev.ts";
import { PROXY_BODY_CAP, PROXY_LIMITS } from "../../packages/server/src/proxy.ts";

const M = "/api/chain";
const NODE_INFO = `${M}/cosmos/base/tendermint/v1beta1/node_info`;
const SIMULATE = `${M}/cosmos/tx/v1beta1/simulate`;
const BROADCAST = `${M}/cosmos/tx/v1beta1/txs`;
const JSON_HEADERS = { "content-type": "application/json" };

interface Case {
  label?: string;
  method?: string;
  path: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  chunked?: boolean;
  status: number | readonly number[];
  error?: string | readonly string[];
  /**
   * A body cut off part way: the handler cancels its read, which destroys the unfinished request
   * and its socket, so the answer may never arrive. A reset then means the server stopped reading
   * at its cap, and counts as the refusal.
   */
  resetIsRefusal?: boolean;
}

const list = <T>(v: T | readonly T[]): readonly T[] => (Array.isArray(v) ? (v as readonly T[]) : [v as T]);

async function probe(c: Case, from: string): Promise<Probe> {
  const label = c.label ?? `${c.method ?? "GET"} ${c.path.length > 96 ? `${c.path.slice(0, 93)}...` : c.path}`;
  const req = { method: c.method ?? "GET", path: c.path, from, ...(c.headers === undefined ? {} : { headers: c.headers }), ...(c.body === undefined ? {} : { body: c.body }), ...(c.chunked ? { chunked: true } : {}) };
  const a = c.resetIsRefusal ? await devOrReset(req) : await dev(req);
  if (a === undefined) return { ok: true, line: `${label} -> the server closed the connection after its cap, with no answer` };
  const statusOk = list(c.status).includes(a.status);
  const errorOk = c.error === undefined || (a.error !== undefined && list(c.error).includes(a.error));
  const wanted = `${list(c.status).join(" or ")}${c.error === undefined ? "" : ` ${list(c.error).join(" or ")}`}`;
  return { ok: statusOk && errorOk && ownHeaders(a), line: `${label} -> ${said(a)}${ownHeaders(a) ? "" : " (NOT our own headers)"} (wanted ${wanted})` };
}

async function run(ctx: Ctx, cases: readonly Case[]): Promise<Result> {
  const from = ctx.ips.fresh();
  const probes: Probe[] = [];
  for (const c of cases) probes.push(await probe(c, from));
  return verdict(probes, `from ${from}: `);
}

/** A qor1 address with its last checksum character swapped for another valid one. */
function badChecksum(qor1: string): string {
  const last = qor1.at(-1);
  return `${qor1.slice(0, -1)}${last === "q" ? "p" : "q"}`;
}

/** An EIP-55 address with the case of its first letter flipped, so only the checksum is wrong. */
function badCase(evm: string): string {
  const i = [...evm].findIndex((ch, n) => n > 1 && /[a-fA-F]/.test(ch));
  if (i < 0) return `${evm}0`;
  const ch = evm[i]!;
  return `${evm.slice(0, i)}${ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()}${evm.slice(i + 1)}`;
}

/** A JSON-shaped body of exactly `size` bytes. */
function bodyOf(size: number): string {
  const head = '{"tx_bytes":"';
  return `${head}${"A".repeat(Math.max(0, size - head.length - 2))}"}`;
}

const doubleSlash: Attack = {
  id: "C22-double-slash",
  claim: "The proxy reaches only the chain's REST: a path starting // that a URL parser would read as another host is refused, never fetched.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${M}//evil.example/`, status: 404, error: "unknown_route" },
      { path: `${M}//evil.example/cosmos/base/tendermint/v1beta1/node_info`, status: 404, error: "unknown_route" },
      { path: `${M}///evil.example`, status: 404, error: "unknown_route" },
    ]),
};

const fullUrl: Attack = {
  id: "C22-full-url",
  claim: "A full URL in the path cannot replace the upstream host: it is refused as an unknown route.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${M}/https://evil.example/x`, status: 404, error: "unknown_route" },
      { path: `${M}/https:/evil.example`, status: 404, error: "unknown_route" },
      { path: `${M}/http:%2f%2fevil.example%2fcosmos`, status: 404, error: "unknown_route" },
    ]),
};

const dotSegments: Attack = {
  id: "C22-dot-segments",
  claim: "Dot segments, plain or percent-encoded, are resolved by the server's URL parser before routing, so they can only land on our own routes and never reach the upstream as written.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${M}/cosmos/../x`, status: 404, error: ["unknown_route", "not_found"] },
      { path: `${M}/cosmos/%2e%2e/%2e%2e/x`, status: 404, error: ["unknown_route", "not_found"] },
      { path: `${M}/../../../etc/passwd`, status: 404, error: "not_found" },
      { path: `${M}/cosmos/bank/v1beta1/balances/..`, status: 404, error: "unknown_route" },
      { label: `GET ${M}/../upload (lands on our own upload handler)`, path: `${M}/../upload`, status: 405, error: "method_not_allowed" },
    ]),
};

const encodedSlash: Attack = {
  id: "C22-encoded-slash",
  claim: "Encoded and double-encoded slashes are never decoded into a path: literal segments must match as written and each parameter goes through its own codec.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${M}/cosmos%2fauth%2fv1beta1%2faccounts%2f${ctx.wallet.qor1}`, status: 404, error: "unknown_route" },
      { path: `${M}/cosmos/auth/v1beta1/accounts/..%2f..%2f..%2fx`, status: 400, error: "bad_parameter" },
      { path: `${M}/cosmos/auth/v1beta1/accounts/%252e%252e%252fx`, status: 400, error: "bad_parameter" },
      { path: `${M}/cosmos/tx/v1beta1/txs/${"ab".repeat(32)}%2f..`, status: 400, error: "bad_parameter" },
      { path: `${M}/cosmos/base/tendermint/v1beta1/blocks%2flatest`, status: 404, error: "unknown_route" },
    ]),
};

const query: Attack = {
  id: "C22-query",
  claim: "No query string is forwarded on any route, a bare ? included.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${NODE_INFO}?x=1`, status: 400, error: "query_not_allowed" },
      { path: `${NODE_INFO}?`, status: 400, error: "query_not_allowed" },
      { path: `${M}/cosmos/auth/v1beta1/accounts/${ctx.wallet.qor1}?height=1`, status: 400, error: "query_not_allowed" },
      { path: `${M}/cosmos/bank/v1beta1/balances/${ctx.wallet.qor1}?pagination.limit=1000000`, status: 400, error: "query_not_allowed" },
    ]),
};

const badAddress: Attack = {
  id: "C22-bad-address",
  claim: "An address in the path is decoded by the strict shared codec (C16): all-lowercase 0x, a wrong EIP-55 case, a bad bech32 checksum, 0X and 22 bytes are each refused.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { path: `${M}/cosmos/auth/v1beta1/accounts/${ctx.wallet.evm.toLowerCase()}`, status: 400, error: "bad_parameter" },
      { path: `${M}/cosmos/auth/v1beta1/accounts/${badCase(ctx.wallet.evm)}`, status: 400, error: "bad_parameter" },
      { path: `${M}/cosmos/bank/v1beta1/balances/${badChecksum(ctx.wallet.qor1)}`, status: 400, error: "bad_parameter" },
      { path: `${M}/qorechain/pqc/v1/account/0X${ctx.wallet.evm.slice(2)}`, status: 400, error: "bad_parameter" },
      { path: `${M}/qorechain/pqc/v1/evm_window/${ctx.wallet.evm}abcd`, status: 400, error: "bad_parameter" },
    ]),
};

const postPath: Attack = {
  id: "C22-post-path",
  claim: "POST is accepted only for transaction simulate and broadcast, as JSON of exactly their schema: another path, another content type, an extra field, a bad base64 and a mode other than SYNC are refused unsent.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { method: "POST", path: `${M}/cosmos/bank/v1beta1/balances/${ctx.wallet.qor1}`, headers: JSON_HEADERS, body: "{}", status: 404, error: "unknown_route" },
      { method: "POST", path: `${M}//evil.example/cosmos/tx/v1beta1/simulate`, headers: JSON_HEADERS, body: '{"tx_bytes":"AA=="}', status: 404, error: "unknown_route" },
      { method: "POST", path: `${SIMULATE}?x=1`, headers: JSON_HEADERS, body: '{"tx_bytes":"AA=="}', status: 400, error: "query_not_allowed" },
      { method: "POST", path: SIMULATE, headers: { "content-type": "text/plain" }, body: '{"tx_bytes":"AA=="}', status: 415, error: "json_only" },
      { method: "POST", path: SIMULATE, headers: JSON_HEADERS, body: '{"tx_bytes":"AA==","extra":1}', status: 400, error: "bad_body" },
      { method: "POST", path: SIMULATE, headers: JSON_HEADERS, body: '{"tx_bytes":"not base64!"}', status: 400, error: "bad_body" },
      { method: "POST", path: BROADCAST, headers: JSON_HEADERS, body: '{"tx_bytes":"AA==","mode":"BROADCAST_MODE_BLOCK"}', status: 400, error: "bad_body" },
      { method: "POST", path: `${M}/qorechain/pqc/v1/protocol_features`, headers: JSON_HEADERS, body: "{}", status: 404, error: "unknown_route" },
    ]),
};

const postOversize: Attack = {
  id: "C22-post-oversize",
  claim: `A POST body over ${PROXY_BODY_CAP} bytes is refused: by its stated length before reading, and while reading when no length is stated.`,
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { label: `POST simulate, ${PROXY_BODY_CAP + 1} bytes with content-length`, method: "POST", path: SIMULATE, headers: JSON_HEADERS, body: bodyOf(PROXY_BODY_CAP + 1), resetIsRefusal: true, status: 413, error: "body_too_large" },
      { label: "POST simulate, 60,000 bytes chunked, no length", method: "POST", path: SIMULATE, headers: JSON_HEADERS, body: bodyOf(60_000), chunked: true, resetIsRefusal: true, status: 413, error: "body_too_large" },
    ]),
};

const methods: Attack = {
  id: "C22-method",
  claim: "Only GET and POST reach the proxy: PUT, DELETE and PATCH are refused.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { method: "PUT", path: NODE_INFO, status: 405, error: "method_not_allowed" },
      { method: "DELETE", path: NODE_INFO, status: 405, error: "method_not_allowed" },
      { method: "PATCH", path: NODE_INFO, status: 405, error: "method_not_allowed" },
    ]),
};

const PLAN = `${M}/cosmos/upgrade/v1beta1/applied_plan`;

const upgradeName: Attack = {
  id: "C22-upgrade-name",
  claim: "The new applied_plan route takes only an upgrade name of 1 to 32 lowercase letters, digits, dots and hyphens; uppercase, too long, underscores, encoded slashes, an empty name and an extra segment are refused.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { label: `GET ${PLAN}/v3.2.0 (control, one public read)`, path: `${PLAN}/v3.2.0`, status: [200, 404] },
      { path: `${PLAN}/V3.2.0`, status: 400, error: "bad_parameter" },
      { path: `${PLAN}/${"v".repeat(33)}`, status: 400, error: "bad_parameter" },
      { path: `${PLAN}/v3_2_0`, status: 400, error: "bad_parameter" },
      { path: `${PLAN}/v3.2.0%2f..%2fx`, status: 400, error: "bad_parameter" },
      { path: `${PLAN}/`, status: 400, error: "bad_parameter" },
      { path: `${PLAN}/v3.2.0/x`, status: 404, error: "unknown_route" },
    ]),
};

const FEATURES = `${M}/qorechain/pqc/v1/protocol_features`;

const protocolFeatures: Attack = {
  id: "C22-protocol-features",
  claim: "The new protocol_features route takes no parameter: the plain read answers under our own JSON headers, and an extra segment or a query is refused.",
  costUqor: 0n,
  run: (ctx) =>
    run(ctx, [
      { label: `GET ${FEATURES} (control, one public read)`, path: FEATURES, status: 200 },
      { path: `${FEATURES}/x`, status: 404, error: "unknown_route" },
      { path: `${FEATURES}?x=1`, status: 400, error: "query_not_allowed" },
    ]),
};

const noCors: Attack = {
  id: "C23-no-cors",
  claim: "Our endpoints serve our app, not the internet: a preflight and requests carrying another site's Origin get no CORS header from the proxy, the relay or the upload.",
  costUqor: 0n,
  async run(ctx) {
    const from = ctx.ips.fresh();
    const origin = { origin: "https://evil.example" };
    const answers: [string, DevAnswer][] = [
      ["OPTIONS preflight to the proxy", await dev({ method: "OPTIONS", path: NODE_INFO, from, headers: { ...origin, "access-control-request-method": "GET" } })],
      ["GET an unknown proxy route with Origin", await dev({ method: "GET", path: `${M}/x`, from, headers: origin })],
      ["POST /api/relay with Origin and no JSON", await dev({ method: "POST", path: "/api/relay", from, headers: { ...origin, "content-type": "text/plain" }, body: "x" })],
      ["POST /api/upload with Origin and a bad kind", await dev({ method: "POST", path: "/api/upload?kind=x", from, headers: origin, body: "x" })],
    ];
    if (answers.some(([, a]) => notConfigured(a))) return notRun("a dev-server route answers 503 not_configured");
    return verdict(answers.map(([label, a]) => ({ ok: ownHeaders(a), line: `${label} -> ${said(a)}, ${ownHeaders(a) ? "no access-control header" : "CARRIES AN ACCESS-CONTROL HEADER OR ANOTHER CONTENT TYPE"}` })), `from ${from}: `);
  },
};

const xff: Attack = {
  id: "C23-xff",
  claim: `Rate limits count the address the platform reports, never a header: ${PROXY_LIMITS.perIp + 1} proxy requests from one address, each claiming another X-Forwarded-For, X-Real-IP and Forwarded, are cut off at ${PROXY_LIMITS.perIp} a minute.`,
  costUqor: 0n,
  costNote: `${PROXY_LIMITS.perIp + 1} requests to an unknown route, so the upstream is never called`,
  async run(ctx) {
    const from = ctx.ips.fresh();
    const statuses: number[] = [];
    let last: DevAnswer | undefined;
    for (let i = 0; i <= PROXY_LIMITS.perIp; i++) {
      const spoof = `10.${Math.floor(i / 250)}.${i % 250}.7`;
      last = await dev({ method: "GET", path: `${M}/x`, from, headers: { "x-forwarded-for": spoof, "x-real-ip": spoof, forwarded: `for=${spoof}` } });
      statuses.push(last.status);
    }
    const first = statuses.slice(0, PROXY_LIMITS.perIp);
    const allowed = first.every((s) => s === 404);
    const cut = last !== undefined && last.status === 429 && last.error === "rate_limited" && last.headers["retry-after"] !== undefined;
    return verdict([
      { ok: allowed, line: `requests 1 to ${PROXY_LIMITS.perIp}, each with a different spoofed client header: ${allowed ? `all 404 unknown_route` : `statuses ${[...new Set(first)].join(", ")}`}` },
      { ok: cut, line: `request ${PROXY_LIMITS.perIp + 1}: ${last === undefined ? "none" : said(last)}${last?.headers["retry-after"] === undefined ? "" : `, retry-after ${last.headers["retry-after"]}`}` },
    ], `from ${from}: `);
  },
};

export const attacks: readonly Attack[] = [doubleSlash, fullUrl, dotSegments, encodedSlash, query, badAddress, postPath, postOversize, methods, upgradeName, protocolFeatures, noCors, xff];
