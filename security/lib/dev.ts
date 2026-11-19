import { request } from "node:http";
import { DEV_SERVER } from "./guard.ts";

/** The most of any dev-server answer this suite keeps. Every handler answers in a few kilobytes. */
const ANSWER_CAP = 1_048_576;
const DEFAULT_TIMEOUT_MS = 30_000;

export interface DevAnswer {
  status: number;
  headers: Record<string, string>;
  json: unknown;
  /** The handler's short refusal code, when the body is `{ error }`. */
  error?: string;
}

export interface DevRequest {
  method: string;
  /** Sent on the request line exactly as given, so odd paths reach the server unchanged. */
  path: string;
  /** The loopback source address the server will see as the client's IP. */
  from: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  /** Send the body in pieces with no content-length, so only a cap applied while reading can stop it. */
  chunked?: boolean;
  timeoutMs?: number;
}

const LOOPBACK = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * One request to the local dev server, and only to it: the host and port are fixed here, and the
 * source must be a loopback address other than 127.0.0.1, which the demo bot's own sweep counts
 * under. The dev server takes the client IP from the socket (C23), so each source address is a
 * separate client to its rate limits.
 *
 * @throws When the source is not such an address, the path does not start with "/", the server
 *   cannot be reached, or it takes longer than the timeout.
 */
export async function dev(req: DevRequest): Promise<DevAnswer> {
  const m = LOOPBACK.exec(req.from);
  if (m === null || req.from === "127.0.0.1" || m.slice(1).some((o) => Number(o) > 255)) throw new Error(`${req.from} is not a loopback source address this suite may use.`);
  if (!req.path.startsWith("/")) throw new Error("A dev-server path starts with /.");
  const body = req.body === undefined ? undefined : typeof req.body === "string" ? Buffer.from(req.body, "utf8") : Buffer.from(req.body);
  const headers: Record<string, string> = { ...req.headers };
  if (body !== undefined && !req.chunked && headers["content-length"] === undefined) headers["content-length"] = String(body.length);

  return new Promise<DevAnswer>((resolve, reject) => {
    const r = request(
      { host: DEV_SERVER.host, port: DEV_SERVER.port, method: req.method, path: req.path, localAddress: req.from, headers, timeout: req.timeoutMs ?? DEFAULT_TIMEOUT_MS },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > ANSWER_CAP) {
            res.destroy(new Error("The dev server's answer is over 1 MiB."));
            return;
          }
          chunks.push(chunk);
        });
        res.on("error", reject);
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: unknown;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          const error = typeof json === "object" && json !== null && typeof (json as { error?: unknown }).error === "string" ? (json as { error: string }).error : undefined;
          const flat: Record<string, string> = {};
          for (const [name, value] of Object.entries(res.headers)) if (value !== undefined) flat[name] = Array.isArray(value) ? value.join(", ") : value;
          resolve({ status: res.statusCode ?? 0, headers: flat, json, ...(error === undefined ? {} : { error }) });
        });
      },
    );
    r.on("timeout", () => r.destroy(new Error(`The dev server did not answer ${req.method} within ${req.timeoutMs ?? DEFAULT_TIMEOUT_MS} ms.`)));
    r.on("error", reject);
    if (body !== undefined && req.chunked) {
      for (let at = 0; at < body.length; at += 16_384) r.write(body.subarray(at, at + 16_384));
      r.end();
    } else {
      r.end(body);
    }
  });
}

/** The status and code of an answer, the way evidence lines quote it. */
export const said = (a: DevAnswer): string => `${a.status}${a.error === undefined ? "" : ` ${a.error}`}`;

/**
 * Loopback source addresses for one run. The second octet comes from the minute the run started, so
 * a rerun within the hour does not inherit the last run's per-IP counters; every call hands out a
 * new address unless an attack keeps one for itself.
 */
export class SourceIps {
  readonly #octet: number;
  #next = 0;

  constructor(startedAt: number) {
    this.#octet = 2 + (Math.floor(startedAt / 60_000) % 250);
  }

  fresh(): string {
    const n = this.#next++;
    return `127.${this.#octet}.${Math.floor(n / 250)}.${(n % 250) + 2}`;
  }
}

/** True when the dev server answered that a part of it is not configured, so an attack on that part cannot run. */
export const notConfigured = (a: DevAnswer): boolean => a.status === 503 && (a.error === "not_configured" || a.error === "not_ready");

/** Our own headers on an answer (C22) and no CORS header of any kind (C23). */
export function ownHeaders(a: DevAnswer): boolean {
  const cors = Object.keys(a.headers).some((h) => h.toLowerCase().startsWith("access-control-"));
  return a.headers["content-type"] === "application/json" && a.headers["x-content-type-options"] === "nosniff" && !cors;
}

const isReset = (err: unknown): boolean => err instanceof Error && /ECONNRESET|EPIPE|socket hang up/i.test(`${(err as { code?: string }).code ?? ""} ${err.message}`);

/**
 * A request whose body the handler may cut off part way. Cancelling the read destroys the
 * unfinished request and its socket, so the answer may never arrive: a reset before any answer
 * comes back as undefined, meaning the server stopped reading at its cap. Any other failure throws.
 */
export async function devOrReset(req: DevRequest): Promise<DevAnswer | undefined> {
  try {
    return await dev(req);
  } catch (err) {
    if (isReset(err)) return undefined;
    throw err;
  }
}
