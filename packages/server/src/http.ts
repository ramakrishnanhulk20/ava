import { logEvent } from "./log.ts";
import type { SharedStore } from "./store.ts";

/** What the hosting layer hands every handler. */
export interface HandlerContext {
  /**
   * The caller's IP as the hosting platform itself reports it. Never read from X-Forwarded-For or
   * any other header the client can set; handlers never look at those headers.
   */
  clientIp: string;
  /** Milliseconds since the epoch, from the hosting layer's clock. */
  now: number;
  store: SharedStore;
}

/**
 * A JSON response under our own headers only: `application/json`, `nosniff`, and no caching.
 * No CORS header is ever set, so other sites' pages cannot read the answer (threat model C23).
 */
export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  const out = new Headers(headers);
  out.set("content-type", "application/json");
  out.set("x-content-type-options", "nosniff");
  out.set("cache-control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: out });
}

/** A refusal: a short code this package chose, never an echo of the input or an upstream text. */
export function refuse(status: number, error: string, headers: Record<string, string> = {}): Response {
  return json(status, { error }, headers);
}

/**
 * Refuses a request another site's page could have made a browser send (threat model C23). Every
 * public handler calls this first, before it counts anything, reads the body or calls upstream.
 *
 * Passes only when the `x-ava` header is exactly "1" and `Sec-Fetch-Site` is absent or exactly
 * "same-origin". A page cannot add a custom header to a request that needs no preflight (a beacon,
 * an image, a form, a no-cors fetch), and a cross-origin fetch that adds one needs a preflight this
 * server never answers, so the header proves the request came from our own app or from a client that
 * is not a browser. A browser always sends Sec-Fetch-Site, so any other value is a page off our origin.
 *
 * Does not cover a client that is not a browser: it can send both headers, and only the rate limits
 * stand in its way.
 *
 * @returns A 403 `{ "error": "cross_site" }` to send as is, or undefined to go on.
 */
export function refuseCrossSite(request: Request): Response | undefined {
  const site = request.headers.get("sec-fetch-site");
  if (request.headers.get("x-ava") === "1" && (site === null || site === "same-origin")) return undefined;
  logEvent("cross_site_refused");
  return refuse(403, "cross_site");
}

/** The body passed its byte cap. */
export class TooLarge extends Error {
  constructor() {
    super("The body is over its size cap.");
    this.name = "TooLarge";
  }
}

/**
 * Reads a byte stream to its end, stopping the moment the total passes `cap`: the chunk that
 * crosses the cap is the last one pulled, and the stream is cancelled so nothing more is asked of
 * the sender. Nothing past the cap is ever buffered.
 *
 * @param signal When it fires, the read stops and its reason is thrown, even if the stream would
 *   otherwise wait forever.
 * @throws TooLarge past the cap; TypeError if the stream yields anything but bytes.
 */
export async function readCapped(stream: ReadableStream<Uint8Array>, cap: number, signal?: AbortSignal): Promise<Uint8Array> {
  const reader = stream.getReader();
  const stop = (): void => {
    reader.cancel().catch(() => undefined);
  };
  signal?.addEventListener("abort", stop, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      if (signal?.aborted) throw signal.reason;
      const { done, value } = await reader.read();
      // A cancel on abort ends the read as if the stream were done, so check before trusting done.
      if (signal?.aborted) throw signal.reason;
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError("A body stream must yield bytes.");
      size += value.byteLength;
      if (size > cap) {
        stop();
        throw new TooLarge();
      }
      chunks.push(value);
    }
  } finally {
    signal?.removeEventListener("abort", stop);
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** How long a handler waits for a request body to end. */
export const BODY_TIMEOUT_MS = 20_000;

/** The request body did not end within BODY_TIMEOUT_MS. */
export class BodyTimeout extends Error {
  constructor() {
    super("The body did not end in time.");
    this.name = "BodyTimeout";
  }
}

/**
 * Reads a request body as readCapped does, and gives up after BODY_TIMEOUT_MS, so a sender that
 * trickles bytes or stops sending cannot hold a function open until the host kills it.
 *
 * @throws TooLarge past the cap; BodyTimeout after 20 seconds; TypeError if the stream yields
 *   anything but bytes.
 */
export async function readBody(stream: ReadableStream<Uint8Array>, cap: number): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new BodyTimeout()), BODY_TIMEOUT_MS);
  try {
    return await readCapped(stream, cap, controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

/** The request's path below `mount`, or undefined when it is outside it or the mount is malformed. */
export function pathBelow(request: Request, mount: string): string | undefined {
  if (!mount.startsWith("/") || mount.endsWith("/")) return undefined;
  const { pathname } = new URL(request.url);
  return pathname.startsWith(`${mount}/`) ? pathname.slice(mount.length) : undefined;
}

/** The declared length when the request states one; a stated length over a cap lets us refuse unread. */
export function declaredLength(request: Request): number | undefined {
  const raw = request.headers.get("content-length");
  if (raw === null || !/^\d{1,16}$/.test(raw)) return undefined;
  return Number(raw);
}
