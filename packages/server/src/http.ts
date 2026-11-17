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
