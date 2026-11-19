import { readCapped, TooLarge } from "../../packages/server/src/http.ts";

export interface BlobRead {
  status: number;
  headers: Headers;
  /** The bytes of a 200 answer, at most `cap` of them. */
  bytes?: Uint8Array;
}

/**
 * Reads one public blob from our blob store's origin, the only GET the fetch guard allows there.
 * Redirects are refused and the body is cut at `cap`, so a wrong blob can never be large.
 *
 * @throws TooLarge past the cap; the guard's refusal for any other origin.
 */
export async function readBlob(url: string, cap: number): Promise<BlobRead> {
  const response = await globalThis.fetch(url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(30_000) });
  if (response.status !== 200 || response.body === null) {
    await response.body?.cancel().catch(() => undefined);
    return { status: response.status, headers: response.headers };
  }
  return { status: 200, headers: response.headers, bytes: await readCapped(response.body, cap) };
}

export { TooLarge };
