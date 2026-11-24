const UPLOAD_PATH = "/api/upload";

export interface ApiCall {
  /** Sent as application/json. Any endpoint but /api/upload. */
  json?: unknown;
  /** Sent as application/octet-stream. /api/upload only. */
  bytes?: Uint8Array<ArrayBuffer>;
  signal?: AbortSignal;
}

/**
 * Calls one of our own endpoints from the browser: a GET with no body, or a POST with either a JSON
 * body or, for /api/upload, raw bytes. Every call carries `x-ava: 1`, which the server requires to
 * tell our app from another site's page (threat model C23).
 *
 * The path is resolved against this page's origin by the URL parser and refused unless it stays on
 * that origin under /api/, so neither the header nor the page's credentials ever reach another
 * host. A redirect fails the call instead of being followed.
 *
 * @param path Like "/api/chain/..." or "/api/upload?kind=envelope".
 * @returns The server's Response as it came, whatever its status.
 * @throws Rejects with TypeError for a path off our API, for both bodies at once, for JSON sent to
 *   /api/upload or bytes sent anywhere else, and for a network failure or redirect.
 */
export async function api(path: string, call: ApiCall = {}): Promise<Response> {
  const origin = window.location.origin;
  const url = new URL(path, origin);
  if (url.origin !== origin || !url.pathname.startsWith("/api/")) throw new TypeError("api() only calls this site's own /api/ endpoints.");
  const upload = url.pathname === UPLOAD_PATH;
  const headers = new Headers({ "x-ava": "1" });
  const init: RequestInit = { method: "GET", headers, credentials: "same-origin", redirect: "error", cache: "no-store", signal: call.signal };
  if (call.json !== undefined && call.bytes !== undefined) throw new TypeError("api() takes a JSON body or bytes, not both.");
  if (call.bytes !== undefined) {
    if (!upload) throw new TypeError("Raw bytes go to /api/upload only.");
    headers.set("content-type", "application/octet-stream");
    init.method = "POST";
    init.body = call.bytes;
  } else if (call.json !== undefined) {
    if (upload) throw new TypeError("/api/upload takes raw bytes, not JSON.");
    headers.set("content-type", "application/json");
    init.method = "POST";
    init.body = JSON.stringify(call.json);
  }
  return fetch(url, init);
}
