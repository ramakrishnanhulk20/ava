/** The chain's public EVM endpoint, which the browser reads directly. csp.test.ts pins it to @ava/core's EVM_RPC. */
export const EVM_RPC_ORIGIN = "https://evm-testnet.qore.host";

/**
 * Where the storage client sends a pack under its one-time token. The trailing slash admits the
 * paths under it and nothing else on that host.
 */
export const BLOB_UPLOAD_API = "https://vercel.com/api/blob/";

export type PolicyInput = {
  /** Fresh for every response, base64, at least 128 bits. */
  nonce: string;
  /** The blob store's public https origin, or an empty string when none is configured. */
  blobOrigin: string;
  /** A development server: React rebuilds error stacks with eval, hot reload talks over a socket, and the error overlay styles itself inline. */
  dev: boolean;
};

const NONCE = /^[A-Za-z0-9+/]{22,}={0,2}$/;

const HOSTNAME = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

/**
 * The value itself when it is one bare https origin: no path, no wildcard, nothing after it. An
 * environment variable can then never widen the policy or add a directive to it.
 */
function httpsOrigin(value: string): string | undefined {
  if (!URL.canParse(value)) return undefined;
  const url = new URL(value);
  return url.protocol === "https:" && url.origin === value && HOSTNAME.test(url.hostname) ? value : undefined;
}

/**
 * The Content-Security-Policy every page is served with (threat model C19).
 *
 * Scripts run only with this response's nonce, or when a script that had it loads them. No host is
 * trusted for scripts, and nothing inline or evaluated runs outside development. The browser may
 * talk to our own origin, the chain's public EVM endpoint, the blob store, and the storage API a
 * pack is uploaded to. The only frame is a `blob:` one, which the board room opens sandboxed to
 * show an image (C20). Forms are never submitted: every form on the site is handled by script, and
 * a form that fell back to the browser would put a passphrase in the address bar.
 *
 * Style attributes stay allowed, because the server renders positions and motion as attributes. A
 * `<style>` element needs the nonce like a script does.
 *
 * @throws Error when the nonce is not base64 of at least 128 bits.
 */
export function contentSecurityPolicy({ nonce, blobOrigin, dev }: PolicyInput): string {
  if (!NONCE.test(nonce)) throw new Error("The nonce must be base64 of at least 128 bits.");
  const blob = httpsOrigin(blobOrigin);
  const directives: [string, string[]][] = [
    ["default-src", ["'none'"]],
    ["script-src", ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", ...(dev ? ["'unsafe-eval'"] : [])]],
    // The development error overlay writes its own <style> elements, which carry no nonce. A nonce would also switch 'unsafe-inline' off.
    ["style-src", dev ? ["'self'", "'unsafe-inline'"] : ["'self'", `'nonce-${nonce}'`]],
    ["style-src-attr", ["'unsafe-inline'"]],
    ["img-src", ["'self'", "blob:"]],
    ["font-src", ["'self'"]],
    ["connect-src", ["'self'", EVM_RPC_ORIGIN, ...(blob === undefined ? [] : [blob]), BLOB_UPLOAD_API, ...(dev ? ["ws:"] : [])]],
    ["frame-src", ["blob:"]],
    ["manifest-src", ["'self'"]],
    ["object-src", ["'none'"]],
    ["base-uri", ["'none'"]],
    ["form-action", ["'none'"]],
    ["frame-ancestors", ["'none'"]],
  ];
  const policy = directives.map(([name, sources]) => `${name} ${sources.join(" ")}`);
  if (!dev) policy.push("upgrade-insecure-requests");
  return policy.join("; ");
}

/** A nonce for one response: 18 random bytes, so 24 base64 characters with no padding. */
export function freshNonce(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(18))));
}
