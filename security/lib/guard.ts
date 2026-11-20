import { sameAccount } from "@ava/core";
import { put } from "@vercel/blob/client";
import { REGISTRY_ADDRESS } from "../../packages/server/src/config.ts";

// The scope this suite may touch, fixed here and nowhere else. Every network call, transaction
// target and dev-server request goes through one of the checks below.

export const COSMOS_CHAIN_ID = "qorechain-diana";
export const EVM_CHAIN_ID = 9800;
export const RPC = "https://rpc-testnet.qore.host";
export const REST = "https://api-testnet.qore.host";
export const EVM_RPC = "https://evm-testnet.qore.host";

/** Our BoardRegistry: the one contract every board action goes to. */
export const REGISTRY = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa" as const;
/** Our PqcProbe from the first core-tech slice. Holds nothing; only ever called with eth_call. */
export const PROBE = "0x624b5C35E3665eB9ade6d75BBbca1218a09E00D1" as const;
/** The local dev server, packages/server/scripts/dev-server.ts. */
export const DEV_SERVER = { host: "127.0.0.1", port: 8787 } as const;
export const DEV_ORIGIN = `http://${DEV_SERVER.host}:${DEV_SERVER.port}`;

/** The two contracts this suite may send to or call. Nothing else, on any lane. */
export const ALLOWED_CONTRACTS: readonly `0x${string}`[] = [REGISTRY, PROBE];

const CHAIN_ORIGINS: readonly string[] = [RPC, REST, EVM_RPC].map((u) => new URL(u).origin);
const FETCH_TIMEOUT_MS = 20_000;

/** The guard refused a call. Nothing was sent. */
export class GuardRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardRefused";
  }
}

const realFetch = globalThis.fetch.bind(globalThis);
let blobOrigin: string | undefined;
let installed = false;

function methodOf(input: RequestInfo | URL, init: RequestInit | undefined): string {
  return (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
}

/**
 * Whether one outgoing request is inside the scope. The URL is parsed once and its origin compared
 * with the parsed allowed origins, so a different scheme, port, host spelling or embedded
 * credentials can never pass as an allowed host. Covers every request that goes through
 * globalThis.fetch: viem, the QoreChain SDK, cosmjs and @ava/core all use it. Does not cover the
 * Vercel Blob client, which brings its own HTTP stack; that one call goes through storePut below.
 */
export function allowedRequest(url: URL, method: string): boolean {
  if (url.username !== "" || url.password !== "") return false;
  if (CHAIN_ORIGINS.includes(url.origin)) return true;
  if (url.origin === DEV_ORIGIN) return true;
  return blobOrigin !== undefined && url.origin === blobOrigin && (method === "GET" || method === "HEAD");
}

/**
 * Replaces globalThis.fetch with one that refuses every host outside the scope and every redirect,
 * so an allowed host can never bounce a request somewhere else. Call it before any network use.
 *
 * @param opts.blobOrigin Our blob store's public origin; reads (GET, HEAD) only.
 */
export function installFetchGuard(opts: { blobOrigin?: string } = {}): void {
  blobOrigin = opts.blobOrigin === undefined ? undefined : new URL(opts.blobOrigin).origin;
  if (installed) return;
  installed = true;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const raw = input instanceof Request ? input.url : String(input);
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new GuardRefused("Refusing a request whose URL does not parse.");
    }
    const method = methodOf(input, init);
    if (!allowedRequest(url, method)) throw new GuardRefused(`Refusing ${method} to ${url.origin}: outside this suite's scope.`);
    return realFetch(input, { ...init, redirect: init?.redirect === "manual" ? "manual" : "error" });
  }) as typeof fetch;
}

/**
 * Replaces globalThis.fetch with one that refuses every request, so an offline run cannot reach any
 * network even through a library. Covers everything that goes through globalThis.fetch; the
 * offline attacks make no other kind of request.
 */
export function installOfflineGuard(): void {
  installed = true;
  globalThis.fetch = (async (): Promise<Response> => {
    throw new GuardRefused("Refusing a network request in an offline run.");
  }) as typeof fetch;
}

/**
 * Refuses any transaction target or eth_call address that is not one of our two contracts,
 * compared as 20 bytes.
 *
 * @throws GuardRefused for anything else.
 */
export function assertContract(address: string): void {
  if (!ALLOWED_CONTRACTS.some((c) => sameAccount(c, address))) throw new GuardRefused(`Refusing ${address}: not one of our two contracts.`);
}

/**
 * Refuses to run while the environment holds the means to sign as another account (any
 * `*_MNEMONIC` phrase or `*PRIVATE_KEY*`) or to reach our stores without our handlers (the blob
 * read-write token, any `UPSTASH_*` setting). Matching on the name's form catches an account added
 * later too. It does not cover a secret stored under a name of another form, and it ignores tokens
 * of unrelated tools; this suite reads only security/.env, and only its own keys.
 */
export function assertNoForeignSecrets(env: NodeJS.ProcessEnv = process.env): void {
  const foreign = Object.keys(env).filter((name) => /_MNEMONIC$|PRIVATE_KEY|^BLOB_READ_WRITE_TOKEN$|^UPSTASH_/i.test(name) && (env[name] ?? "") !== "");
  if (foreign.length > 0) throw new GuardRefused(`Refusing to run: the environment sets ${foreign.join(", ")}. Run from a shell without other accounts' secrets.`);
}

/**
 * The dev server's relayer must send only to the registry in scope. Its target is a build-time
 * constant in packages/server/src/config.ts; this checks that constant is ours.
 */
export function assertServerTarget(): void {
  if (!sameAccount(REGISTRY_ADDRESS, REGISTRY)) throw new GuardRefused("packages/server targets a registry outside this suite's scope.");
}

async function readJson(url: string, init?: RequestInit): Promise<unknown> {
  const response = await globalThis.fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${new URL(url).origin} answered HTTP ${response.status}.`);
  return response.json();
}

/**
 * Asks the consensus RPC and the EVM JSON-RPC which chain they serve, and throws unless they are
 * qorechain-diana and 9800. Every script calls this before any transaction.
 *
 * @throws When either endpoint cannot be read or names any other chain.
 */
export async function assertTestnet(): Promise<{ cosmos: string; evm: number }> {
  const status = (await readJson(`${RPC}/status`)) as { result?: { node_info?: { network?: unknown } } };
  const network = status.result?.node_info?.network;
  if (network !== COSMOS_CHAIN_ID) throw new GuardRefused(`${RPC} does not report chain ${COSMOS_CHAIN_ID}. Refusing to continue.`);
  const body = (await readJson(EVM_RPC, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
  })) as { result?: unknown };
  if (typeof body.result !== "string" || body.result.toLowerCase() !== `0x${EVM_CHAIN_ID.toString(16)}`) {
    throw new GuardRefused(`${EVM_RPC} does not report chain id ${EVM_CHAIN_ID}. Refusing to continue.`);
  }
  return { cosmos: network, evm: EVM_CHAIN_ID };
}

const issuedTokens = new Set<string>();

/** Records a client token our own /api/document/token handler issued in this run, so storePut will use it. */
export function noteIssuedToken(token: string): void {
  if (typeof token === "string" && token.startsWith("vercel_blob_client_")) issuedTokens.add(token);
}

/**
 * The one call outside the fetch guard: a browser-style upload straight to our own blob store with
 * a client token, which is the path the C28 token attacks must test. The Vercel Blob client sends
 * it to its fixed upload API with its own HTTP stack. This refuses unless the token is one our own
 * handler issued in this run and no setting points the client at another API.
 *
 * @throws GuardRefused before anything is sent; otherwise whatever the store answers, as the
 *   client's own error.
 */
export async function storePut(pathname: string, body: Uint8Array, opts: { token: string; contentType: string }): Promise<{ url: string; pathname: string }> {
  if (!issuedTokens.has(opts.token)) throw new GuardRefused("Refusing an upload with a token our own handler did not issue in this run.");
  if ((process.env.VERCEL_BLOB_API_URL ?? "") !== "" || (process.env.NEXT_PUBLIC_VERCEL_BLOB_API_URL ?? "") !== "") {
    throw new GuardRefused("Refusing an upload while a setting points the blob client at another API.");
  }
  return put(pathname, Buffer.from(body), { access: "public", token: opts.token, contentType: opts.contentType, multipart: false });
}
