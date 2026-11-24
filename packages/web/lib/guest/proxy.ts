import type { FetchLike } from "@qorechain/sdk";
import { api } from "../api";

/** Where the app serves the chain REST proxy. The chain's REST sends no CORS headers, so the browser reads it only through here. */
export const CHAIN_MOUNT = "/api/chain";
/** The guest's coin, as the chain names it. */
export const DENOM = "uqor";

type Json = Record<string, unknown>;

/** The proxy answered with a status other than 200. `error` is the proxy's or the upstream's short code, when it sent one. */
export class ChainHttpError extends Error {
  readonly status: number;
  readonly error: string | undefined;

  constructor(status: number, error: string | undefined) {
    super(`The chain proxy answered HTTP ${status}${error === undefined ? "" : ` ${error}`}.`);
    this.name = "ChainHttpError";
    this.status = status;
    this.error = error;
  }
}

async function answer(response: Response): Promise<Json> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  const record = body !== null && typeof body === "object" && !Array.isArray(body) ? (body as Json) : undefined;
  if (response.status !== 200 || record === undefined) {
    const error = typeof record?.error === "string" && /^[A-Za-z0-9_]{1,64}$/.test(record.error) ? record.error : undefined;
    throw new ChainHttpError(response.status, error);
  }
  return record;
}

/** GET one of the proxy's routes, like "/cosmos/bank/v1beta1/balances/qor1...". */
export async function chainGet(path: string, signal?: AbortSignal): Promise<Json> {
  return answer(await api(`${CHAIN_MOUNT}${path}`, { signal }));
}

/** POST one of the proxy's two routes: simulate, or broadcast in BROADCAST_MODE_SYNC. */
export async function chainPost(path: string, body: Json, signal?: AbortSignal): Promise<Json> {
  return answer(await api(`${CHAIN_MOUNT}${path}`, { json: body, signal }));
}

/** The proxy's base URL, for the SDK's own REST lookups. */
export function proxyRest(): string {
  return `${window.location.origin}${CHAIN_MOUNT}`;
}

/**
 * The fetch the SDK's sign-bytes lookup runs through: GET only, and only under this page's own
 * proxy mount, parsed by the URL parser, so the SDK's REST reads carry x-ava and never leave this
 * origin. Anything else rejects before a request is made.
 */
export const proxyFetch: FetchLike = (input, init) => {
  const method = (init?.method ?? "GET").toUpperCase();
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return Promise.reject(new TypeError("The SDK asked for a URL that does not parse."));
  }
  const hasBody = init?.body !== undefined && init.body !== null;
  if (method !== "GET" || hasBody || url.origin !== window.location.origin || !url.pathname.startsWith(`${CHAIN_MOUNT}/`) || url.search !== "" || url.hash !== "") {
    return Promise.reject(new TypeError("The SDK asked for something other than a GET on this site's chain proxy."));
  }
  return api(url.pathname, { signal: init?.signal ?? undefined });
};

function digits(value: unknown, what: string): bigint {
  if (typeof value !== "string" || !/^\d{1,30}$/.test(value)) throw new Error(`Unexpected ${what} in a chain answer.`);
  return BigInt(value);
}

/**
 * The account number and the committed sequence the next signature must carry.
 *
 * @returns undefined when the chain has never seen the address (not funded yet).
 */
export async function accountSequence(qor1: string, signal?: AbortSignal): Promise<{ accountNumber: bigint; sequence: bigint } | undefined> {
  let body: Json;
  try {
    body = await chainGet(`/cosmos/auth/v1beta1/accounts/${encodeURIComponent(qor1)}`, signal);
  } catch (error) {
    if (error instanceof ChainHttpError && error.status === 404) return undefined;
    throw error;
  }
  const account = body.account as Json | undefined;
  const record = (account?.base_account ?? account) as Json | undefined;
  if (record === undefined || record === null || typeof record !== "object") throw new Error("The account answer carries no account record.");
  return { accountNumber: digits(record.account_number, "account number"), sequence: digits(record.sequence, "sequence") };
}

/** The account's uqor balance, 0 for an account the chain has never seen. */
export async function balanceOf(qor1: string, signal?: AbortSignal): Promise<bigint> {
  const body = await chainGet(`/cosmos/bank/v1beta1/balances/${encodeURIComponent(qor1)}`, signal);
  if (!Array.isArray(body.balances)) throw new Error("Unexpected balance answer: no balances list.");
  const coin = body.balances.find((c: unknown) => (c as Json | null)?.denom === DENOM) as Json | undefined;
  if (coin === undefined) return 0n;
  if (typeof coin.amount !== "string" || !/^\d{1,40}$/.test(coin.amount)) throw new Error("Unexpected balance amount.");
  return BigInt(coin.amount);
}
