import "server-only";
import {
  UpstashStore,
  VercelBlobBackend,
  liveDemoChain,
  liveEnvelopeLogs,
  liveRelayer,
  liveSponsor,
  loadEnv,
  type BlobBackend,
  type DemoChain,
  type DemoContext,
  type DemoSweepContext,
  type EnvelopeLogs,
  type HandlerContext,
  type ServerEnv,
  type SharedStore,
} from "@ava/server";
import { after } from "next/server";

/** Everything the handlers share for the life of the process, as packages/server/scripts/dev-server.ts builds it at boot. */
export interface ServerApp {
  env: ServerEnv;
  store: SharedStore;
  blobs: BlobBackend;
  /** Undefined while RELAYER_MNEMONIC is unset: the relay and demo endpoints then answer 503. */
  relayer: Awaited<ReturnType<typeof liveRelayer>> | undefined;
  /** Undefined while SPONSOR_MNEMONIC is unset: the sponsor endpoint then answers 503. */
  sponsor: Awaited<ReturnType<typeof liveSponsor>> | undefined;
  demoChain: DemoChain;
  envelopeLogs: EnvelopeLogs;
}

async function build(): Promise<ServerApp> {
  const env = loadEnv(process.env);
  const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const blobs = new VercelBlobBackend(env.BLOB_READ_WRITE_TOKEN);
  const relayer = env.RELAYER_MNEMONIC === undefined ? undefined : await liveRelayer(env.RELAYER_MNEMONIC);
  const sponsor = env.SPONSOR_MNEMONIC === undefined ? undefined : await liveSponsor(env.SPONSOR_MNEMONIC);
  return { env, store, blobs, relayer, sponsor, demoChain: liveDemoChain(), envelopeLogs: liveEnvelopeLogs() };
}

// Next may load this module once per route bundle, and dev reloads re-run it, so the memo lives on
// globalThis to derive the role keys once per process, as the dev server does.
const holder = globalThis as typeof globalThis & { avaServerApp?: Promise<ServerApp> };

/**
 * The process's shared server state, built on first use. A failed build is forgotten, so the next
 * request tries again instead of the process failing for good, the way a restarted dev server would.
 *
 * @throws EnvError, naming keys and never values, when the settings are missing or malformed.
 */
export function serverApp(): Promise<ServerApp> {
  holder.avaServerApp ??= build().catch((error: unknown) => {
    holder.avaServerApp = undefined;
    throw error;
  });
  return holder.avaServerApp;
}

/**
 * The caller's IP as the host reports it (threat model C23). On Vercel that is x-real-ip, which
 * Vercel's edge writes over anything the caller sent. Anywhere else a local caller could set that
 * header, so no header is read and every caller counts as 127.0.0.1.
 */
function clientIp(request: Request): string {
  if (process.env.VERCEL === "1") return request.headers.get("x-real-ip") ?? "";
  return "127.0.0.1";
}

/** What every handler receives for one request. */
export function handlerBase(request: Request, app: ServerApp): HandlerContext {
  return { clientIp: clientIp(request), now: Date.now(), store: app.store };
}

/** Logged, never thrown at the join that scheduled it, as the dev server's runner does. */
const background = (work: () => Promise<unknown>): void => {
  after(async () => {
    try {
      await work();
    } catch {
      console.warn(JSON.stringify({ event: "background_failed" }));
    }
  });
};

/** The demo endpoints' context, or undefined while the relayer is not configured. */
export function demoContext(base: HandlerContext, app: ServerApp): DemoContext | undefined {
  if (app.relayer === undefined) return undefined;
  return { ...base, env: app.env, chain: app.demoChain, blobs: app.blobs, relayer: app.relayer.relayer, relayChain: app.relayer.chain, background };
}

/** The scheduled demo sweep's context: no caller, so no client IP; or undefined while the relayer is not configured. */
export function demoSweepContext(app: ServerApp, now: number): DemoSweepContext | undefined {
  if (app.relayer === undefined) return undefined;
  return { now, store: app.store, env: app.env, chain: app.demoChain, blobs: app.blobs, relayer: app.relayer.relayer, relayChain: app.relayer.chain };
}
