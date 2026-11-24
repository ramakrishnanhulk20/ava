import { existsSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { VercelBlobBackend, handleUpload } from "../src/blob.ts";
import { liveRelayer } from "../src/chain/live.ts";
import { handleDemoChallenge, handleDemoJoin, handleDemoLeave, handleDemoLeaveChallenge, type DemoContext } from "../src/demo.ts";
import { liveDemoChain } from "../src/demoBoard.ts";
import { handleDocumentToken, handleDocumentVerify } from "../src/docupload.ts";
import { loadEnv } from "../src/env.ts";
import { refuse, type HandlerContext } from "../src/http.ts";
import { handleChainGet, handleChainPost } from "../src/proxy.ts";
import { handleRelay } from "../src/relay.ts";
import { handleSponsor, liveSponsor } from "../src/sponsor.ts";
import { UpstashStore } from "../src/store.ts";

// A local server for trying every handler against the live chain, the live shared store and the
// live blob store. Not for production: the app mounts these handlers itself, behind its host's
// own body limits, timeouts and client IP.

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
const HOST = "127.0.0.1";
const PORT = 8787;
const CHAIN_MOUNT = "/api/chain";

if (existsSync(ENV_PATH)) process.loadEnvFile(ENV_PATH);
const env = loadEnv();
const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
const blobs = new VercelBlobBackend(env.BLOB_READ_WRITE_TOKEN);
const relayer = env.RELAYER_MNEMONIC === undefined ? undefined : await liveRelayer(env.RELAYER_MNEMONIC);
const sponsor = env.SPONSOR_MNEMONIC === undefined ? undefined : await liveSponsor(env.SPONSOR_MNEMONIC);
const demoChain = liveDemoChain();

type Handler = (request: Request, base: HandlerContext) => Promise<Response>;

const notConfigured = (key: string): Response => {
  console.warn(JSON.stringify({ event: "dev_not_configured", key }));
  return refuse(503, "not_configured");
};

/**
 * Runs a join's background work, the demo board's pressure pass, after the join has answered, as
 * Next.js `after` does in the app. Fire and forget: a failure is logged, never thrown at the join.
 */
const background = (work: () => Promise<unknown>): void => {
  void Promise.resolve()
    .then(work)
    .catch(() => console.warn(JSON.stringify({ event: "dev_background_failed" })));
};

const demo = (base: HandlerContext): DemoContext | undefined =>
  relayer === undefined ? undefined : { ...base, env, chain: demoChain, blobs, relayer: relayer.relayer, relayChain: relayer.chain, background };

const ROUTES: ReadonlyMap<string, Handler> = new Map<string, Handler>([
  ["/api/upload", (request, base) => handleUpload(request, { ...base, blobs, blobOrigin: env.BLOB_ORIGIN })],
  ["/api/document/token", (request, base) => handleDocumentToken(request, { ...base, blobs, env })],
  ["/api/document/verify", (request, base) => handleDocumentVerify(request, { ...base, blobs, env })],
  ["/api/relay", async (request, base) => (relayer === undefined ? notConfigured("RELAYER_MNEMONIC") : handleRelay(request, { ...base, ...relayer }))],
  ["/api/sponsor", async (request, base) => (sponsor === undefined ? notConfigured("SPONSOR_MNEMONIC") : handleSponsor(request, { ...base, ...sponsor }))],
  [
    "/api/demo/challenge",
    async (request, base) => {
      const ctx = demo(base);
      return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoChallenge(request, ctx);
    },
  ],
  [
    "/api/demo/join",
    async (request, base) => {
      const ctx = demo(base);
      return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoJoin(request, ctx);
    },
  ],
  [
    "/api/demo/leave/challenge",
    async (request, base) => {
      const ctx = demo(base);
      return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoLeaveChallenge(request, ctx);
    },
  ],
  [
    "/api/demo/leave",
    async (request, base) => {
      const ctx = demo(base);
      return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoLeave(request, ctx);
    },
  ],
]);

function route(pathname: string, method: string): Handler | undefined {
  if (pathname.startsWith(`${CHAIN_MOUNT}/`)) {
    const proxy = method === "POST" ? handleChainPost : handleChainGet;
    return (request, base) => proxy(request, { ...base, upstream: env.REST_UPSTREAM, mount: CHAIN_MOUNT });
  }
  return ROUTES.get(pathname);
}

/** The node request as a web Request, its body streamed so every handler's own byte cap applies while reading. */
function toRequest(req: IncomingMessage): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(name, value);
    else if (Array.isArray(value)) for (const v of value) headers.append(name, v);
  }
  const method = req.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? (Readable.toWeb(req) as ReadableStream<Uint8Array>) : undefined;
  return new Request(`http://${HOST}:${PORT}${req.url ?? "/"}`, { method, headers, body, duplex: "half" } as RequestInit);
}

async function serve(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // The socket's own address, never a header the client sets (threat model C23).
  const base: HandlerContext = { clientIp: req.socket.remoteAddress ?? "", now: Date.now(), store };
  const request = toRequest(req);
  const handler = route(new URL(request.url).pathname, request.method);
  let response: Response;
  try {
    response = handler === undefined ? refuse(404, "not_found") : await handler(request, base);
  } catch {
    console.warn(JSON.stringify({ event: "dev_handler_failed" }));
    response = refuse(500, "handler_failed");
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(bytes);
  console.log(`${request.method} ${new URL(request.url).pathname} ${response.status}`);
}

const server = createServer((req, res) => {
  serve(req, res).catch(() => {
    res.statusCode = 500;
    res.end();
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Ava dev server on http://${HOST}:${PORT}, against the live testnet, shared store and blob store. Not for production.`);
  console.log(`  GET, POST ${CHAIN_MOUNT}/...        chain REST proxy`);
  console.log("  POST /api/upload?kind=envelope   envelope upload");
  console.log("  POST /api/document/token         document upload token");
  console.log("  POST /api/document/verify        document verify");
  console.log(`  POST /api/relay                  relay${relayer === undefined ? " (503: RELAYER_MNEMONIC not set)" : ""}`);
  console.log(`  POST /api/sponsor                sponsor${sponsor === undefined ? " (503: SPONSOR_MNEMONIC not set)" : ""}`);
  console.log(`  POST /api/demo/challenge         demo guest challenge${env.DEMO_BOARD_ID === undefined ? " (503 not_ready until DEMO_BOARD_ID is set)" : ""}`);
  console.log(`  POST /api/demo/join              demo guest join${env.DEMO_BOARD_ID === undefined ? " (503 not_ready until DEMO_BOARD_ID is set)" : ""}`);
  console.log(`pid ${process.pid}`);
});
