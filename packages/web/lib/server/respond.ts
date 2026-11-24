import "server-only";
import { EnvError } from "@ava/server";

// The same headers as packages/server/src/http.ts `json`, which the package does not export: JSON,
// nosniff, no caching, and no CORS header, so other sites' pages cannot read the answer.
export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-content-type-options": "nosniff", "cache-control": "no-store" },
  });
}

export function refuse(status: number, error: string): Response {
  return json(status, { error });
}

/** The dev server's answer for an endpoint whose account phrase is not set. */
export function notConfigured(key: string): Response {
  console.warn(JSON.stringify({ event: "not_configured", key }));
  return refuse(503, "not_configured");
}

/**
 * Runs one route's work and answers 500 `handler_failed` if it throws, as the dev server does, so
 * the app always gets JSON back. Only an EnvError's message is logged: it names keys and never
 * their values, while any other error could carry upstream text. Every error's class name is
 * logged too: it says what kind of failure it was and holds nothing a caller or an upstream wrote.
 */
export async function serve(run: () => Promise<Response>): Promise<Response> {
  try {
    return await run();
  } catch (error) {
    const kind = error instanceof Error ? error.constructor.name : typeof error;
    console.warn(JSON.stringify({ event: "handler_failed", kind, ...(error instanceof EnvError ? { reason: error.message } : {}) }));
    return refuse(500, "handler_failed");
  }
}
