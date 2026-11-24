import "server-only";
import { createHash, timingSafeEqual } from "node:crypto";
import { serverApp, type ServerApp } from "./context";
import { refuse, serve } from "./respond";

const digest = (value: string): Buffer => createHash("sha256").update(value).digest();

/**
 * Whether the Authorization header is exactly `Bearer <CRON_SECRET>`, as Vercel cron sends it. An
 * unset or empty CRON_SECRET admits nobody, so "Bearer " or "Bearer undefined" never passes. Both
 * sides are hashed first so the comparison takes the same time whatever the header holds.
 */
function fromScheduler(request: Request): boolean {
  const secret = process.env.CRON_SECRET;
  const given = request.headers.get("authorization");
  if (secret === undefined || secret === "" || given === null) return false;
  return timingSafeEqual(digest(given), digest(`Bearer ${secret}`));
}

/**
 * Runs one scheduled sweep for a caller holding the cron secret, answering 401 `unauthorized`
 * before anything is built or read for any other caller.
 */
export function runSweep(request: Request, sweep: string, run: (app: ServerApp, now: number) => Promise<Response>): Promise<Response> {
  if (!fromScheduler(request)) {
    console.warn(JSON.stringify({ event: "cron_refused", sweep }));
    return Promise.resolve(refuse(401, "unauthorized"));
  }
  return serve(async () => run(await serverApp(), Date.now()));
}
