import { sweepUnreferencedEnvelopes } from "@ava/server";
import { runSweep } from "@/lib/server/cron";
import { json } from "@/lib/server/respond";

export const runtime = "nodejs";
export const maxDuration = 300;

export function GET(request: Request): Promise<Response> {
  return runSweep(request, "envelopes", async (app, now) =>
    json(200, await sweepUnreferencedEnvelopes({ blobs: app.blobs, store: app.store, now, logs: app.envelopeLogs })),
  );
}
