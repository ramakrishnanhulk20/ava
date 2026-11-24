import { sweepUnverified } from "@ava/server";
import { runSweep } from "@/lib/server/cron";
import { json } from "@/lib/server/respond";

export const runtime = "nodejs";
export const maxDuration = 300;

export function GET(request: Request): Promise<Response> {
  return runSweep(request, "documents", async (app, now) =>
    json(200, await sweepUnverified({ blobs: app.blobs, store: app.store, blobOrigin: app.env.BLOB_ORIGIN, now })),
  );
}
