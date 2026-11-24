import { sweepDemoGuests } from "@ava/server";
import { demoSweepContext } from "@/lib/server/context";
import { runSweep } from "@/lib/server/cron";
import { json, notConfigured } from "@/lib/server/respond";

export const runtime = "nodejs";
export const maxDuration = 300;

export function GET(request: Request): Promise<Response> {
  return runSweep(request, "demo", async (app, now) => {
    const ctx = demoSweepContext(app, now);
    return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : json(200, await sweepDemoGuests(ctx));
  });
}
