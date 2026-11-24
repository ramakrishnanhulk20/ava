import { handleDemoLeaveChallenge } from "@ava/server";
import { demoContext, handlerBase, serverApp } from "@/lib/server/context";
import { notConfigured, serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// A body may take 20 s to arrive; the rest is a few shared store calls.
export const maxDuration = 30;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    const ctx = demoContext(handlerBase(request, app), app);
    return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoLeaveChallenge(request, ctx);
  });
}
