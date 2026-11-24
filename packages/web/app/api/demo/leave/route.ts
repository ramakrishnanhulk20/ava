import { handleDemoLeave } from "@ava/server";
import { demoContext, handlerBase, serverApp } from "@/lib/server/context";
import { notConfigured, serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// The leave keeps its own 120 s deadline. The pack post it hands to after() shares this budget,
// and the scheduled sweep posts it if that run is cut off.
export const maxDuration = 300;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    const ctx = demoContext(handlerBase(request, app), app);
    return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoLeave(request, ctx);
  });
}
