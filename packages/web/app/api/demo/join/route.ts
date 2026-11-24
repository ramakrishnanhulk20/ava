import { handleDemoJoin } from "@ava/server";
import { demoContext, handlerBase, serverApp } from "@/lib/server/context";
import { notConfigured, serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// The join keeps its own 120 s deadline. A pressure pass it hands to after() shares this budget,
// and the scheduled sweep picks up whatever a cut-off pass leaves.
export const maxDuration = 300;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    const ctx = demoContext(handlerBase(request, app), app);
    return ctx === undefined ? notConfigured("RELAYER_MNEMONIC") : handleDemoJoin(request, ctx);
  });
}
