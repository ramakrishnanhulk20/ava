import { handleRelay } from "@ava/server";
import { handlerBase, serverApp } from "@/lib/server/context";
import { notConfigured, serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// The relay keeps its own 55 s deadline inside this.
export const maxDuration = 60;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    if (app.relayer === undefined) return notConfigured("RELAYER_MNEMONIC");
    return handleRelay(request, { ...handlerBase(request, app), ...app.relayer });
  });
}
