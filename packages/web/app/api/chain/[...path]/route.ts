import { handleChainGet, handleChainPost } from "@ava/server";
import { handlerBase, serverApp } from "@/lib/server/context";
import { serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// A body may take 20 s to arrive and the upstream call 8 s more.
export const maxDuration = 30;

const MOUNT = "/api/chain";

export function GET(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    return handleChainGet(request, { ...handlerBase(request, app), upstream: app.env.REST_UPSTREAM, mount: MOUNT });
  });
}

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    return handleChainPost(request, { ...handlerBase(request, app), upstream: app.env.REST_UPSTREAM, mount: MOUNT });
  });
}
