import { handleDocumentToken } from "@ava/server";
import { handlerBase, serverApp } from "@/lib/server/context";
import { serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// A body may take 20 s to arrive and the blob store lookup 10 s more.
export const maxDuration = 30;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    return handleDocumentToken(request, { ...handlerBase(request, app), blobs: app.blobs, env: app.env });
  });
}
