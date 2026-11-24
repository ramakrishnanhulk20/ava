import { handleDocumentVerify } from "@ava/server";
import { handlerBase, serverApp } from "@/lib/server/context";
import { serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// A body may take 20 s to arrive, the read back 30 s and a delete 10 s.
export const maxDuration = 60;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    return handleDocumentVerify(request, { ...handlerBase(request, app), blobs: app.blobs, env: app.env });
  });
}
