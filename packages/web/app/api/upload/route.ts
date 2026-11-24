import { handleUpload } from "@ava/server";
import { handlerBase, serverApp } from "@/lib/server/context";
import { serve } from "@/lib/server/respond";

export const runtime = "nodejs";
// A body may take 20 s to arrive, and the blob store write has no timeout of its own.
export const maxDuration = 60;

export function POST(request: Request): Promise<Response> {
  return serve(async () => {
    const app = await serverApp();
    return handleUpload(request, { ...handlerBase(request, app), blobs: app.blobs, blobOrigin: app.env.BLOB_ORIGIN });
  });
}
