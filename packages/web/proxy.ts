import { NextResponse, type NextRequest } from "next/server";
import { contentSecurityPolicy, freshNonce } from "./lib/csp";

/**
 * Serves every page with a Content-Security-Policy built around a nonce made for that one response
 * (threat model C19). The policy also goes onto the request, which is where Next reads the nonce
 * it stamps on its own scripts while rendering.
 */
export function proxy(request: NextRequest): NextResponse {
  const nonce = freshNonce();
  const policy = contentSecurityPolicy({
    nonce,
    blobOrigin: process.env.NEXT_PUBLIC_BLOB_ORIGIN ?? "",
    dev: process.env.NODE_ENV === "development",
  });

  // Set, never appended: whatever the caller sent under these names is replaced.
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", policy);

  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", policy);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  return response;
}

export const config = {
  matcher: [
    {
      // Pages only. The API answers JSON, and the static files are the scripts and styles the policy already governs.
      source: "/((?!api/|_next/static|_next/image|favicon.ico|icon.svg|opengraph-image|twitter-image).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
