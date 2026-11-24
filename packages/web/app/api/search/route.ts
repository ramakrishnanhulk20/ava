import { createFromSource } from "fumadocs-core/search/server";
import { source } from "@/lib/source";

// The docs search index: built from the pages in content/docs and nothing else. It reads no chain
// data, no store and nothing about a visitor, which is why it is the one route that answers without
// the `x-ava` header the other routes require (threat model C23).
const search = createFromSource(source, {
  language: "english",
});

/** Longer than any phrase a reader types. A longer query gets the empty answer without a search being run. */
const MAX_QUERY_CHARACTERS = 100;

export function GET(request: Request): Response | Promise<Response> {
  const query = new URL(request.url).searchParams.get("query") ?? "";
  if (query.length > MAX_QUERY_CHARACTERS) {
    return new Response("[]", { status: 200, headers: { "content-type": "application/json", "x-content-type-options": "nosniff", "cache-control": "no-store" } });
  }
  return search.GET(request);
}
