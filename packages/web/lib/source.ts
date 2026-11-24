import { loader } from "fumadocs-core/source";
import { defineDocs } from "fumadocs-mdx/macro";

const docs = defineDocs({
  dir: "content/docs",
});

/** The pages under /docs: MDX files in content/docs, read at build time. */
export const source = loader({
  baseUrl: "/docs",
  source: docs.toFumadocsSource(),
});
