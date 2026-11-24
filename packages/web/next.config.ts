import path from "node:path";
import { createMDX } from "fumadocs-mdx/next";
import type { NextConfig } from "next";

const config: NextConfig = {
  // A second folder for verification builds, so they never overwrite the dev server's cache.
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  // @ava/core and @ava/server ship TypeScript source, so Next has to compile them with the app.
  transpilePackages: ["@ava/core", "@ava/server"],
  // The dev badge would sit on top of the hero during design review.
  devIndicators: false,
  // @ava/core and @ava/server are links outside this folder. The bundler only follows links inside its root.
  turbopack: { root: path.resolve(import.meta.dirname, "../..") },
};

// The docs under /docs are MDX files in content/docs, compiled with the app.
export default createMDX()(config);
