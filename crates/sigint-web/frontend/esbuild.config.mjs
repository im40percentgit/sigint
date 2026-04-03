/**
 * esbuild build configuration for SIGINT web UI.
 *
 * Bundles src/index.tsx → ../static/assets/app.js.
 * CSS imported in index.tsx is automatically extracted to ../static/assets/app.css
 * by esbuild when outfile is used (sibling file convention).
 *
 * Modes:
 *   node esbuild.config.mjs          → production (minified, no sourcemaps)
 *   node esbuild.config.mjs --watch  → watch mode (sourcemaps, not minified)
 */

import * as esbuild from "esbuild";
import { argv } from "process";

const isWatch = argv.includes("--watch");
const isProd = !isWatch;

/** @type {import('esbuild').BuildOptions} */
const config = {
  entryPoints: ["src/index.tsx"],
  bundle: true,
  outfile: "../static/assets/app.js",
  platform: "browser",
  target: ["es2020"],
  format: "esm",
  jsx: "automatic",
  jsxImportSource: "preact",
  minify: isProd,
  sourcemap: isWatch ? "inline" : false,
  // esbuild automatically generates app.css alongside app.js when CSS is imported
  loader: {
    ".css": "css",
  },
};

if (isWatch) {
  const ctx = await esbuild.context(config);
  await ctx.watch();
  console.log("Watching for changes...");
} else {
  const result = await esbuild.build(config);
  if (result.errors.length > 0) {
    console.error("Build errors:", result.errors);
    process.exit(1);
  }
  console.log("Build complete.");
}
