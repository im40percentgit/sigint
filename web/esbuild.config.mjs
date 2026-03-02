import { build, context } from 'esbuild';
import { copyFileSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const watch = process.argv.includes('--watch');
const outdir = resolve(__dirname, '../crates/sigint-web/static/assets');

// Ensure output directories exist
mkdirSync(outdir, { recursive: true });
mkdirSync(resolve(__dirname, '../crates/sigint-web/static'), { recursive: true });

const buildOptions = {
  // Bundle both JS and CSS as separate entry points so esbuild emits app.css
  entryPoints: [
    resolve(__dirname, 'src/app.js'),
    resolve(__dirname, 'src/app.css'),
  ],
  bundle: true,
  outdir,
  minify: !watch,
  sourcemap: watch,
  format: 'esm',
  loader: { '.js': 'jsx' },
  jsxFactory: 'h',
  jsxFragment: 'Fragment',
  define: { 'process.env.NODE_ENV': watch ? '"development"' : '"production"' },
};

// Copy static files to output root
copyFileSync(
  resolve(__dirname, 'src/index.html'),
  resolve(__dirname, '../crates/sigint-web/static/index.html')
);

if (watch) {
  const ctx = await context(buildOptions);
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await build(buildOptions);
  console.log('Build complete → crates/sigint-web/static/');
}
