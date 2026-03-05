#!/usr/bin/env node
/**
 * ForgeAI Govern - Frontend Build Script
 *
 * Bundles ES module source files into browser-ready IIFE bundles using esbuild.
 * Usage: node build.js [--watch]
 */

const esbuild = require('esbuild');

const watch = process.argv.includes('--watch');

const buildOptions = {
  entryPoints: ['src/frontend/js/pages/index.js'],
  bundle: true,
  format: 'iife',
  outfile: 'src/frontend/js/pages.bundle.js',
  minify: process.env.NODE_ENV === 'production',
  sourcemap: process.env.NODE_ENV !== 'production',
  target: ['es2020'],
  logLevel: 'info',
};

async function build() {
  if (watch) {
    const ctx = await esbuild.context(buildOptions);
    await ctx.watch();
    console.log('Watching for changes...');
  } else {
    await esbuild.build(buildOptions);
  }
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
