#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Remove a package's build output before it is packed: `dist/` and any
// *.tsbuildinfo next to package.json. Run from the package directory (every
// package's `prepack` script is `node ../../scripts/clean-dist.mjs && tsc -p
// tsconfig.json`).
//
// WHY. `tsc` only ever ADDS files to dist/. A source file that was renamed or
// deleted — or a test that used to be compiled before tsconfig excluded
// tests — leaves its old .js/.d.ts behind, and `npm pack` ships whatever is
// in dist/. Published tarballs carried stale modules and compiled tests that
// way. Cleaning first makes every tarball exactly the current build.
//
// The tsbuildinfo matters for the same reason: with `composite`, tsc trusts
// it and skips emitting files it believes are up to date — after dist/ was
// deleted, that would produce an EMPTY package. (When outDir is set, tsc
// keeps it inside dist/, which this removes too; the root-level sweep covers
// configs that put it elsewhere.)
//
// Cross-platform on purpose (no `rm -rf`): packing happens on Windows too.

import { existsSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";

const pkgDir = resolve(process.argv[2] ?? process.cwd());
if (!existsSync(join(pkgDir, "package.json"))) {
  console.error(`clean-dist: ${pkgDir} has no package.json — refusing to delete anything`);
  process.exit(1);
}

rmSync(join(pkgDir, "dist"), { recursive: true, force: true });
for (const f of readdirSync(pkgDir)) {
  if (f.endsWith(".tsbuildinfo")) rmSync(join(pkgDir, f), { force: true });
}
