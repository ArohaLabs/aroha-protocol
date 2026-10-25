// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { defineConfig } from "vitest/config";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { readdirSync, existsSync, readFileSync } from "fs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const packagesDir = resolve(ROOT, "packages");

/** Resolve one exports-map value (string, or {import: "..."}) to a relative path, or null if unresolvable. */
function exportTarget(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (value && typeof value === "object" && "import" in value && typeof (value as { import: unknown }).import === "string") {
    return (value as { import: string }).import;
  }
  return null;
}

// Build resolve.alias for every workspace package's exports map, not just its
// root ("."`) entry — a package with subpath exports (e.g. @aroha-sdk/core's
// "./crypto") needs one alias per subpath, or an import of that subpath falls
// through to real module resolution and can fail when the importing file is
// itself a transitively-loaded, already-compiled dist/*.js file (observed:
// packages/aroha-settlement/dist/escrow.js importing "@aroha-sdk/core/crypto"
// resolved fine under plain Node run directly but not under Vitest's
// resolution pipeline here). Aliasing gives Vite an absolute file path
// instead of a bare module specifier, bypassing the workspace symlink +
// exports-map resolution chain that can fail on Windows paths-with-spaces
// when packages are imported transitively (e.g. orchestrator → core, not
// directly from the test file).
//
// Array form with anchored RegExp `find` values, not a plain object — Vite's
// alias resolution (via @rollup/plugin-alias) treats a plain string `find`
// as EITHER an exact match OR a match for anything starting with
// `${find}/`, meaning the root entry "@aroha-sdk/core" would ALSO catch
// "@aroha-sdk/core/crypto" before the more specific subpath entry ever got
// consulted, rewriting it to the nonsensical "<dist/index.js path>/crypto".
// This was the actual root cause of the ERR_MODULE_NOT_FOUND above — adding
// a subpath entry to a plain object alone did not fix it, since the root
// entry kept winning. `^...$`-anchored regexes make every entry exact-match
// only, so the specific subpath entry always wins over the root one.
const workspaceAliases: Array<{ find: RegExp; replacement: string }> = [];
for (const dir of readdirSync(packagesDir)) {
  if (!dir.startsWith("aroha-")) continue;
  const pkgJsonPath = resolve(packagesDir, dir, "package.json");
  if (!existsSync(pkgJsonPath)) continue;
  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8")) as { exports?: Record<string, unknown> };
  const pkgName = "@aroha-sdk/" + dir.replace(/^aroha-/, "");

  if (pkgJson.exports) {
    for (const [subpath, value] of Object.entries(pkgJson.exports)) {
      const target = exportTarget(value);
      if (!target) continue;
      const absTarget = resolve(packagesDir, dir, target);
      if (!existsSync(absTarget)) continue;
      const specifier = subpath === "." ? pkgName : pkgName + subpath.slice(1);
      workspaceAliases.push({
        find: new RegExp(`^${specifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
        replacement: absTarget,
      });
    }
  } else {
    // No exports map declared — fall back to the package's dist/index.js.
    const distIndex = resolve(packagesDir, dir, "dist", "index.js");
    if (existsSync(distIndex)) {
      workspaceAliases.push({
        find: new RegExp(`^${pkgName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`),
        replacement: distIndex,
      });
    }
  }
}

/**
 * Conformance-only vitest config — used exclusively by the conformance workflow.
 *
 * Invoked as: npx vitest run --config vitest.conformance.config.ts
 *
 * Named with a non-default filename so Vitest does NOT auto-load it when
 * individual workspace packages run their own `vitest run` scripts.
 * Without this, individual package test runs would inherit this config's
 * narrow `include` pattern and report "No test files found" for unit tests.
 */
export default defineConfig({
  resolve: {
    alias: workspaceAliases,
  },
  test: {
    include: [
      "packages/*/src/**/*.conformance.test.ts",
      "packages/*/src/**/*.conformance.spec.ts",
    ],
    globals: false,
    environment: "node",
    // Increase timeout for saga tests that simulate timeouts
    testTimeout: 15_000,
    server: {
      deps: {
        // By default Vitest externalizes workspace packages (they resolve
        // through node_modules) and hands them to Node's native loader,
        // which never consults `resolve.alias` above — so a package like
        // aroha-settlement's escrow.ts, which imports the SUBPATH
        // "@aroha-sdk/core/crypto", fails to resolve when loaded
        // transitively (orchestrator → credentials → ... → settlement),
        // even though the same import resolves fine under plain Node run
        // directly and even though the direct "@aroha-sdk/core" root
        // import (no subpath) works fine here. Inlining forces Vite's own
        // resolver — and therefore the aliases above — to apply
        // consistently through the whole transitive chain, not just for
        // imports written directly in a test file.
        inline: [/^@aroha-sdk\//],
      },
    },
    // Allow TypeScript path aliases from each package's tsconfig
    typecheck: {
      enabled: false,
    },
  },
});
