// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Guard: the `./sar` and `./personal-name` subpaths stay bundleable for the
// Cloudflare Workers runtime.
//
// WHY THIS TEST EXISTS. apps/registry-server (a Worker) used to carry its own
// copies of sar.ts and personal-name.ts, because importing them from this
// package dragged in the `@aroha-sdk/core` barrel — and through its transport
// module `ws`/`undici`, and through those `fs`, `http`, `path` and
// `string_decoder` — so `wrangler deploy` could not bundle it. The copies had
// to be kept byte-for-byte in step with the reference implementation by
// pinning tests, which is exactly the kind of duplication that drifts. The
// fix was at the source: these two modules import only the Worker-safe core
// subpaths (`@aroha-sdk/core/identity`, `@aroha-sdk/core/crypto`), and the
// server imports them directly.
//
// Nothing about that is visible in a type check or a unit test run under
// Node, where every built-in resolves. One innocent "import { x } from
// '@aroha-sdk/core'" would silently re-break the Worker deploy. So this test
// bundles each subpath's source with esbuild for a platform that has NO Node
// built-ins (platform "neutral", the conditions wrangler resolves with) and
// fails naming every built-in that became reachable, and the path to it.
//
// The test bundles src/, not dist/: it guards the import graph, which is the
// same in both, and does not need this package built first (core's dist is
// needed, as for every other test here). The exports-map assertion below
// pins that the published subpaths ARE these files.

import { describe, it, expect } from "vitest";
import { createRequire, builtinModules } from "node:module";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgRoot = join(here, "..");

// esbuild is not a declared dependency of this package; it is vite's, and
// vitest (which is running this file) cannot run without vite. Resolving it
// THROUGH vite makes that dependency explicit instead of relying on hoisting.
const requireHere = createRequire(import.meta.url);
const requireFromVite = createRequire(requireHere.resolve("vite"));
const esbuild = requireFromVite("esbuild") as typeof import("esbuild");

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

interface Reached {
  builtin: string;
  importer: string;
}

/**
 * Bundle `entry` for a runtime with no Node built-ins. Built-in imports are
 * recorded (and marked external so the build can finish and report them
 * all) rather than failing on the first one.
 */
async function nodeBuiltinsReachableFrom(entry: string): Promise<{ reached: Reached[]; bytes: number }> {
  const reached: Reached[] = [];
  const result = await esbuild.build({
    entryPoints: [entry],
    bundle: true,
    write: false,
    format: "esm",
    platform: "neutral",
    // What wrangler resolves package exports with for a Worker; "neutral"
    // alone sets no main fields, which would fail on main-only packages.
    conditions: ["workerd", "worker", "browser", "import", "default"],
    mainFields: ["module", "main"],
    logLevel: "silent",
    plugins: [
      {
        name: "record-node-builtins",
        setup(build) {
          build.onResolve({ filter: /.*/ }, (args) => {
            const bare = args.path.startsWith("node:") ? args.path : args.path.split("/")[0];
            if (BUILTINS.has(args.path) || BUILTINS.has(bare)) {
              reached.push({ builtin: args.path, importer: args.importer });
              return { path: args.path, external: true };
            }
            return undefined;
          });
        },
      },
    ],
  });
  const bytes = result.outputFiles.reduce((n, f) => n + f.contents.byteLength, 0);
  return { reached, bytes };
}

describe("Worker-safe subpaths", () => {
  it("the exports map publishes ./sar and ./personal-name from the guarded modules", () => {
    // Each subpath is a conditions object ({ types, import, default }) so
    // TypeScript resolves the .d.ts and runtimes the guarded .js.
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as {
      exports: Record<string, { types: string; import: string; default: string }>;
    };
    expect(pkg.exports["./sar"]).toEqual({ types: "./dist/sar.d.ts", import: "./dist/sar.js", default: "./dist/sar.js" });
    expect(pkg.exports["./personal-name"]).toEqual({
      types: "./dist/personal-name.d.ts", import: "./dist/personal-name.js", default: "./dist/personal-name.js",
    });
  });

  it.each(["sar.ts", "personal-name.ts"])("src/%s reaches no Node built-in", async (file) => {
    const { reached, bytes } = await nodeBuiltinsReachableFrom(join(here, file));
    expect(reached, `Node built-ins reachable from ${file}: ${JSON.stringify(reached, null, 2)}`).toEqual([]);
    expect(bytes).toBeGreaterThan(0);
  });

  // The guard is only worth something if it can fail. The core barrel is the
  // exact import that broke the Worker bundle; it must be caught here.
  it("catches the @aroha-sdk/core barrel (the regression this guards against)", async () => {
    const { reached } = await nodeBuiltinsReachableFrom(requireHere.resolve("@aroha-sdk/core"));
    expect(reached.length).toBeGreaterThan(0);
  });
});
