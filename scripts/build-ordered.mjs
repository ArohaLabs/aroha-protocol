// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Builds all workspace packages in topological dependency order.
 * npm workspaces --workspaces runs alphabetically, which breaks packages
 * that depend on other workspace packages whose dist/ doesn't exist yet.
 */
import { spawnSync } from "child_process";

// How to invoke npm for a child build.
//
// The obvious `spawnSync("npm.cmd", …, { shell: false })` is broken on Windows
// from Node 20.12/21 onward: spawning a .bat/.cmd without a shell now fails
// with EINVAL (the CVE-2024-27980 mitigation). spawnSync reports that as
// `status: null`, which the loop below then treats as a failed build — so
// `npm run build` exited 1 having built absolutely nothing, on every Windows
// machine, while CI stayed green because Linux invokes plain `npm`.
//
// When this script runs under npm (the normal path — `npm run build`), npm
// sets npm_execpath to its own npm-cli.js. Running that with the current Node
// binary sidesteps both the .cmd problem and the argument-escaping hazard that
// `shell: true` would reintroduce. The direct-invocation fallback
// (`node scripts/build-ordered.mjs`) still needs a shell on Windows.
const NPM_CLI = process.env.npm_execpath;
const VIA_NODE = Boolean(NPM_CLI);
const NPM = VIA_NODE ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
const NPM_PREFIX_ARGS = VIA_NODE ? [NPM_CLI] : [];
const NEEDS_SHELL = !VIA_NODE && process.platform === "win32";

const layers = [
  // Layer 0 — no inter-package dependencies
  ["packages/aroha-core", "packages/aroha-mcp-guard", "packages/aroha-trust",
   // Depends only on @noble — no Aroha package at all.
   "packages/aroha-bbs",
   // Depends only on @modelcontextprotocol/sdk — no Aroha package at all.
   "packages/aroha-gmail-mcp"],
  // Layer 1 — depends only on core
  [
    "packages/aroha-credentials",
    "packages/aroha-policy",
    "packages/aroha-telemetry",
    "packages/aroha-trusted-mesh",
    "packages/aroha-micro",
    "packages/aroha-run",
    "packages/aroha-evals",
    "packages/aroha-a2a-bridge",
    "packages/aroha-langchain-bridge",
    "packages/aroha-cache",
    "packages/aroha-registry",
    "packages/aroha-audit",
    "packages/aroha-chaos",
    "packages/aroha-resilience",
    "packages/aroha-openclaw-bridge",
    "packages/aroha-composio-bridge",
  ],
  // Layer 2 — depends on registry, credentials or run
  [
    "packages/aroha-mcp-bridge",
    "packages/aroha-preferences",
    "packages/aroha-cli",
    "packages/aroha-delegation",
    // Depends on core + credentials.
    "packages/aroha-mcp-server",
    // Depend on credentials only (durable stores for its interfaces).
    "packages/aroha-store-postgres",
    "packages/aroha-store-redis",
  ],
  // Layer 2b — depends on mcp-bridge
  [
    "packages/aroha-hermes-bridge",
  ],
  // Layer 2c — depends on aroha-cli
  [
    "packages/create-aroha-agent",
  ],
  // Reference provider agent for interoperability tests (core, credentials, registry)
  ["agents/mock-provider-agent"],
];

for (const layer of layers) {
  // Build "-w pkg1 -w pkg2 ..." as an argument array — no shell interpolation
  const workspaceArgs = layer.flatMap((p) => ["-w", p]);
  const result = spawnSync(
    NPM,
    [...NPM_PREFIX_ARGS, "run", "build", ...workspaceArgs, "--if-present"],
    { stdio: "inherit", shell: NEEDS_SHELL },
  );

  // A spawn that never ran reports status null with an error — surface that as
  // itself rather than as "the build failed", which is what sent an earlier
  // investigation looking for a TypeScript error that did not exist.
  if (result.error) {
    console.error(`Could not run npm for layer [${layer.join(", ")}]: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) process.exit(result.status ?? 1);
}
