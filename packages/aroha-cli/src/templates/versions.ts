// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Dependency ranges written into scaffolded projects.
 *
 * The @aroha-sdk/* ranges MUST track the versions in this monorepo's
 * packages/<name>/package.json — templates.test.ts fails when they drift, so
 * bumping a package without updating this table breaks the CLI's tests, not
 * the user's freshly scaffolded project. @aroha-sdk/orchestrator is developed
 * in ArohaLabs/aroha-extensions; its pin lives in templates.test.ts.
 */
export const AROHA_SDK_RANGES = {
  "@aroha-sdk/core": "^2.0.0",
  "@aroha-sdk/credentials": "^2.0.0",
  "@aroha-sdk/registry": "^2.0.0",
  "@aroha-sdk/orchestrator": "^1.4.0",
  "@aroha-sdk/preferences": "^1.2.3",
  "@aroha-sdk/micro": "^2.0.0",
  "@aroha-sdk/mcp-bridge": "^3.0.0",
  "@aroha-sdk/a2a-bridge": "^2.0.0",
} as const;

export type ArohaSdkPackage = keyof typeof AROHA_SDK_RANGES;

/** Pick ranges for the named @aroha-sdk packages. */
export function sdkDeps(...names: ArohaSdkPackage[]): Record<string, string> {
  return Object.fromEntries(names.map((n) => [n, AROHA_SDK_RANGES[n]]));
}

/**
 * Toolchain ranges for generated projects. Node 22 is the floor everywhere
 * (engines, CLI doctor), so @types/node follows it; `tsx` runs TypeScript
 * directly in dev (ts-node's ESM loader is not maintained for Node 22).
 */
export const TOOLCHAIN = {
  typescript: "^5.4.5",
  "@types/node": "^22.0.0",
  tsx: "^4.19.0",
} as const;

export const NODE_ENGINE = ">=22";
