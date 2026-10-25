// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `aroha create-bridge` — scaffold a standalone Aroha bridge package.
 *
 * Generates a ready-to-publish npm package implementing the Aroha bridge
 * pattern for any SDK, protocol, or REST API. The generated package follows
 * the same duck-typed, zero-hard-dependency pattern as @aroha-sdk/langchain-bridge.
 */

import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import {
  bridgePackageJson,
  bridgeTsConfig,
  bridgeIndexTs,
  bridgeTypesTs,
  bridgeMainTs,
  bridgeReadme,
} from "../templates/bridge.js";
import * as readline from "readline";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const prompt = (query: string): Promise<string> => {
  return new Promise((resolve) => rl.question(query, resolve));
};

export interface CreateBridgeOptions {
  name?: string;
  sdk?: string;
  out?: string;
  yes?: boolean;
}

export async function runCreateBridge(opts: CreateBridgeOptions): Promise<void> {
  const name =
    opts.name ??
    (await prompt("Bridge name (kebab-case, e.g. hubspot): ")).trim();

  const sdk =
    opts.sdk ??
    (await prompt(`SDK or protocol name (e.g. HubSpot, Salesforce, MyAPI): `)).trim();

  const outDir = opts.out ?? `aroha-${name}-bridge`;

  if (existsSync(outDir) && !opts.yes) {
    const overwrite = await prompt(`Directory "${outDir}" exists. Overwrite? [y/N] `);
    if (!overwrite.toLowerCase().startsWith("y")) {
      console.log("Aborted.");
      rl.close();
      return;
    }
  }

  rl.close();

  mkdirSync(join(outDir, "src"), { recursive: true });

  const files: [string, string][] = [
    ["package.json", bridgePackageJson(name, sdk)],
    ["tsconfig.json", bridgeTsConfig()],
    ["src/index.ts", bridgeIndexTs(name, sdk)],
    ["src/types.ts", bridgeTypesTs(name, sdk)],
    ["src/bridge.ts", bridgeMainTs(name, sdk)],
    ["README.md", bridgeReadme(name, sdk)],
  ];

  for (const [filePath, content] of files) {
    writeFileSync(join(outDir, filePath), content);
  }

  console.log(`
\x1b[32m✓\x1b[0m Bridge scaffolded at \x1b[1m${outDir}/\x1b[0m

Next steps:
  cd ${outDir}
  npm install
  # Edit src/bridge.ts — implement handleCapability() with your ${sdk} calls
  npm run build
  npm publish --access public

Then request a listing in the Aroha ecosystem registry — open an issue with
your package name and repo link at:
  https://github.com/ArohaLabs/aroha-spec/issues
`);
}
