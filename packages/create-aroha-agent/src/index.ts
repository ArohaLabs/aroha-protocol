#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * create-aroha-agent — zero-config npx scaffolder
 *
 * Usage:
 *   npx create-aroha-agent                          # agent named my-aroha-agent
 *   npx create-aroha-agent my-agent                 # scaffolds my-agent/
 *   npx create-aroha-agent my-agent --type orchestrator
 *   npx create-aroha-agent my-agent --port 4001
 *
 * To wrap an existing MCP server, use `npx @aroha-sdk/cli convert --from mcp`.
 */

import { createRequire } from "node:module";
import { runInit } from "@aroha-sdk/cli/commands/init";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

const args = process.argv.slice(2);

function flagValue(f: string): string | undefined {
  const i = args.indexOf(f);
  return i !== -1 ? args[i + 1] : undefined;
}

if (args.includes("--mcp")) {
  console.error(
    "--mcp is not supported. To wrap an existing MCP server as an Aroha agent, run:\n" +
      "  npx @aroha-sdk/cli convert --from mcp --endpoint <mcp-server-url>"
  );
  process.exit(1);
}

// First positional argument (not a flag or a flag's value) is the agent name.
const flagsWithValues = new Set(["--type", "--port"]);
const name = args.find((a, i) => !a.startsWith("--") && !flagsWithValues.has(args[i - 1] ?? ""));

const title = `create-aroha-agent  v${version}`;
const width = 49;
console.log("┌" + "─".repeat(width) + "┐");
console.log("│  " + title.padEnd(width - 2) + "│");
console.log("│  " + "The fastest way to start a new Aroha agent".padEnd(width - 2) + "│");
console.log("└" + "─".repeat(width) + "┘\n");

await runInit(name, {
  type: (flagValue("--type") as "provider" | "orchestrator" | undefined) ?? "provider",
  port: flagValue("--port") ? Number(flagValue("--port")) : undefined,
  yes: true,
});
