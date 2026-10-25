#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
/**
 * CLI entry point — called by Hermes Agent / ZeroClaw as an MCP subprocess.
 *
 * Hermes config:
 *   { "mcpServers": { "aroha": { "command": "npx", "args": ["@aroha-sdk/hermes-bridge", "--endpoint", "http://localhost:3000", "--agent-did", "did:aroha:travel-agent"] } } }
 *
 * ZeroClaw config (TOML):
 *   [[mcp_servers]]
 *   name = "aroha"
 *   command = "npx @aroha-sdk/hermes-bridge --endpoint http://localhost:3000 --agent-did did:aroha:travel-agent"
 */

import { fileURLToPath } from "url";
import { createHermesMcpServer } from "./bridge.js";

export async function startFromCli(): Promise<void> {
  const args = process.argv.slice(2);
  const get = (flag: string) => {
    const i = args.indexOf(flag);
    return i !== -1 ? args[i + 1] : undefined;
  };

  const endpoint = get("--endpoint");
  const agentDID = get("--agent-did");

  if (!endpoint || !agentDID) {
    process.stderr.write(
      "Usage: aroha-mcp-server --endpoint <url> --agent-did <did>\n"
    );
    process.exit(1);
  }

  try {
    const server = await createHermesMcpServer({ endpoint, agentDID });
    process.stderr.write(
      `[aroha-hermes-bridge] Connected to ${agentDID} — ${server.tools.length} capabilities registered as MCP tools\n`
    );
    await server.serve(process.stdin, process.stdout);
  } catch (err) {
    process.stderr.write(`[aroha-hermes-bridge] Fatal: ${err}\n`);
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startFromCli();
}
