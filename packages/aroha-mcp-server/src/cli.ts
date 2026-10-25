#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * aroha-mcp-server — run the Aroha MCP server.
 *
 *   aroha-mcp-server            stdio (Claude Desktop and other local clients)
 *   aroha-mcp-server --http     Streamable HTTP + OAuth resource server
 *
 * Configuration: environment variables and/or a JSON file named by
 * AROHA_MCP_CONFIG (see README.md). stdout is the MCP stream in stdio mode,
 * so all diagnostics go to stderr.
 */

import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { loadConfig, type TransportMode } from "./config.js";
import { FilePrincipalKeyStore, LOCAL_PRINCIPAL } from "./keystore.js";
import { createArohaMcpServer, createRuntime } from "./server.js";
import { startHttpServer } from "./http.js";

const argv = process.argv.slice(2);
const transport: TransportMode | undefined = argv.includes("--http") ? "http" : argv.includes("--stdio") ? "stdio" : undefined;

try {
  const config = loadConfig(process.env, transport ? { transport } : {});
  const runtime = createRuntime(config, new FilePrincipalKeyStore(config.keysDir));
  if (config.transport === "http") {
    const running = await startHttpServer({ runtime });
    const shutdown = () => { void running.close().finally(() => process.exit(0)); };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } else {
    // One local user: the pre-existing per-install key.
    serveStdio(() => createArohaMcpServer(runtime, LOCAL_PRINCIPAL), {
      onerror: (err) => process.stderr.write(`[aroha-mcp-server] ${err.message}\n`),
    });
  }
} catch (err) {
  process.stderr.write(`[aroha-mcp-server] ${(err as Error).message}\n`);
  process.exit(1);
}
