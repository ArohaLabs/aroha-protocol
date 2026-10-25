// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ Hermes Agent / ZeroClaw Bridge
 *
 * Hermes Agent (Nous Research) and ZeroClaw both support MCP servers as the
 * integration point for external tools. This bridge starts a stdio MCP server
 * that proxies calls through to one or more Aroha agents.
 *
 * Usage in hermes config (hermes.config.json):
 * {
 *   "mcpServers": {
 *     "aroha": {
 *       "command": "npx",
 *       "args": ["@aroha-sdk/hermes-bridge", "--endpoint", "http://localhost:3000", "--agent-did", "did:aroha:travel-agent"]
 *     }
 *   }
 * }
 *
 * Usage in ZeroClaw config:
 * [[mcp_servers]]
 * name = "aroha"
 * command = "npx @aroha-sdk/hermes-bridge --endpoint http://localhost:3000 --agent-did did:aroha:travel-agent"
 */

export { createHermesMcpServer, type HermesMcpServerOptions } from "./bridge.js";
export { startFromCli } from "./server.js";
