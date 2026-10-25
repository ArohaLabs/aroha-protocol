// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Quickstart — Claude-backed agent
 *
 * The fastest path from zero to a Hub-registered AI agent.
 *
 * Prerequisites:
 *   export ANTHROPIC_API_KEY="sk-ant-..."
 *   export AROHA_API_KEY="ak-..."      # from aroha-labs.com/keys
 *
 * Run (local, loopback only — no request auth, see "Auth" below):
 *   npx tsx agent.ts
 *
 * Deploy (reachable from other machines — request auth is switched on):
 *   HOST=0.0.0.0 AROHA_BEARER_TOKEN=<long random secret> npx tsx agent.ts
 *
 * Register on the Hub (after deploying to a public URL). The registry only
 * registers a DID whose key the caller proves it holds, so registration needs
 * the agent's DID, its manifest CID and its Ed25519 seed:
 *   export AGENT_DID="did:aroha:..."
 *   export AROHA_MANIFEST_CID="bafy..."
 *   export AGENT_PRIVATE_KEY_HEX="<64 hex chars>"
 *   npx tsx agent.ts --register --endpoint https://my-agent.fly.dev
 *
 * The registry defaults to the Aroha-managed one; set AROHA_REGISTRY_URL to
 * use another.
 */

import { serve, createClaudeHandler } from "@aroha-sdk/run";

// ── 1. Build the handler ────────────────────────────────────────────────────
//
// createClaudeHandler wires Anthropic streaming → Aroha typed SSE events.
// The handler is an async generator: you get token | tool_call | final events
// without writing any streaming boilerplate.

const handler = createClaudeHandler({
  apiKey:      process.env.ANTHROPIC_API_KEY,
  model:       "claude-sonnet-4-6",
  systemPrompt: `You are a helpful, concise assistant registered on the Aroha Protocol.
You respond in plain text. Keep answers under 3 sentences unless asked for more detail.`,
});

// ── 2. Serve ────────────────────────────────────────────────────────────────
//
// serve() wraps the handler in a full HTTP server exposing:
//   POST /v1/run                        — invoke (stream: true for SSE)
//   POST /v1/resume                     — resolve a HITL approval
//   POST /mcp                           — MCP JSON-RPC (tools/list, tools/call)
//   GET  /health                        — liveness probe
//   GET  /.well-known/aroha-agent.json  — manifest

//
// Auth: serve() requires signed requests by default. On loopback (the default
// bind address) this quickstart turns auth off so you can try it with curl —
// DEMO-ONLY: nothing but this machine can reach a 127.0.0.1 listener. Once
// HOST widens the bind address, requests must carry AROHA_BEARER_TOKEN (if
// set) or an Aroha request signature. Never deploy with auth: "none" — anyone
// who reaches the agent would spend your Anthropic credits.

const host = process.env.HOST ?? "127.0.0.1";
const loopback = ["127.0.0.1", "::1", "localhost"].includes(host);
if (!loopback) console.warn(`HOST=${host} — the agent is reachable from other machines; request auth is on`);

const agent = serve("Quickstart Agent", handler, {
  description: "A simple Claude-backed agent registered on the Aroha Hub.",
  provider:    "anthropic",
  model:       "claude-sonnet-4-6",
  memory:      "session",   // automatically persists conversation history
  exposeMcp:   true,        // compatible with Claude Desktop and any MCP client
  auth:        loopback ? "none" : process.env.AROHA_BEARER_TOKEN ? "bearer" : "aroha-sig",
  host,
});

// ── 3. Start ────────────────────────────────────────────────────────────────

const port = Number(process.env.PORT ?? 8000);

// Handle --register flag
const args = process.argv.slice(2);
const registerIdx = args.indexOf("--register");
const endpointIdx = args.indexOf("--endpoint");

if (registerIdx !== -1) {
  const endpointUrl = endpointIdx !== -1 ? args[endpointIdx + 1] : undefined;
  if (!endpointUrl) {
    console.error("Usage: tsx agent.ts --register --endpoint https://my-agent.example.com");
    process.exit(1);
  }
  const apiKey = process.env.AROHA_API_KEY;
  if (!apiKey) {
    console.error("Set AROHA_API_KEY env var — get one at aroha-labs.com/keys");
    process.exit(1);
  }
  const did = process.env.AGENT_DID;
  const manifestCID = process.env.AROHA_MANIFEST_CID;
  const seedHex = process.env.AGENT_PRIVATE_KEY_HEX?.trim() ?? "";
  if (!did || !manifestCID || !/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    console.error("Set AGENT_DID, AROHA_MANIFEST_CID and AGENT_PRIVATE_KEY_HEX (64 hex chars) to register");
    process.exit(1);
  }
  const privateKey = new Uint8Array(Buffer.from(seedHex, "hex"));
  agent.register(endpointUrl, { apiKey, did, manifestCID, privateKey }).then((result) => {
    console.log("✓ Registered on the Aroha Hub");
    console.log("  DID:     ", result.did);
    console.log("  didHash: ", result.didHash);
    console.log("  Hub URL: ", `https://aroha-labs.com/hub/${result.didHash}`);
    process.exit(0);
  }).catch((err) => {
    console.error("Registration failed:", err.message);
    process.exit(1);
  });
} else {
  agent.start(port);
}
