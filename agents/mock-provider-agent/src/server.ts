// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mock Provider Agent — Entry Point (Tier 3: Application)
 *
 * Boots a Aroha-compliant provider agent using the @aroha-sdk/core transport server.
 * Demonstrates the minimal setup needed to run a provider agent:
 *
 *   1. Generate (or load) an Ed25519 keypair + DID
 *   2. Build the capability manifest
 *   3. Start the ArohaServer with a message handler
 *
 * The ArohaServer (protocol infrastructure) handles:
 *   - Serving the DID Document at /.well-known/aroha-agent.json
 *   - Validating all inbound message signatures, nonces, and expiry
 *   - Dispatching validated messages to our handler
 *
 * Our handler (application logic) decides what to DO with each message.
 */

import { createServer as createHttpServer } from "node:http";
import { ArohaServer } from "@aroha-sdk/core";
import { ArohaRole, createRbacMiddleware } from "@aroha-sdk/credentials";
import { handleMessage } from "./handlers.js";
import { loadIdentity, resolveEndpoint, resolveListenHost } from "./startup.js";

const PORT = parseInt(process.env.PORT ?? "3001");
const AGENT_ID = process.env.AGENT_ID ?? "mock-flight-provider";
const LOG = "[MockProvider]";
// Published in the DID document; required outside NODE_ENV=development (startup.ts).
const ENDPOINT = resolveEndpoint(["AGENT_ENDPOINT"], `http://localhost:${PORT}/aroha/v1`, LOG);

// Module-level state so that test harness functions can mutate it after startup.
const knownPublicKeys = new Map<string, Uint8Array>();
const agentRoles = new Map<string, ArohaRole[]>();

/** Register a peer's public key so the server will accept messages from it. */
export function registerPeer(did: string, pubKey: Uint8Array): void {
  knownPublicKeys.set(did, pubKey);
}

/** Grant an agent the orchestrator role so it can initiate sagas. */
export function registerOrchestrator(did: string): void {
  agentRoles.set(did, [ArohaRole.AgentOrchestrator]);
  console.log(`[MockProvider] Registered orchestrator: ${did}`);
}

/** Resolved agent identity — available after main() completes. */
export let agentIdentity: Awaited<ReturnType<typeof loadIdentity>> | null = null;

async function main() {
  // 1. Load identity — AGENT_PRIVATE_KEY_HEX / AGENT_PRIVATE_KEY_FILE for a
  // persistent key peers can pin; otherwise an ephemeral one (with a warning).
  const identity = await loadIdentity(AGENT_ID, ENDPOINT, LOG);
  agentIdentity = identity;
  console.log(`[MockProvider] DID: ${identity.did}`);

  // 2. Seed known keys with own identity; additional peers added via registerPeer()
  knownPublicKeys.set(identity.did, identity.publicKey);
  agentRoles.set(identity.did, [ArohaRole.AgentProvider]);

  // 3. Start Aroha server
  const server = new ArohaServer({
    agentDID: identity.did,
    didDocument: identity.document,
    port: PORT,
    // AGENT_HOST, default 127.0.0.1 (loopback). Set 0.0.0.0 explicitly to
    // serve other machines; startup.ts logs a warning when it is not loopback.
    host: resolveListenHost(LOG),
    resolvePublicKey: async (senderDID) => knownPublicKeys.get(senderDID) ?? null,
    middleware: [
      createRbacMiddleware({
        resolveAgentRoles: async (did) => agentRoles.get(did) ?? [],
        resolveIssuerPublicKey: async (issuerDID) => knownPublicKeys.get(issuerDID) ?? null,
      }),
    ],
    onMessage: async (envelope, respond, _stream) => {
      const reply = await handleMessage(envelope, identity.did, identity.privateKey);
      respond(reply);
    },
  });

  await server.start();

  console.log(`[MockProvider] Agent ready at ${ENDPOINT}`);
  console.log(`[MockProvider] DID Document: http://localhost:${PORT}/.well-known/aroha-agent.json`);
}

/**
 * Web2-friendly reputation sidecar — GET /api/v1/reputation/:did
 *
 * Reads the on-chain ArohaReputation score and exposes it as a plain REST
 * endpoint so any HTTP client can check an agent's track record without
 * touching the blockchain directly.
 *
 * In production this proxies to ArohaReputation.sol via ethers.js.
 * In development it returns a realistic simulated score.
 */
const REP_PORT = parseInt(process.env.REP_PORT ?? "3002");
// Loopback by default: this is an unauthenticated dev sidecar. REP_HOST widens it.
const REP_HOST = process.env.REP_HOST ?? "127.0.0.1";

function startReputationApi(): void {
  const server = createHttpServer((req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");

    const match = req.url?.match(/^\/api\/v1\/reputation\/(.+)$/);
    if (!match) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: "Not found. Use GET /api/v1/reputation/:did" }));
      return;
    }

    const did = decodeURIComponent(match[1]);

    // In production: query ArohaReputation.sol getScore(keccak256(did))
    // For local dev, derive a stable mock score from the DID string so the
    // same DID always returns the same number (useful for demo reproducibility).
    const seed = did.split("").reduce((acc, ch) => acc + ch.charCodeAt(0), 0);
    const score = 5000 + (seed % 5000);          // 5000–9999
    const maxScore = 10000;
    const grade =
      score >= 9000 ? "A" :
      score >= 7500 ? "B" :
      score >= 6000 ? "C" :
      score >= 4000 ? "D" : "F";

    const payload = {
      did,
      score,
      maxScore,
      grade,
      successCount: Math.floor(score / 60),
      failureCount: Math.floor((maxScore - score) / 500),
      lastUpdated: Date.now() - 3_600_000,
      source: "ArohaReputation.sol (simulated — connect Anvil for live data)",
    };

    res.writeHead(200);
    res.end(JSON.stringify(payload, null, 2));
  });

  server.listen(REP_PORT, REP_HOST, () => {
    console.log(`[MockProvider] Reputation API: http://${REP_HOST}:${REP_PORT}/api/v1/reputation/:did`);
  });
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});
startReputationApi();
