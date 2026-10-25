// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha provider agent on Vercel Serverless Functions.
 *
 * vercel.json rewrites /aroha/v1 and /.well-known/aroha-agent.json to this
 * function (api/aroha.ts). Every request is a signed ArohaEnvelope — no
 * long-running process needed.
 *
 * Environment variables (Vercel project settings):
 *   AROHA_AGENT_DID          did:aroha:<your-agent-id>
 *   AROHA_PRIVATE_KEY        base64 of the 32-byte Ed25519 private key (seed)
 *   ORCHESTRATOR_DID         DID of the orchestrator allowed to call this agent
 *   ORCHESTRATOR_PUBLIC_KEY  base64 of that orchestrator's 32-byte Ed25519 public key
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  validateEnvelope,
  buildEnvelope,
  NonceRegistry,
  ArohaErrorCode,
  type ArohaEnvelope,
  type ArohaRequestBody,
  type ArohaResponseBody,
} from "@aroha-sdk/core";

// ─── Agent identity ────────────────────────────────────────────────────────────

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "";
const PRIVATE_KEY = Uint8Array.from(Buffer.from(process.env.AROHA_PRIVATE_KEY ?? "", "base64"));

// In-process nonce registry: it does not survive across function instances.
// For production, back replay protection with shared storage (e.g. Redis).
const nonceRegistry = new NonceRegistry();

// ─── Public key resolver ──────────────────────────────────────────────────────
// Replace with a registry lookup (@aroha-sdk/registry) when you have more peers.

async function resolvePublicKey(senderDID: string): Promise<Uint8Array | null> {
  const orchestratorDid = process.env.ORCHESTRATOR_DID;
  const orchestratorKey = process.env.ORCHESTRATOR_PUBLIC_KEY;
  if (orchestratorDid && orchestratorKey && senderDID === orchestratorDid) {
    return Uint8Array.from(Buffer.from(orchestratorKey, "base64"));
  }
  return null;
}

// ─── Capability handlers ──────────────────────────────────────────────────────

const handlers: Record<string, (params: Record<string, unknown>) => Promise<Record<string, unknown>>> = {
  "hello-world": async (params) => ({
    message: `Hello from Vercel! You said: ${JSON.stringify(params)}`,
    timestamp: new Date().toISOString(),
  }),
  // Add your capabilities here:
  // "search-products": async (params) => { ... },
};

// ─── Handler ──────────────────────────────────────────────────────────────────

export default async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  if (!AGENT_DID || PRIVATE_KEY.length !== 32) {
    res.status(500).json({ error: "Set AROHA_AGENT_DID and AROHA_PRIVATE_KEY (base64, 32 bytes)" });
    return;
  }

  // Serve the agent document
  if (req.method === "GET" && req.url?.endsWith("/.well-known/aroha-agent.json")) {
    res.status(200).json({
      "@context": "https://aroha-labs.com/contexts/v1",
      id: AGENT_DID,
      endpoint: `https://${req.headers.host}/aroha/v1`,
    });
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ error: "Method Not Allowed" });
    return;
  }

  const envelope = req.body as ArohaEnvelope;

  // Verify the sender's public key
  const senderPubKey = await resolvePublicKey(envelope.from);
  if (!senderPubKey) {
    res.status(401).json({ error: "Unknown sender DID" });
    return;
  }

  // Validate signature, expiry, nonce, recipient
  const result = await validateEnvelope(envelope, senderPubKey, AGENT_DID, nonceRegistry);
  if (!result.valid) {
    res.status(401).json({ error: result.reason });
    return;
  }

  if (envelope.type !== "ArohaRequest") {
    res.status(422).json({ error: `Unsupported message type: ${envelope.type}` });
    return;
  }

  const body = envelope.body as ArohaRequestBody;
  const capabilityHandler = handlers[body.capability];

  if (!capabilityHandler) {
    const errEnvelope = await buildEnvelope(
      "ArohaError",
      AGENT_DID,
      envelope.from,
      { code: ArohaErrorCode.UnknownCapability, message: `Unknown: ${body.capability}`, retryable: false },
      envelope.correlationId,
      PRIVATE_KEY
    );
    res.status(200).json(errEnvelope);
    return;
  }

  const capResult = await capabilityHandler(body.params);
  const responseBody: ArohaResponseBody = { capability: body.capability, result: capResult };
  const reply = await buildEnvelope(
    "ArohaResponse",
    AGENT_DID,
    envelope.from,
    responseBody,
    envelope.correlationId,
    PRIVATE_KEY
  );

  res.status(200).json(reply);
}
