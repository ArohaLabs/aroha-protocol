// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Agent on Cloudflare Workers
 *
 * Deploy a globally-distributed Aroha agent or InMemoryRegistry as a
 * Cloudflare Worker. Zero cold starts, 200+ edge locations, free tier
 * handles 100k requests/day.
 *
 * Deploy:
 *   npx wrangler deploy
 *
 * Secrets (npx wrangler secret put <NAME>; .dev.vars for wrangler dev):
 *   AROHA_PRIVATE_KEY        — base64 of the 32-byte Ed25519 private key (seed)
 *   AROHA_AGENT_DID          — did:aroha:<your-agent-id>
 *   ORCHESTRATOR_DID         — DID allowed to call this agent
 *   ORCHESTRATOR_PUBLIC_KEY  — base64 of that DID's 32-byte public key
 *
 * Note: Workers run a V8 isolate — @noble/* (used by @aroha-sdk/core) works
 * natively, but Node.js APIs (http, ws, fs) are NOT available. So this
 * example imports from the `@aroha-sdk/core/messages` subpath, which pulls in
 * only the envelope, nonce and signing code — NOT the package root, whose
 * transport exports drag in ws/undici/fs. It uses the Aroha envelope format
 * directly, without ArohaServer.
 */

import {
  validateEnvelope,
  buildEnvelope,
  NonceRegistry,
  ArohaErrorCode,
  type ArohaEnvelope,
  type ArohaRequestBody,
  type ArohaResponseBody,
} from "@aroha-sdk/core/messages";

// ─── Replay protection: read this before deploying ───────────────────────────
//
// The nonce registry lives at MODULE scope so that it survives across
// requests handled by the same isolate. (It used to be created inside the
// request handler, i.e. empty for every request — which rejected nothing.)
//
// That is still NOT real replay protection: Cloudflare runs many isolates,
// in many locations, and recycles them at will; none of them share this
// memory. A captured envelope replayed to a different isolate (or after
// eviction) within its validity window is accepted again. For real
// protection, record nonces in a Durable Object (one strongly consistent
// owner per agent) and reject a nonce it has already seen. KV is NOT
// sufficient: it is eventually consistent, so two isolates can both miss.
const nonceRegistry = new NonceRegistry();

// ─── Worker environment ───────────────────────────────────────────────────────

export interface Env {
  AROHA_PRIVATE_KEY: string;
  AROHA_AGENT_DID: string;
  ORCHESTRATOR_DID: string;
  ORCHESTRATOR_PUBLIC_KEY: string;
  // For replay protection across isolates, bind a Durable Object namespace
  // that records seen nonces (see "Replay protection" above), e.g.:
  // NONCE_GUARD: DurableObjectNamespace;
}

// ─── Capability handlers ──────────────────────────────────────────────────────

async function handleCapability(
  capability: string,
  params: Record<string, unknown>
): Promise<Record<string, unknown> | null> {
  switch (capability) {
    case "hello-world":
      return {
        message: `Hello from Cloudflare Workers edge! Params: ${JSON.stringify(params)}`,
        colo: "global",
        timestamp: new Date().toISOString(),
      };
    // Add your capabilities here
    default:
      return null;
  }
}

// ─── Worker fetch handler ─────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // ── Serve DID Document ────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/.well-known/aroha-agent.json") {
      return Response.json({
        "@context": "https://aroha-labs.com/contexts/v1",
        id: env.AROHA_AGENT_DID,
        endpoint: `${url.origin}/aroha/v1`,
      });
    }

    // ── Aroha message endpoint ─────────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/aroha/v1") {
      return handleArohaRequest(request, env);
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function handleArohaRequest(request: Request, env: Env): Promise<Response> {
  let envelope: ArohaEnvelope;
  try {
    envelope = (await request.json()) as ArohaEnvelope;
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!env.AROHA_AGENT_DID || !env.AROHA_PRIVATE_KEY) {
    return Response.json({ error: "Set the AROHA_AGENT_DID and AROHA_PRIVATE_KEY secrets" }, { status: 500 });
  }
  const privateKey = base64ToBytes(env.AROHA_PRIVATE_KEY);
  const agentDID = env.AROHA_AGENT_DID;

  // Resolve sender public key
  const knownKeys: Record<string, string> = {};
  if (env.ORCHESTRATOR_DID && env.ORCHESTRATOR_PUBLIC_KEY) knownKeys[env.ORCHESTRATOR_DID] = env.ORCHESTRATOR_PUBLIC_KEY;
  const senderPubKeyB64 = knownKeys[envelope.from];
  if (!senderPubKeyB64) {
    return Response.json({ error: "Unknown sender DID" }, { status: 401 });
  }
  const senderPubKey = base64ToBytes(senderPubKeyB64);

  // Per-isolate nonce memory only — see "Replay protection" at the top.
  const result = await validateEnvelope(envelope, senderPubKey, agentDID, nonceRegistry);
  if (!result.valid) {
    return Response.json({ error: result.reason }, { status: 401 });
  }

  if (envelope.type !== "ArohaRequest") {
    return Response.json({ error: `Unsupported: ${envelope.type}` }, { status: 422 });
  }

  const body = envelope.body as ArohaRequestBody;
  const capResult = await handleCapability(body.capability, body.params);

  if (!capResult) {
    const err = await buildEnvelope(
      "ArohaError",
      agentDID,
      envelope.from,
      { code: ArohaErrorCode.UnknownCapability, message: `Unknown: ${body.capability}`, retryable: false },
      envelope.correlationId,
      privateKey
    );
    return Response.json(err);
  }

  const responseBody: ArohaResponseBody = { capability: body.capability, result: capResult };
  const reply = await buildEnvelope(
    "ArohaResponse",
    agentDID,
    envelope.from,
    responseBody,
    envelope.correlationId,
    privateKey
  );

  return Response.json(reply);
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
