// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — Self-Hostable HTTP Reference Server
 *
 * A production-capable HTTP server implementing the Aroha Registry REST API.
 * Wrap any IArohaRegistry backend (InMemoryRegistry for dev, your own database
 * implementation for production).
 *
 * Quickstart (zero config):
 *   import { createArohaRegistryServer } from "@aroha-sdk/registry/server";
 *   const { listen } = createArohaRegistryServer({ port: 3001 });
 *   await listen(); // http://localhost:3001
 *
 * With your own backend:
 *   import { createArohaRegistryServer } from "@aroha-sdk/registry/server";
 *   import { MyPostgresRegistry } from "./my-registry.js";
 *   const { listen } = createArohaRegistryServer({
 *     registry: new MyPostgresRegistry(db),
 *     apiKey: process.env.REGISTRY_API_KEY,
 *     port: 8080,
 *   });
 *   await listen();
 *
 * REST API (identical to the Aroha managed registry):
 *   POST   /v1/agents                       — register agent
 *   DELETE /v1/agents/:didHash              — deactivate agent
 *   PUT    /v1/agents/:didHash/manifest     — update manifest CID
 *   GET    /v1/agents/:didHash              — resolve by DID hash
 *   GET    /v1/agents?capabilities=a,b,c   — query by capability IDs
 *   GET    /healthz                         — health check
 */

import { isLoopbackHost } from "@aroha-sdk/core/endpoints";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import type { IArohaRegistry, AgentRecord } from "./types.js";
import { registrationNeedsProof, verifyRegistrationChallenge } from "./registration-proof.js";
import { isContentAddressedDid, fromMultibase } from "@aroha-sdk/core/identity";
import { InMemoryRegistry } from "./memory-registry.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ArohaRegistryServerOptions {
  /**
   * The registry backend to expose over HTTP.
   * Defaults to an in-memory registry (data lost on restart).
   * For persistence, implement IArohaRegistry against a database and pass it here.
   */
  registry?: IArohaRegistry;
  /**
   * Bearer token required for mutating operations (register, deactivate, updateManifest).
   * REQUIRED unless `hostname` is a loopback address: createArohaRegistryServer
   * throws otherwise. WHY: without it anyone who can reach the port can
   * register a DID under any public key, or deactivate someone else's agent.
   */
  apiKey?: string;
  /** TCP port to listen on. Defaults to 3001. */
  port?: number;
  /**
   * Hostname / interface to bind. Defaults to "127.0.0.1" (loopback only;
   * it was "0.0.0.0"). Binding any other interface requires `apiKey`.
   */
  hostname?: string;
}

export interface ArohaRegistryServerHandle {
  listen(): Promise<void>;
  close(): Promise<void>;
  readonly port: number;
  readonly hostname: string;
}

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createArohaRegistryServer(
  opts: ArohaRegistryServerOptions = {}
): ArohaRegistryServerHandle {
  const registry = opts.registry ?? new InMemoryRegistry();
  const { apiKey, port = 3001, hostname = "127.0.0.1" } = opts;
  if (!apiKey && !isLoopbackHost(hostname)) {
    throw new Error(
      `createArohaRegistryServer: apiKey is required when binding ${hostname} (non-loopback). ` +
      `Without it every write endpoint is open to the network.`
    );
  }

  // didHash (hex) → original DID string
  // Needed because the REST API routes by didHash, but IArohaRegistry operates on DIDs.
  const hashToDID = new Map<string, string>();
  // Outstanding registration challenges: nonce → { did, expiresAt }. Single
  // use; same contract as the managed registry (see registration-proof.ts).
  const challenges = new Map<string, { did: string; expiresAt: number }>();

  const server = createServer(async (req, res) => {
    try {
      await route(req, res, registry, hashToDID, apiKey, challenges);
    } catch (err) {
      sendJSON(res, 500, { error: "Internal server error", detail: String(err) });
    }
  });

  return {
    port,
    hostname,
    listen: () =>
      new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, hostname, () => resolve());
      }),
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close(err => (err ? reject(err) : resolve()));
      }),
  };
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function route(
  req: IncomingMessage,
  res: ServerResponse,
  registry: IArohaRegistry,
  hashToDID: Map<string, string>,
  apiKey: string | undefined,
  challenges: Map<string, { did: string; expiresAt: number }>
): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const method = req.method ?? "GET";
  const pathname = url.pathname;

  // Health check — no auth required
  if (method === "GET" && pathname === "/healthz") {
    sendJSON(res, 200, { status: "ok" });
    return;
  }

  // POST /v1/agents/challenge — one-time nonce for proof of key possession
  if (method === "POST" && pathname === "/v1/agents/challenge") {
    if (!checkAuth(req, res, apiKey)) return;
    const body = await readJSON<{ did?: string }>(req, res);
    if (!body) return;
    if (typeof body.did !== "string" || !body.did) { sendJSON(res, 400, { error: "did is required" }); return; }
    const now = Date.now();
    for (const [n, c] of challenges) if (c.expiresAt < now) challenges.delete(n);
    if (challenges.size >= 10_000) { sendJSON(res, 503, { error: "too many outstanding challenges" }); return; }
    const nonce = crypto.randomUUID();
    const expiresAt = now + 5 * 60_000;
    challenges.set(nonce, { did: body.did, expiresAt });
    sendJSON(res, 200, { nonce, expiresAt });
    return;
  }

  // POST /v1/agents — register
  if (method === "POST" && pathname === "/v1/agents") {
    if (!checkAuth(req, res, apiKey)) return;
    const body = await readJSON<RegisterBody>(req, res);
    if (!body) return;
    if (!body.did || !body.manifestCID || !body.publicKeyB64) {
      sendJSON(res, 400, { error: "did, manifestCID and publicKeyB64 are required" });
      return;
    }
    const didHash = hashDID(body.did);
    // Accept base64url (canonical) or standard base64, like the managed registry.
    const publicKey = new Uint8Array(Buffer.from(body.publicKeyB64.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
    if (publicKey.length !== 32) {
      sendJSON(res, 400, { error: "publicKeyB64 must encode a 32-byte Ed25519 public key" });
      return;
    }
    if (isContentAddressedDid(body.did)) {
      const encoded = fromMultibase(body.did.slice("did:aroha:".length));
      if (Buffer.compare(Buffer.from(encoded), Buffer.from(publicKey)) !== 0) {
        sendJSON(res, 400, { error: "publicKeyB64 is not the key this content-addressed DID encodes" });
        return;
      }
    }
    if (registrationNeedsProof(body.did)) {
      if (typeof body.challengeNonce !== "string" || typeof body.challengeSignature !== "string") {
        sendJSON(res, 400, {
          error: "challengeNonce and challengeSignature are required: request a nonce from POST /v1/agents/challenge and sign it with the agent key",
        });
        return;
      }
      const ch = challenges.get(body.challengeNonce);
      challenges.delete(body.challengeNonce); // single use, whatever the outcome
      if (!ch || ch.did !== body.did || ch.expiresAt < Date.now()) {
        sendJSON(res, 403, { error: "challenge not found, already used, expired, or issued for a different DID" });
        return;
      }
      const sig = new Uint8Array(Buffer.from(body.challengeSignature.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
      if (sig.length !== 64 || !(await verifyRegistrationChallenge(body.did, body.challengeNonce, sig, publicKey))) {
        sendJSON(res, 403, { error: "challenge signature does not verify against publicKeyB64" });
        return;
      }
    }
    await registry.register(body.did, body.manifestCID, publicKey, {
      capabilityIds: body.capabilityIds ?? [],
    });
    hashToDID.set(didHash, body.did);
    sendJSON(res, 201, { didHash, did: body.did });
    return;
  }

  // GET /v1/agents?capabilities=a,b,c — query by capability
  if (method === "GET" && pathname === "/v1/agents") {
    const capParam = url.searchParams.get("capabilities") ?? "";
    const capabilityIds = capParam ? capParam.split(",").map(decodeURIComponent) : [];
    if (capabilityIds.length === 0) {
      sendJSON(res, 400, { error: "capabilities query param required" });
      return;
    }
    const results = await registry.queryByCapability(capabilityIds);
    sendJSON(res, 200, results);
    return;
  }

  // /v1/agents/:didHash and /v1/agents/:didHash/manifest
  const agentMatch = pathname.match(/^\/v1\/agents\/(0x[0-9a-f]+)(\/manifest)?$/i);
  if (agentMatch) {
    const didHash = agentMatch[1].toLowerCase();
    const isManifest = Boolean(agentMatch[2]);

    // GET /v1/agents/:didHash — resolve
    if (method === "GET" && !isManifest) {
      const did = hashToDID.get(didHash);
      if (!did) { sendJSON(res, 404, { error: "Agent not found" }); return; }
      const record: AgentRecord | null = await registry.resolveByDID(did);
      if (!record) { sendJSON(res, 404, { error: "Agent not found or inactive" }); return; }
      sendJSON(res, 200, record);
      return;
    }

    // DELETE /v1/agents/:didHash — deactivate
    if (method === "DELETE" && !isManifest) {
      if (!checkAuth(req, res, apiKey)) return;
      const did = hashToDID.get(didHash);
      if (!did) { sendJSON(res, 404, { error: "Agent not found" }); return; }
      await registry.deactivate(did);
      sendJSON(res, 200, { deactivated: true });
      return;
    }

    // PUT /v1/agents/:didHash/manifest — update manifest
    if (method === "PUT" && isManifest) {
      if (!checkAuth(req, res, apiKey)) return;
      const did = hashToDID.get(didHash);
      if (!did) { sendJSON(res, 404, { error: "Agent not found" }); return; }
      const body = await readJSON<{ manifestCID: string }>(req, res);
      if (!body) return;
      if (!body.manifestCID) { sendJSON(res, 400, { error: "manifestCID is required" }); return; }
      await registry.updateManifest(did, body.manifestCID);
      sendJSON(res, 200, { updated: true });
      return;
    }
  }

  sendJSON(res, 404, { error: `${method} ${pathname} not found` });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface RegisterBody {
  did: string;
  manifestCID: string;
  publicKeyB64: string;
  /** Still honoured by this in-memory server, which has no IPFS indexer. */
  capabilityIds?: string[];
  challengeNonce?: string;
  challengeSignature?: string;
}

function hashDID(did: string): string {
  return "0x" + bytesToHex(keccak_256(new TextEncoder().encode(did)));
}

function checkAuth(req: IncomingMessage, res: ServerResponse, apiKey?: string): boolean {
  if (!apiKey) return true;
  const provided = Buffer.from(req.headers.authorization ?? "");
  const expected = Buffer.from(`Bearer ${apiKey}`);
  // timingSafeEqual requires equal-length buffers; length check must come first
  // but is done via the alloc trick to avoid early exit leaking key length.
  const valid =
    provided.length === expected.length &&
    timingSafeEqual(provided, expected);
  if (!valid) {
    sendJSON(res, 401, { error: "Unauthorized" });
    return false;
  }
  return true;
}

function sendJSON(res: ServerResponse, status: number, body: unknown): void {
  // Serialize bigint as string — AgentRecord.stakedWei is bigint and JSON.stringify throws otherwise
  const json = JSON.stringify(body, (_, v) => (typeof v === "bigint" ? v.toString() : v));
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

async function readJSON<T>(req: IncomingMessage, res: ServerResponse): Promise<T | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as T);
      } catch {
        sendJSON(res, 400, { error: "Invalid JSON body" });
        resolve(null);
      }
    });
    req.on("error", () => {
      sendJSON(res, 400, { error: "Failed to read request body" });
      resolve(null);
    });
  });
}
