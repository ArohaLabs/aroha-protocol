// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/agents — implements the REST contract that ArohaHttpRegistry (SDK client) calls.
 *
 * Endpoints:
 *   POST   /v1/agents                    register
 *   GET    /v1/agents                    list (hub browse page)
 *   GET    /v1/agents?capabilities=a,b   discover by capability
 *   GET    /v1/agents/:didHash           resolve by DID hash
 *   PUT    /v1/agents/:didHash/manifest  update manifest CID
 *   DELETE /v1/agents/:didHash           deactivate
 */

import { Hono } from "hono";
import { keccak_256 } from "@noble/hashes/sha3";
import { authMiddleware, adminMiddleware, optionalAuthMiddleware } from "../auth.js";
import { rotateKeyLimiter, discoveryIpLimiter } from "../middleware/rate-limit.js";
import type { AgentRow } from "../repository.js";
import type { Env, HonoEnv } from "../index.js";
import { verifyBlock, type BlockVerifyResult } from "../cid-verify.js";
import { manifestGatewayAttempts } from "../ipfs-gateways.js";
import { isInceptionDid, KelError, type KelEvent } from "@aroha-sdk/core/identity";
import { acceptSubmittedKel, storedKelState, kelErrorResponse, bytesToB64 } from "../kel-store.js";
import { resolveContentAddressedKey } from "@aroha-sdk/credentials/mandates";
import { decodeB64, decodeEd25519PublicKey, bytesEqual } from "../b64.js";
import { parsePagination } from "../pagination.js";
import { canViewAgent, viewerDependent } from "../visibility.js";

export const agentRoutes = new Hono<HonoEnv>();

// ─── Helpers ─────────────────────────────────────────────────────────────────

const VERIFIED_MIN_SCORE = 7_000;
const VERIFIED_MIN_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** New agents are hidden from public discovery for 48 h after registration. */
const COOLDOWN_MS = 48 * 60 * 60 * 1000;

function computeVerified(row: { active: boolean; reputationScore: number; registeredAt: number }): boolean {
  return (
    row.active &&
    row.reputationScore >= VERIFIED_MIN_SCORE &&
    Date.now() - row.registeredAt >= VERIFIED_MIN_AGE_MS
  );
}

export function hashDID(did: string): string {
  const bytes = new TextEncoder().encode(did);
  const hash = keccak_256(bytes);
  return "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Shape returned to SDK clients — mirrors AgentRecord from @aroha-sdk/registry */
function toApiRecord(row: AgentRow) {
  return {
    did: row.did,
    didHash: row.didHash,
    publishedBy: row.orgName || null,
    ownerAddress: "0x0000000000000000000000000000000000000000", // staking not yet live
    manifestCID: row.manifestCID,
    publicKeyB64: row.publicKeyB64,
    stakedWei: "0",
    reputationScore: row.reputationScore,
    active: row.active,
    registeredAt: row.registeredAt,
    lastUpdatedAt: row.lastUpdatedAt,
    capabilityIds: row.capabilityIds ?? [],
    endpointUrl: row.endpointUrl ?? null,
    keyVersion: row.keyVersion ?? 1,
    keyRotatedAt: row.keyRotatedAt ?? null,
    verified: computeVerified(row),
    verificationTier: row.verificationTier ?? 'community',
    domain: row.domain ?? null,
    orgSigned: row.verificationTier === 'org-signed',
    visibility: row.visibility ?? 'public',
  };
}

/**
 * Fetch capability IDs from the content-addressed IPFS manifest.
 *
 * The manifest CID is the integrity-bound source of truth for capabilities —
 * accepting caller-supplied IDs without verification would let anyone claim
 * arbitrary capabilities and poison discovery results.
 *
 * Tries the gateways in ipfs-gateways.ts in order (Pinata only with PINATA_JWT).
 * Only a raw IPLD block whose SHA-256 matches the CID is ever read; anything
 * else (JSON served directly, an unsupported CID form, a tampered block)
 * contributes nothing. Falls back to [] if no gateway returns a verifiable
 * block — registration never blocks on IPFS.
 * Capabilities are rebuilt on the next manifest update.
 */
async function fetchCapabilityIds(
  manifestCID: string,
  env: Env,
): Promise<string[]> {
  // Ordered gateways: Pinata's API gateway only when PINATA_JWT is set (no
  // propagation delay for content the SDK just pinned), then the Aroha
  // gateway (IPFS_GATEWAY), then any explicitly configured
  // IPFS_FALLBACK_GATEWAYS. See ipfs-gateways.ts.
  const attempts = manifestGatewayAttempts(manifestCID, env);

  // Pinata's own gateway may need a few seconds to index content immediately
  // after pinning. Retry the authenticated Pinata attempt before falling through
  // to the other gateways. fetch() waits don't count against Worker CPU time.
  const PINATA_RETRY_DELAY_MS = [0, 1500, 3000];

  outer: for (const { url, headers } of attempts) {
    const isPinataAuth = headers?.Authorization !== undefined;
    const retries = isPinataAuth ? 3 : 1;
    for (let attempt = 0; attempt < retries; attempt++) {
      if (attempt > 0) await new Promise((r) => setTimeout(r, PINATA_RETRY_DELAY_MS[attempt] ?? 3000));
      try {
        // Request the raw IPLD block so we can verify SHA-256(block) == CID hash.
        // Gateways that support the IPFS HTTP gateway spec return Content-Type:
        // application/vnd.ipld.raw; gateways that don't return JSON directly.
        const res = await fetch(url, {
          headers: { ...headers, Accept: "application/vnd.ipld.raw" },
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) {
          console.error(`[capabilities] ${url} attempt ${attempt + 1} → ${res.status}`);
          continue;
        }

        const bodyBytes = new Uint8Array(await res.arrayBuffer());
        const contentType = res.headers.get("Content-Type") ?? "";

        if (contentType.includes("vnd.ipld.raw")) {
          // Gateway returned a raw IPLD block — verify CID integrity before use.
          const result: BlockVerifyResult = await verifyBlock(manifestCID, bodyBytes);
          if (!result.ok) {
            if (result.tampered) {
              // SHA-256 mismatch — this gateway is serving tampered data. Abort all
              // retries for this gateway and try the next one (or fail closed).
              console.error(`[capabilities] ${url} — CID integrity check FAILED (tampered block)`);
              continue outer;
            }
            // Unsupported CID format or unrecognised codec — nothing this
            // registry can check the bytes against, so nothing is indexed
            // from them (see the fail-closed note below).
            console.error(`[capabilities] ${url} — block could not be verified against ${manifestCID} (unsupported CID or codec); indexing nothing from it`);
            continue outer;
          } else {
            const manifest = result.manifest as { capabilities?: Array<{ id: string }> };
            const ids = (manifest.capabilities ?? [])
              .map((c) => c.id)
              .filter(isValidCapabilityId)
              .slice(0, 50);
            if (ids.length > 0) return ids;
            continue; // verified but no capabilities — try next retry/gateway
          }
        }

        // Fail closed: the gateway did not return a raw IPLD block (it served
        // JSON directly, or ignored the Accept header), so there is nothing to
        // check these bytes against the CID with. This path used to parse and
        // index the JSON anyway, which made the CID's integrity binding
        // optional — any gateway, or anything between us and it, could put
        // arbitrary capabilities into discovery. Try the next gateway; if
        // none returns a verifiable block, the agent indexes no capabilities
        // until its next manifest update.
        console.error(`[capabilities] ${url} attempt ${attempt + 1} → not a raw IPLD block (Content-Type: ${contentType || "none"}); not indexed`);
        continue outer;
      } catch (err) {
        console.error(`[capabilities] ${url} attempt ${attempt + 1} → threw: ${err}`);
      }
    }
  }
  return [];
}

// Capability IDs must be non-empty, ≤64 chars, and contain only URL-safe chars.
// Rejects arbitrary strings that a compromised IPFS gateway might inject.
function isValidCapabilityId(id: unknown): id is string {
  return typeof id === "string" && id.length > 0 && id.length <= 64 && /^[\w\-.]+$/.test(id);
}

// ─── Routes ──────────────────────────────────────────────────────────────────

const REGISTRATION_CHALLENGE_TTL_MS = 5 * 60_000;

/**
 * POST /v1/agents/challenge — issue a one-time nonce proving the caller
 * holds the private key for `did` before it can be registered (M6).
 *
 * Without this, a valid API key alone was sufficient to register ANY
 * did+publicKeyB64 pair — including someone else's DID and someone else's
 * public key, with no proof the registrant controls the corresponding
 * private key. This endpoint plus the challengeNonce/challengeSignature
 * fields on POST /v1/agents close that gap. Tied to the requesting key's
 * hash (not just the DID) so a different API key intercepting the nonce
 * cannot redeem it.
 */
agentRoutes.post("/challenge", authMiddleware, async (c) => {
  const body = await c.req.json<{ did?: string }>().catch(() => ({}) as { did?: string });
  if (!body.did) return c.json({ error: "did is required" }, 400);

  const nonce = crypto.randomUUID();
  const expiresAt = Date.now() + REGISTRATION_CHALLENGE_TTL_MS;
  await c.get("repo").createRegistrationChallenge(nonce, body.did, c.get("keyHash"), expiresAt);
  return c.json({ nonce, expiresAt });
});

/**
 * Canonical message a registrant signs to prove key ownership — deliberately
 * distinct from the org-signature registration payload below it, so a
 * signature over one can never be replayed as the other.
 */
function challengeCanonicalString(did: string, nonce: string): string {
  return JSON.stringify({ action: "prove-ownership", did, nonce });
}

/** POST /v1/agents — register a new agent */
agentRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{
    did?: string;
    manifestCID?: string;
    publicKeyB64?: string;
    endpointUrl?: string;
    /** Unix ms timestamp included in the signed payload. Required when orgSignature is present. */
    registeredAt?: number;
    /** Base64 Ed25519 org signature over the canonical registration payload. */
    orgSignature?: string;
    /** Optional at registration: 'public' (default) | 'unlisted' | 'private'. */
    visibility?: string;
    /**
     * Proof of holding did's private key, from POST /v1/agents/challenge.
     * Required for every DID except a rotatable E-DID (whose key is bound
     * by its verified Key Event Log instead). This was optional while
     * callers caught up; leaving it optional meant any API key holder could
     * still pin any key to any non-E DID, so it is now mandatory.
     */
    challengeNonce?: string;
    challengeSignature?: string;
    /**
     * Rotatable did:aroha:E… agents only: the agent's Key Event Log (and,
     * for an agent with a controller person, optionally that person's log).
     * Omit it if the log was already posted to POST /v1/kel/:did.
     */
    kel?: unknown;
    controllerKel?: unknown;
  }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Request body must be a JSON object" }, 400);

  if (typeof body.did !== "string" || !body.did || typeof body.manifestCID !== "string" || !body.manifestCID) {
    return c.json({ error: "did, manifestCID, and publicKeyB64 are required" }, 400);
  }

  // ── Rotatable E-DIDs: the KEL, not the request, says which key is current ──
  // An E-DID commits to its inception event, not a key; its current key is
  // whatever its verified Key Event Log says now. So registration takes the
  // key FROM the log (posted in this body or earlier via POST /v1/kel) and
  // never from publicKeyB64 — a caller-supplied key the log does not name
  // would let an API key holder pin any key they like to someone's
  // self-certifying identity. publicKeyB64 is optional for E-DIDs; if sent,
  // it must match the log, which catches a client that registers a stale key.
  // From here on the row follows the log (kel-store.ts syncs it on every
  // accepted log), and PUT /:didHash/rotate-key refuses E-DIDs.
  let kelKeyVersion = 1;
  // The controller person, from the verified inception — stored on the row so
  // revoking that person deactivates this agent (kel-store.ts, migration 015).
  let kelControllerDid: string | null = null;
  if (isInceptionDid(body.did)) {
    const repoForKel = c.get("repo");
    let state;
    try {
      state = body.kel !== undefined
        ? await acceptSubmittedKel(repoForKel, body.did, body.kel as KelEvent[], {
            controllerKel: body.controllerKel as KelEvent[] | undefined,
            onStale: "use-stored",
          })
        : await storedKelState(repoForKel, body.did);
    } catch (e) {
      if (e instanceof KelError) {
        const { status, body: errBody } = kelErrorResponse(e);
        return c.json(errBody, status);
      }
      throw e;
    }
    if (!state) {
      return c.json({
        error: `${body.did} is a rotatable E-DID: include its Key Event Log as \`kel\`, or POST it to /v1/kel/${body.did} first`,
      }, 400);
    }
    if (state.kind !== "agent") {
      return c.json({ error: "a person E-DID is a principal, not an agent, and cannot be registered as one" }, 400);
    }
    if (state.revoked || state.controllerRevoked || !state.currentKey) {
      return c.json({ error: "this identity has been revoked (or its controller has) and cannot be registered" }, 403);
    }
    const kelKeyB64 = bytesToB64(state.currentKey);
    // Compared as bytes, not strings: the same key may arrive as base64url
    // or standard base64 (see b64.ts).
    if (body.publicKeyB64) {
      const sent = decodeB64(body.publicKeyB64);
      if (!sent || !bytesEqual(sent, state.currentKey)) {
        return c.json({ error: "publicKeyB64 is not the current key of this DID's Key Event Log" }, 400);
      }
    }
    body.publicKeyB64 = kelKeyB64;
    kelKeyVersion = state.keyHistory.length;
    kelControllerDid = state.controller ?? null;
  }

  if (!body.publicKeyB64) {
    return c.json({ error: "did, manifestCID, and publicKeyB64 are required" }, 400);
  }
  const publicKeyB64 = body.publicKeyB64;
  // Every path stores a key some other route will later verify a signature
  // with (rotate-key, relay connect, caller signatures, mandate chains), so
  // a value that is not a 32-byte Ed25519 key is refused here rather than
  // becoming a row nothing can ever verify against.
  const keyBytes = decodeEd25519PublicKey(publicKeyB64);
  if (!keyBytes) {
    return c.json({ error: "publicKeyB64 must be a base64url (or base64) encoded 32-byte Ed25519 public key" }, 400);
  }

  // ── Content-addressed z-DIDs: the DID IS the key ──────────────────────────
  // A `did:aroha:z…` DID is the multibase encoding of its own public key, so
  // there is exactly one key it can be registered with. Mandate chains
  // already derive the key from the DID and never consult the row
  // (routes/mandates.ts), but every other reader — relay connect, caller
  // signatures, credentials, discovery — trusts the row; a row holding some
  // other key would make the registry disagree with the DID itself.
  if (body.did.startsWith("did:aroha:z")) {
    const derived = await resolveContentAddressedKey(body.did);
    if (!derived) {
      return c.json({ error: "did is not a valid content-addressed did:aroha:z… identifier" }, 400);
    }
    if (!bytesEqual(derived, keyBytes)) {
      return c.json({ error: "publicKeyB64 is not the key this content-addressed DID encodes" }, 400);
    }
  }

  if (body.endpointUrl) {
    try {
      const u = new URL(body.endpointUrl);
      if (!["http:", "https:"].includes(u.protocol)) throw new Error();
    } catch {
      return c.json({ error: "endpointUrl must be an http(s) URL" }, 400);
    }
  }

  // ── Proof of key possession (all but E-DIDs) ───────────────────────────────
  // An E-DID's key comes from its verified Key Event Log above, which is
  // itself signed — that is the binding. Everything else must prove, over a
  // server-issued nonce, that the registrant holds the private key for
  // publicKeyB64; without it an API key alone could bind any key to any
  // named DID.
  if (!isInceptionDid(body.did)) {
    if (typeof body.challengeNonce !== "string" || typeof body.challengeSignature !== "string"
      || !body.challengeNonce || !body.challengeSignature) {
      return c.json({
        error: "challengeNonce and challengeSignature are required: request a nonce from POST /v1/agents/challenge and sign it with the agent key",
      }, 400);
    }
    const consumed = await c
      .get("repo")
      .consumeRegistrationChallenge(body.challengeNonce, body.did, c.get("keyHash"), Date.now());
    if (!consumed) {
      return c.json({ error: "challenge not found, already used, expired, or issued to a different API key" }, 403);
    }

    const sigBytes = decodeB64(body.challengeSignature);
    if (!sigBytes) return c.json({ error: "challengeSignature is not valid base64" }, 400);
    if (sigBytes.length !== 64) return c.json({ error: "challengeSignature must be 64 bytes" }, 400);

    const message = new TextEncoder().encode(challengeCanonicalString(body.did, body.challengeNonce));
    try {
      const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "Ed25519" }, false, ["verify"]);
      const valid = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, message);
      if (!valid) return c.json({ error: "challenge signature does not verify against publicKeyB64" }, 403);
    } catch {
      return c.json({ error: "challenge signature verification failed" }, 403);
    }
    // Ownership proven: the caller holds the private key matching
    // publicKeyB64, and that key produced a signature over THIS specific
    // nonce, so it cannot have been captured from a different request.
  }

  const didHash = hashDID(body.did);
  const repo = c.get("repo");

  // Reject duplicate registrations.
  // For deactivated DIDs, allow re-registration only by the original owner key —
  // otherwise any valid API key holder could hijack an inactive DID.
  const existing = await repo.getAgentAny(didHash);
  if (existing) {
    if (existing.active) return c.json({ error: "DID already registered" }, 409);
    if (existing.ownerKeyHash !== c.get("keyHash")) {
      return c.json({ error: "DID owned by another principal" }, 403);
    }
  }

  // ── Org-signature verification ───────────────────────────────────────────────
  // If the caller's API key has a registered org signing key AND the request
  // includes an orgSignature, verify the Ed25519 signature over the canonical
  // registration payload. A valid signature upgrades the tier to 'org-signed'.
  //
  // Canonical signed message (UTF-8 bytes of JSON with keys sorted alphabetically):
  //   {"action":"register-agent","did":"...","manifestCID":"...","publicKeyB64":"...","registeredAt":ms}
  //
  // The client must supply registeredAt (within 5 minutes of now) so it knows
  // exactly what it signed and the registry can verify freshness without a nonce table.
  let orgVerifiedTier: 'community' | 'org-signed' = 'community';

  const orgPublicKeyB64 = c.get("orgPublicKeyB64");
  if (body.orgSignature) {
    if (!orgPublicKeyB64) {
      return c.json({ error: "orgSignature provided but this API key has no registered org signing key — call PUT /v1/auth/org-key first" }, 400);
    }
    if (typeof body.registeredAt !== "number") {
      return c.json({ error: "registeredAt (Unix ms) is required when orgSignature is provided" }, 400);
    }
    if (Math.abs(Date.now() - body.registeredAt) > 5 * 60 * 1000) {
      return c.json({ error: "registeredAt is outside the 5-minute freshness window" }, 400);
    }

    const sigMessage = JSON.stringify({
      action: "register-agent",
      did: body.did,
      manifestCID: body.manifestCID,
      publicKeyB64: body.publicKeyB64,
      registeredAt: body.registeredAt,
    });
    const messageBytes = new TextEncoder().encode(sigMessage);

    const sigBytes = decodeB64(body.orgSignature);
    const orgKeyBytes = decodeB64(orgPublicKeyB64);
    if (!sigBytes || !orgKeyBytes) {
      return c.json({ error: "orgSignature or org key is not valid base64" }, 400);
    }
    if (sigBytes.length !== 64) {
      return c.json({ error: "orgSignature must be a 64-byte Ed25519 signature" }, 400);
    }

    let sigValid: boolean;
    try {
      const cryptoKey = await crypto.subtle.importKey(
        "raw", orgKeyBytes, { name: "Ed25519" }, false, ["verify"],
      );
      sigValid = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, messageBytes);
    } catch {
      return c.json({ error: "org signature verification failed" }, 400);
    }

    if (!sigValid) {
      return c.json({ error: "org signature is invalid" }, 403);
    }

    orgVerifiedTier = 'org-signed';
  }

  // ── Capability derivation ────────────────────────────────────────────────────
  // Derive capabilities from the content-addressed IPFS manifest only.
  // Never trust caller-supplied IDs — any key holder could claim arbitrary
  // capabilities. fetchCapabilityIds retries internally with backoff to handle
  // the brief propagation delay after a fresh Pinata pin.
  const capabilityIds = await fetchCapabilityIds(body.manifestCID, c.env);

  // Use client-supplied registeredAt for org-signed registrations (it was part of
  // the signed payload). For unsigned registrations the server sets it.
  const now = (orgVerifiedTier === 'org-signed' && typeof body.registeredAt === "number")
    ? body.registeredAt
    : Date.now();

  // Re-registering a deactivated DID replaces the row, so carry the previous
  // visibility forward — otherwise reviving a private agent would silently make
  // it public. A caller may still set it explicitly via body.visibility.
  // (`existing` was already fetched during the ownership check above.)
  const requested = body.visibility;
  const visibility =
    requested === "public" || requested === "unlisted" || requested === "private"
      ? requested
      : (existing?.visibility ?? "public");

  await repo.insertAgent(
    {
      didHash,
      did: body.did,
      visibility,
      ownerKeyHash: c.get("keyHash"),
      orgName: c.get("orgName"),
      manifestCID: body.manifestCID,
      publicKeyB64,
      stakedWei: "0",
      reputationScore: 5000,
      active: true,
      registeredAt: now,
      lastUpdatedAt: now,
      endpointUrl: body.endpointUrl ?? undefined,
      // E-DIDs: the number of key-establishing events in the log, the same
      // value kel-store.ts writes when a later rotation is accepted.
      keyVersion: kelKeyVersion,
      keyRotatedAt: null,
      verificationTier: orgVerifiedTier,
      domain: null,
      domainVerified: false,
      discoveryEligibleAt: now + COOLDOWN_MS,
      orgSignature: body.orgSignature ?? null,
      controllerDid: kelControllerDid,
    },
    capabilityIds,
  );

  void repo.recordEvent("agent.registered", didHash).catch(() => {});
  return c.json({ didHash }, 201);
});

/**
 * GET /v1/agents — list all agents (hub browse) or filter by capability.
 *
 * Anonymous callers see public agents only. A caller presenting a valid API key
 * (optionalAuthMiddleware) additionally sees agents they own or hold a live
 * access grant for. Unlisted agents never appear in list results — they are
 * reachable only by resolving their didHash directly.
 */
agentRoutes.get("/", discoveryIpLimiter, optionalAuthMiddleware, async (c) => {
  const capParam = c.req.query("capabilities");
  const repo = c.get("repo");
  const viewer = c.get("keyHash") ?? null;

  if (capParam) {
    const capabilityIds = capParam.split(",").map(decodeURIComponent).filter(Boolean);
    const rows = (await repo.queryByCapability(capabilityIds, viewer))
      .filter((r) => r.visibility !== "unlisted" || r.ownerKeyHash === viewer);
    void repo.recordEvent("capabilities.queried", null).catch(() => {});
    return c.json(rows.map(toApiRecord));
  }

  const { limit, offset } = parsePagination(c);
  const rows = (await repo.listAgents(limit, offset, viewer))
    .filter((r) => r.visibility !== "unlisted" || r.ownerKeyHash === viewer);
  void repo.recordEvent("agent.listed", null).catch(() => {});
  return c.json(rows.map(toApiRecord));
});

/**
 * GET /v1/agents/:did — resolve a single agent by DID string or keccak-256 hash.
 *
 * public   → anyone
 * unlisted → anyone who knows the identifier (share-by-link)
 * private  → owner or an unexpired grant only; everyone else gets a 404, not a
 *            403, so the endpoint cannot be used to prove a private agent exists.
 */
agentRoutes.get("/:did", discoveryIpLimiter, optionalAuthMiddleware, async (c) => {
  const param = decodeURIComponent(c.req.param("did")!);
  // Accept either the raw DID ("did:aroha:...") or the pre-computed hash ("0x...")
  const didHash = param.startsWith("0x") ? param : hashDID(param);
  const repo = c.get("repo");
  const row = await repo.getAgent(didHash);
  if (!row) return c.json({ error: "Not found" }, 404);

  // The visibility rule every per-agent read shares (visibility.ts).
  if (!(await canViewAgent(repo, row, c.get("keyHash") ?? null))) {
    return c.json({ error: "Not found" }, 404);
  }

  // Record discovery event fire-and-forget — must never block the response.
  void repo.recordEvent("agent.discovered", didHash).catch(() => {});
  // Private rows answer differently per caller; never let a cache share them.
  viewerDependent(c);
  return c.json(toApiRecord(row));
});

/**
 * PATCH /v1/agents/:didHash/visibility — set public | unlisted | private.
 * Owner-scoped via the registering API key.
 */
agentRoutes.patch("/:didHash/visibility", authMiddleware, async (c) => {
  const didHash = decodeURIComponent(c.req.param("didHash")!);
  const body = await c.req.json<{ visibility?: string }>().catch(() => ({}) as { visibility?: string });
  const v = body.visibility;
  if (v !== "public" && v !== "unlisted" && v !== "private") {
    return c.json({ error: "visibility must be one of: public, unlisted, private" }, 422);
  }
  const ok = await c.get("repo").setVisibility(didHash, "agent", v, c.get("keyHash"));
  if (!ok) return c.json({ error: "Not found, or not your agent" }, 403);
  return c.json({ didHash, visibility: v });
});

/** PUT /v1/agents/:didHash/manifest — update manifest CID */
agentRoutes.put("/:didHash/manifest", authMiddleware, async (c) => {
  const body = await c.req.json<{ manifestCID?: string }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Request body must be a JSON object" }, 400);
  if (typeof body.manifestCID !== "string" || !body.manifestCID) return c.json({ error: "manifestCID is required" }, 400);

  const capabilityIds = await fetchCapabilityIds(body.manifestCID, c.env);
  const updated = await c.get("repo").updateManifest(
    c.req.param("didHash")!,
    body.manifestCID,
    capabilityIds,
    c.get("keyHash"),
  );

  if (!updated) return c.json({ error: "Not found or not owned by this key" }, 404);
  return c.json({ ok: true });
});

/** DELETE /v1/agents/:didHash — deactivate (own key) */
agentRoutes.delete("/:didHash", authMiddleware, async (c) => {
  const deactivated = await c.get("repo").deactivateAgent(
    c.req.param("didHash")!,
    c.get("keyHash"),
  );
  if (!deactivated) return c.json({ error: "Not found or not owned by this key" }, 404);
  return c.json({ ok: true });
});

/**
 * DELETE /v1/agents/:didHash/admin — admin-delegated deactivation.
 * Called by the Next.js server on behalf of authenticated Studio users.
 * Ownership is verified by org_name (stable, tied to user's ownerToken).
 */
agentRoutes.delete("/:didHash/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{ orgName?: string }>().catch(() => ({} as { orgName?: string }));
  if (!body.orgName) return c.json({ error: "orgName required" }, 400);
  const deactivated = await c.get("repo").deactivateAgentByOrgName(c.req.param("didHash")!, body.orgName);
  if (!deactivated) return c.json({ error: "Not found or not owned by this orgName" }, 404);
  return c.json({ ok: true });
});

/**
 * PUT /v1/agents/:didHash/manifest/admin — admin-delegated manifest update.
 * Called by the Next.js server when a Studio user adds capabilities to their agent.
 */
agentRoutes.put("/:didHash/manifest/admin", adminMiddleware, async (c) => {
  const body = await c.req.json<{ manifestCID?: string; orgName?: string }>().catch(() => ({} as { manifestCID?: string; orgName?: string }));
  if (!body.manifestCID || !body.orgName) return c.json({ error: "manifestCID and orgName required" }, 400);
  const capabilityIds = await fetchCapabilityIds(body.manifestCID, c.env);
  const updated = await c.get("repo").updateManifestByOrgName(
    c.req.param("didHash")!, body.manifestCID, capabilityIds, body.orgName,
  );
  if (!updated) return c.json({ error: "Not found or not owned by this orgName" }, 404);
  return c.json({ ok: true });
});

/**
 * PUT /v1/agents/:didHash/rotate-key
 *
 * Rotate the agent's Ed25519 signing key.
 *
 * The caller must prove control of the CURRENT key by signing a rotation
 * message with it. Once accepted:
 *   - The old key is archived in revoked_keys (permanent audit log)
 *   - agent_records is updated with the new public key and a bumped key_version
 *   - All mandate tokens signed with the old key are automatically invalidated
 *     because verifyMandate() resolves the current public key from the registry
 *
 * Request body:
 *   {
 *     "newPublicKeyB64": "<base64-encoded 32-byte Ed25519 public key>",
 *     "signature":       "<base64-encoded 64-byte Ed25519 signature>",
 *     "nonce":           "<UUID — unique per request>",
 *     "issuedAt":        "<ISO 8601 timestamp, must be within 5 minutes>"
 *   }
 *
 * Signed message (UTF-8 bytes of canonical JSON, keys alphabetically sorted):
 *   {"action":"rotate-key","didHash":"<didHash>","issuedAt":"<issuedAt>","newPublicKeyB64":"<newPublicKeyB64>","nonce":"<nonce>"}
 *
 * The caller constructs this JSON string, signs it with the CURRENT private key,
 * and base64-encodes the resulting 64-byte signature.
 *
 * Authentication: requires the OWNER's API key (authMiddleware plus an
 * ownerKeyHash match) in addition to the Ed25519 proof, so a stolen agent
 * key alone cannot rotate the agent out from under its owner.
 */
// rotateKeyLimiter runs AFTER authMiddleware: keyed by didHash, an
// unauthenticated caller could otherwise spend a victim agent's five
// attempts per minute and lock its owner out of rotating.
agentRoutes.put("/:didHash/rotate-key", authMiddleware, rotateKeyLimiter, async (c) => {
  const didHash = c.req.param("didHash")!;

  const body = await c.req.json<{
    newPublicKeyB64?: string;
    signature?: string;
    nonce?: string;
    issuedAt?: string;
  }>().catch(() => ({} as Record<string, never>));

  if (!body.newPublicKeyB64 || !body.signature || !body.nonce || !body.issuedAt) {
    return c.json({ error: "newPublicKeyB64, signature, nonce, and issuedAt are required" }, 400);
  }

  // Replay protection: issuedAt must be within 5 minutes of now, in EITHER
  // direction. Only the past was bounded before, so a far-future issuedAt
  // produced a nonce row (expires issuedAt + 5 min) that pruning never
  // removed, and a signature that stayed "fresh" until that date.
  const issuedAtMs = new Date(body.issuedAt).getTime();
  if (!Number.isFinite(issuedAtMs) || Math.abs(Date.now() - issuedAtMs) > 5 * 60 * 1000) {
    return c.json({ error: "issuedAt is missing, invalid, or outside the 5-minute window" }, 400);
  }

  const repo = c.get("repo");
  const agent = await repo.getAgent(didHash);
  if (!agent) return c.json({ error: "Agent not found" }, 404);

  // A rotatable E-DID's key is whatever its Key Event Log says — the row is
  // a cache of the log, not an authority over it. Rotating here would make
  // the registry disagree with the log every verifier replays (and a
  // registry-side rotation is exactly the trust the E-form removes: an owner
  // API key plus a stolen device key could otherwise move the key without
  // the pre-committed next key). The real rotation is a `rotate` event
  // signed by that next key; posting the extended log updates this row.
  if (isInceptionDid(agent.did)) {
    return c.json({
      error:
        `${agent.did} is a rotatable E-DID: its key is set by its Key Event Log, not by the registry. ` +
        `Rotate with the pre-committed next key (rotateKel) and POST the new log to /v1/kel/${agent.did}.`,
    }, 409);
  }

  // Only the agent's OWNER may rotate its key — the same check verify-domain
  // makes. The signature below proves possession of the current agent key,
  // but that key lives on a device, and a stolen device is exactly the case
  // rotation has to survive: with any registered API key accepted, a thief
  // holding the agent key alone could rotate to their own key and lock the
  // owner out for good. Requiring the owner's API key as well makes the
  // device key necessary but no longer sufficient.
  if (agent.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Only the agent's owner may rotate its key" }, 403);
  }

  // Reconstruct the canonical signed message — keys must be alphabetically sorted.
  const message = JSON.stringify({
    action: "rotate-key",
    didHash,
    issuedAt: body.issuedAt,
    newPublicKeyB64: body.newPublicKeyB64,
    nonce: body.nonce,
  });
  const messageBytes = new TextEncoder().encode(message);

  // Verify the Ed25519 signature against the CURRENT public key in the registry.
  const signatureBytes = decodeB64(body.signature);
  const currentKeyBytes = decodeB64(agent.publicKeyB64);
  if (!signatureBytes || !currentKeyBytes) {
    return c.json({ error: "signature or current key is not valid base64" }, 400);
  }

  if (signatureBytes.length !== 64) {
    return c.json({ error: "signature must be 64 bytes (Ed25519)" }, 400);
  }

  let valid: boolean;
  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      currentKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify("Ed25519", cryptoKey, signatureBytes, messageBytes);
  } catch (err) {
    console.error("[rotate-key] crypto.subtle error:", err);
    return c.json({ error: "Signature verification failed" }, 400);
  }

  if (!valid) {
    return c.json({ error: "Invalid signature — must be signed by the current key" }, 403);
  }

  // Validate the new public key is parseable (32 bytes).
  if (!decodeEd25519PublicKey(body.newPublicKeyB64)) {
    return c.json({ error: "newPublicKeyB64 must be a base64url (or base64) encoded 32-byte Ed25519 public key" }, 400);
  }

  // Atomically consume the nonce — INSERT OR IGNORE is the guard.
  // If this nonce was already used (replay within the 5-minute window),
  // changes === 0 and we reject before touching the key.
  const nonceExpiresAt = issuedAtMs + 5 * 60 * 1000;
  const nonceConsumed = await repo.consumeRotationNonce(body.nonce, didHash, nonceExpiresAt);
  if (!nonceConsumed) {
    return c.json({ error: "Nonce already used — this request is a replay" }, 409);
  }

  // Prune stale nonces fire-and-forget — keeps the table bounded without a cron.
  repo.pruneExpiredRotationNonces().catch((err) =>
    console.error("[rotate-key] nonce prune failed:", err),
  );

  // rotateKey is conditional on the version this request verified against:
  // two rotations racing on the same current key cannot both land.
  const result = await repo.rotateKey(didHash, body.newPublicKeyB64, agent.keyVersion ?? 1);
  if (result === "conflict") {
    return c.json({ error: "The key was rotated by a concurrent request — re-read the agent and retry" }, 409);
  }
  if (!result) return c.json({ error: "Agent not found or inactive" }, 404);

  return c.json({ ok: true, keyVersion: result.keyVersion });
});

/**
 * GET /v1/agents/:didHash/revoked-keys — audit log of rotated-out public keys.
 * Same visibility rule as GET /v1/agents/:did: a private agent's key
 * history is not public, and an unknown or hidden agent is a 404 either way.
 */
agentRoutes.get("/:didHash/revoked-keys", optionalAuthMiddleware, async (c) => {
  const didHash = c.req.param("didHash")!;
  const repo = c.get("repo");
  const agent = await repo.getAgentAny(didHash);
  if (!agent || !(await canViewAgent(repo, agent, c.get("keyHash") ?? null))) {
    return c.json({ error: "Not found" }, 404);
  }
  const keys = await repo.getRevokedKeys(didHash);
  viewerDependent(c);
  return c.json(keys);
});

/**
 * POST /v1/agents/:didHash/verify-domain — elevate trust tier to 'domain'
 *
 * The agent owner proves control of a domain by hosting a well-known file:
 *   https://<domain>/.well-known/aroha-did.json  →  { "did": "did:aroha:..." }
 *
 * This registry fetches that file and checks the DID matches the registered agent.
 * On success the agent's verificationTier is set to 'domain' in the DB.
 *
 * Request body: { "domain": "acme.com" }
 * Auth: Bearer API key (must be the ownerKeyHash for this agent)
 */
agentRoutes.post("/:didHash/verify-domain", authMiddleware, async (c) => {
  const body = await c.req.json<{ domain?: string }>().catch(() => ({} as { domain?: string }));
  if (!body.domain) return c.json({ error: "domain is required" }, 400);

  // Reject IPs, ports, and paths — allow only valid hostnames
  const domainRe = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (!domainRe.test(body.domain)) return c.json({ error: "invalid domain format" }, 400);

  const repo = c.get("repo");
  const agent = await repo.getAgent(c.req.param("didHash")!);
  if (!agent) return c.json({ error: "Agent not found" }, 404);

  // Only the owner (matching ownerKeyHash) may verify
  if (agent.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Not your agent" }, 403);
  }

  // Fetch the .well-known file from the claimed domain.
  //
  // SSRF note: Cloudflare Workers egress is network-isolated — Workers cannot
  // reach RFC1918, loopback, link-local, CGNAT, or cloud-metadata addresses,
  // so DNS-rebinding attacks are blocked at the platform layer. We still set
  // redirect:'manual' as defence-in-depth so no redirect chain is followed.
  let wellKnown: { did?: string };
  try {
    const res = await fetch(`https://${body.domain}/.well-known/aroha-did.json`, {
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    // Treat redirects as failures — don't follow Location headers.
    // redirect:'manual' causes 3xx responses to be returned as-is (not followed).
    if (!res.ok || res.status >= 300) {
      return c.json({ error: `Well-known verification failed — host { "did": "<your DID>" } at https://${body.domain}/.well-known/aroha-did.json` }, 422);
    }
    wellKnown = await res.json() as { did?: string };
  } catch {
    return c.json({ error: `Could not reach https://${body.domain}/.well-known/aroha-did.json` }, 422);
  }

  if (wellKnown.did !== agent.did) {
    return c.json({
      error: "DID mismatch — the file must contain { \"did\": \"<your agent DID>\" }",
      expected: agent.did,
      got: wellKnown.did ?? null,
    }, 422);
  }

  const ok = await repo.setVerificationTier(agent.didHash, c.get("keyHash"), "domain", body.domain);
  if (!ok) return c.json({ error: "Failed to update verification tier" }, 500);

  void repo.recordEvent("agent.domain_verified", agent.didHash).catch(() => {});
  return c.json({ ok: true, verificationTier: "domain", domain: body.domain });
});
