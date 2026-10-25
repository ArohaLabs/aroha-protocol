// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * POST /v1/signals — ingest external quality signals into agent reputation scores.
 *
 * Called by @aroha-sdk/evals postEvalsToReputation() after eval runs.
 * Also callable by satisfaction surveys, saga monitors, or admin tooling.
 *
 * Authentication: requires ADMIN_SECRET Bearer token (same as the admin routes).
 *
 * Body:
 *   {
 *     "agentDID":    "did:aroha:studio:<hash>",       — agent DID or didHash
 *     "source":      "evals" | "survey" | "saga" | "manual",
 *     "successRate": 0.85,    — 0–1
 *     "qualityScore": 0.78,   — 0–1 (optional, defaults to successRate)
 *     "sampleSize":  50,      — weight (observation count this batch represents)
 *     "reportedAt":  "...",   — ISO8601 (optional, defaults to now)
 *   }
 *
 * Response:
 *   { "ok": true, "didHash": "...", "compositeScore": 0.82 }
 */

import { Hono } from "hono";
import { keccak_256 } from "@noble/hashes/sha3";
import { checkAdmin, logAdminUnconfigured, ADMIN_UNCONFIGURED_MESSAGE } from "../secrets.js";
import type { HonoEnv } from "../index.js";

export const signalRoutes = new Hono<HonoEnv>();

function hashDID(did: string): string {
  const bytes = new TextEncoder().encode(did);
  const hash  = keccak_256(bytes);
  return "0x" + Array.from(hash).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isDidHash(s: string): boolean {
  return /^0x[0-9a-f]{64}$/i.test(s);
}

interface SignalBody {
  agentDID:      string;
  source?:       string;
  successRate:   number;
  qualityScore?: number;
  sampleSize?:   number;
  reportedAt?:   string;
}

signalRoutes.post("/", async (c) => {
  // Admin only, as the header comment has always said. This route used to
  // also accept any active org API key (rate-limited to 5 signals per agent
  // per day), which let any self-service key holder move any agent's
  // reputation score — including competitors'. Reputation inputs come from
  // operator tooling (evals, saga monitors, surveys) that holds the admin
  // secret; per-org feedback has its own attested path, POST
  // /v1/signals/attest, which is bound to a signed caller DID.
  const check = await checkAdmin(c);
  if (check === "unconfigured") {
    logAdminUnconfigured();
    return c.json({ error: ADMIN_UNCONFIGURED_MESSAGE }, 503);
  }
  if (check !== "ok") {
    return c.json({ error: "Unauthorized" }, 401);
  }

  let body: SignalBody;
  try {
    body = await c.req.json<SignalBody>();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (!body.agentDID || typeof body.successRate !== "number") {
    return c.json({ error: "agentDID and successRate are required" }, 400);
  }
  if (body.successRate < 0 || body.successRate > 1) {
    return c.json({ error: "successRate must be between 0 and 1" }, 400);
  }

  const qualityScore = body.qualityScore ?? body.successRate;
  if (qualityScore < 0 || qualityScore > 1) {
    return c.json({ error: "qualityScore must be between 0 and 1" }, 400);
  }

  const didHash = isDidHash(body.agentDID) ? body.agentDID : hashDID(body.agentDID);
  const repo    = c.get("repo");

  const sampleSize = Math.max(1, body.sampleSize ?? 1);
  const alpha      = Math.min(0.3, Math.max(0.05, sampleSize / (sampleSize + 10)));

  const updated = await repo.updateReputationScore(didHash, qualityScore, alpha);
  if (updated === null) {
    return c.json({ error: "Agent not found or inactive" }, 404);
  }

  void repo
    .recordAuditAction("signal.submitted", "admin", didHash, c.req.header("CF-Connecting-IP"))
    .catch((err) => console.error("[audit] signal.submitted not recorded:", err));

  return c.json({
    ok:             true,
    didHash,
    source:         body.source ?? "unknown",
    compositeScore: Math.round(updated * 1000) / 1000,
  });
});
