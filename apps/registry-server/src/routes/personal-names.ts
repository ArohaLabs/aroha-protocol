// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/personal-names — key-derived personal agent names (spec §7.10).
 *
 *   POST /v1/personal-names        mint a label for a registered agent
 *   GET  /v1/personal-names/:label resolve a label to its DID (routing)
 *
 * "Mint lazily" (§7.10): an agent only gets an index row here once it's
 * first made callable, not at registration. Minting is deliberately NOT
 * gated behind a fresh proof-of-key-possession signature the way
 * POST /v1/agents/challenge is for registration — the label's validity
 * doesn't rest on this endpoint or this database at all. It rests on pure
 * math: derivePersonalLabel(publicKey) is a public, deterministic function,
 * so anyone (this server included) can already verify a claimed label
 * against the DID with zero trust in whoever submitted it. What DOES need
 * gating is *whose* index entry this is (so a stranger can't overwrite your
 * routing record with a no-op re-mint of your own label, which would be
 * harmless, or spam the table) — hence authMiddleware plus an ownership
 * check against the agent's registered ownerKeyHash, the same scoping every
 * other owner-only mutation on an agent already uses (visibility, manifest,
 * rotate-key).
 *
 * The label derives from the DID, not from the agent's current key: a
 * content-addressed z-DID IS its key, so nothing changed for those; a
 * rotatable E-DID derives from its inception digest, so the name it mints
 * once stays valid across every rotation and recovery of its key.
 */

import { Hono } from "hono";
import { authMiddleware } from "../auth.js";
import type { HonoEnv } from "../index.js";
import { hashDID } from "./agents.js";
import { derivePersonalLabelForDid, isPersonalLabelFormat } from "@aroha-sdk/registry/personal-name";

export const personalNameRoutes = new Hono<HonoEnv>();

personalNameRoutes.post("/", authMiddleware, async (c) => {
  const body = await c.req.json<{ did?: string; label?: string }>().catch(() => ({}) as { did?: string; label?: string });
  if (!body.did || !body.label) {
    return c.json({ error: "did and label are required" }, 400);
  }

  const label = body.label.toLowerCase();
  if (!isPersonalLabelFormat(label)) {
    return c.json({ error: "label is not a validly-shaped personal name (6 hyphen-separated wordlist tokens)" }, 400);
  }

  // Only a self-certifying DID commits to something a name can derive from:
  // a content-addressed did:aroha:z… commits to its public key, a rotatable
  // did:aroha:E… to its inception event. A namespaced DID
  // (did:aroha:<namespace>.<agentId>) commits to nothing and cannot mint a
  // self-verifying personal name.
  const expected = derivePersonalLabelForDid(body.did);
  if (!expected) {
    return c.json({
      error: "did must be a self-certifying did:aroha:z… (content-addressed) or did:aroha:E… (rotatable) DID to derive a personal name",
    }, 400);
  }

  if (expected !== label) {
    return c.json({ error: "label does not derive from this DID" }, 422);
  }

  const didHash = hashDID(body.did);
  const repo = c.get("repo");
  const agent = await repo.getAgent(didHash);
  if (!agent) return c.json({ error: "DID is not a registered agent" }, 404);
  if (agent.ownerKeyHash !== c.get("keyHash")) {
    return c.json({ error: "Not your agent" }, 403);
  }

  const minted = await repo.mintPersonalName({
    label,
    didHash,
    did: body.did,
    ownerKeyHash: c.get("keyHash"),
    mintedAt: Date.now(),
  });
  if (!minted) {
    // Only reachable via an actual scrypt collision between two different
    // keys' derivations — astronomically unlikely at these parameters, but
    // the contract must still name a response for it rather than silently
    // overwriting someone else's routing record.
    return c.json({ error: "label is already bound to a different DID" }, 409);
  }

  void repo.recordEvent("personal_name.minted", didHash).catch(() => {});
  return c.json({ ok: true, label, did: body.did }, 201);
});

personalNameRoutes.get("/:label", async (c) => {
  const label = decodeURIComponent(c.req.param("label")!).toLowerCase();
  if (!isPersonalLabelFormat(label)) {
    return c.json({ error: "Not found" }, 404);
  }
  const row = await c.get("repo").lookupPersonalName(label);
  if (!row) return c.json({ error: "Not found" }, 404);
  return c.json({ label, did: row.did });
});
