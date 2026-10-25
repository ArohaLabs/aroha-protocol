/**
 * HTTP route tests for /v1/spending — budget lifecycle via the REST API.
 *
 * Tests the full Hono request/response cycle with in-memory SQLite:
 *   POST /v1/spending/budgets         — init a budget from a verified mandate token
 *   POST /v1/spending/allocate        — atomic deduct
 *   POST /v1/spending/release/:id     — return allocation to pool
 *   GET  /v1/spending/status/:mandate — query budget state
 *
 * Budgets are created from real issueIntentMandate / attenuateToCart tokens:
 * the limit is the verified mandate's, never a number in the request body.
 */

import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core";
import {
  issueIntentMandate,
  attenuateToCart,
  mandateRevocationPayload,
  type SignedMandate,
} from "@aroha-sdk/credentials";
import { makeApp, type TestApp } from "../test-utils/make-app.js";
import { sha256hex } from "../auth.js";
import type { SqliteD1 } from "../test-utils/sqlite-d1.js";

function authHeaders(apiKey: string) {
  return { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` };
}

async function party() {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, did: generateDid(pub) };
}

/** An intent mandate from a fresh human to a fresh agent. */
async function intent(spendLimitUsd = 100, extra: { sessionLimitUsd?: number } = {}, ttlMs?: number) {
  const human = await party();
  const agent = await party();
  const m = await issueIntentMandate(human.did, agent.did, { spendLimitUsd, ...extra }, human.priv, ttlMs);
  return { human, agent, m };
}

async function addKey(env: TestApp["env"], org: string): Promise<string> {
  const key = `${org}-key-` + Math.random().toString(36).slice(2);
  await (env.DB as SqliteD1)
    .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
    .bind(await sha256hex(key), org, Date.now())
    .run();
  return key;
}

function createBudget(t: TestApp, apiKey: string, body: unknown) {
  return t.app.request("/v1/spending/budgets", { method: "POST", headers: authHeaders(apiKey), body: JSON.stringify(body) }, t.env);
}

function allocate(t: TestApp, apiKey: string, m: SignedMandate, amountUsd: number) {
  return t.app.request("/v1/spending/allocate", {
    method: "POST",
    headers: authHeaders(apiKey),
    body: JSON.stringify({ parentMandateId: m.mandate.mandateId, grantor: m.mandate.grantor, amountUsd }),
  }, t.env);
}

function status(t: TestApp, apiKey: string, m: SignedMandate) {
  return t.app.request(
    `/v1/spending/status/${encodeURIComponent(m.mandate.mandateId)}?grantor=${encodeURIComponent(m.mandate.grantor)}`,
    { headers: { Authorization: `Bearer ${apiKey}` } },
    t.env,
  );
}

// ─── POST /v1/spending/budgets ────────────────────────────────────────────────

describe("POST /v1/spending/budgets", () => {
  it("201 — derives limitUsd and expiry from the verified mandate, keyed by grantor#mandateId", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    const res = await createBudget(t, t.apiKey, { token: m.token });
    expect(res.status).toBe(201);
    const body = await res.json() as { ok: boolean; limitUsd: number; budgetKey: string; grantor: string; expiresAt: number };
    expect(body).toMatchObject({ ok: true, limitUsd: 100, grantor: m.mandate.grantor, mandateId: m.mandate.mandateId });
    expect(body.budgetKey).toBe(`${m.mandate.grantor}#${m.mandate.mandateId}`);
    expect(body.expiresAt).toBe(Date.parse(m.mandate.expiresAt));
  });

  it("ignores a caller-supplied limitUsd — the body cannot widen the pool", async () => {
    const t = await makeApp();
    const { m } = await intent(25);
    const res = await createBudget(t, t.apiKey, { token: m.token, limitUsd: 1_000_000 });
    expect(((await res.json()) as { limitUsd: number }).limitUsd).toBe(25);
    // The old body shape (no token) is refused outright.
    expect((await createBudget(t, t.apiKey, { mandateId: "x", limitUsd: 100 })).status).toBe(400);
  });

  it("uses min(spendLimitUsd, sessionLimitUsd) of the verified leaf, including a cart", async () => {
    const t = await makeApp();
    const { m: root, agent } = await intent(100, { sessionLimitUsd: 40 });
    expect(((await (await createBudget(t, t.apiKey, { token: root.token })).json()) as { limitUsd: number }).limitUsd).toBe(40);
    const provider = await party();
    const cart = await attenuateToCart(root, provider.did, { spendLimitUsd: 30 }, agent.priv);
    expect(((await (await createBudget(t, t.apiKey, { token: cart.token })).json()) as { limitUsd: number }).limitUsd).toBe(30);
  });

  it("400 — a tampered or unverifiable token", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    const raw = JSON.parse(Buffer.from(m.token, "base64url").toString("utf8"));
    raw.mandate.constraints.spendLimitUsd = 1_000_000;
    const forged = Buffer.from(JSON.stringify(raw)).toString("base64url");
    expect((await createBudget(t, t.apiKey, { token: forged })).status).toBe(400);
    expect((await createBudget(t, t.apiKey, { token: "garbage" })).status).toBe(400);
  });

  it("400 — a mandate revoked at this registry", async () => {
    const t = await makeApp();
    const { m, human } = await intent(100);
    const revokedAt = new Date().toISOString();
    const sig = await ed.signAsync(new TextEncoder().encode(mandateRevocationPayload(m.mandate.mandateId, revokedAt)), human.priv);
    const rv = await t.app.request(`/v1/mandates/${encodeURIComponent(m.mandate.mandateId)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: m.token, revokedAt, revoker: human.did, signature: Buffer.from(sig).toString("base64url") }),
    }, t.env);
    expect(rv.status).toBe(200);
    expect((await createBudget(t, t.apiKey, { token: m.token })).status).toBe(400);
  });

  it("an earlier expiresAt shortens the budget; a later one does not extend it", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    const soon = Date.now() + 60_000;
    expect(((await (await createBudget(t, t.apiKey, { token: m.token, expiresAt: soon })).json()) as { expiresAt: number }).expiresAt).toBe(soon);
    const { m: m2 } = await intent(100);
    const late = Date.parse(m2.mandate.expiresAt) + 86_400_000;
    expect(((await (await createBudget(t, t.apiKey, { token: m2.token, expiresAt: late })).json()) as { expiresAt: number }).expiresAt)
      .toBe(Date.parse(m2.mandate.expiresAt));
  });

  it("201 — idempotent for the same key calling twice", async () => {
    const t = await makeApp();
    const { m } = await intent(50);
    await createBudget(t, t.apiKey, { token: m.token });
    const res2 = await createBudget(t, t.apiKey, { token: m.token });
    expect(res2.status).toBe(201);
    expect(await res2.json()).toMatchObject({ existing: true, limitUsd: 50 });
  });

  it("409 — a different key trying to claim the same mandate", async () => {
    const t = await makeApp();
    const key2 = await addKey(t.env, "Org2");
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    expect((await createBudget(t, key2, { token: m.token })).status).toBe(409);
  });

  it("the same mandateId under a different grantor is a different budget", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    const other = await party();
    // A mandate the attacker validly signed, reusing the victim's id.
    const raw = JSON.parse(Buffer.from(m.token, "base64url").toString("utf8"));
    const { mandateSigningPayloadV2 } = await import("@aroha-sdk/credentials");
    raw.mandate.grantor = other.did;
    const sig = await ed.signAsync(new TextEncoder().encode(mandateSigningPayloadV2(raw.mandate)), other.priv);
    raw.signature = Buffer.from(sig).toString("base64url");
    const squat = Buffer.from(JSON.stringify(raw)).toString("base64url");
    const key2 = await addKey(t.env, "Squatter");
    expect((await createBudget(t, key2, { token: squat })).status).toBe(201);
    // The victim's own budget is unaffected.
    expect((await createBudget(t, t.apiKey, { token: m.token })).status).toBe(201);
    expect(await (await status(t, t.apiKey, m)).json()).toMatchObject({ limitUsd: 100 });
  });

  it("records the creation in the audit log", async () => {
    const t = await makeApp();
    const { m } = await intent(10);
    await createBudget(t, t.apiKey, { token: m.token });
    await new Promise((r) => setTimeout(r, 10));
    const row = await (t.env.DB as SqliteD1)
      .prepare(`SELECT action, actor, target FROM admin_audit_log WHERE action = 'spending.budget_created'`)
      .first<{ action: string; actor: string; target: string }>();
    expect(row).toMatchObject({ actor: "Test Org" });
    expect(row!.target).toContain(`${m.mandate.grantor}#${m.mandate.mandateId}`);
  });

  it("401 — missing API key", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    const res = await t.app.request("/v1/spending/budgets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: m.token }),
    }, t.env);
    expect(res.status).toBe(401);
  });
});

// ─── POST /v1/spending/allocate ───────────────────────────────────────────────

describe("POST /v1/spending/allocate", () => {
  it("returns allocationId and remaining balance, and audits it", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    const res = await allocate(t, t.apiKey, m, 30);
    expect(res.status).toBe(200);
    const body = await res.json() as { allocationId: string; remainingUsd: number };
    expect(body.allocationId).toBeDefined();
    expect(body.remainingUsd).toBe(70);
    await new Promise((r) => setTimeout(r, 10));
    const row = await (t.env.DB as SqliteD1)
      .prepare(`SELECT target FROM admin_audit_log WHERE action = 'spending.allocated'`)
      .first<{ target: string }>();
    expect(row!.target).toContain(body.allocationId);
  });

  it("409 BUDGET_EXHAUSTED when over-allocating", async () => {
    const t = await makeApp();
    const { m } = await intent(50);
    await createBudget(t, t.apiKey, { token: m.token });
    await allocate(t, t.apiKey, m, 50);
    const res = await allocate(t, t.apiKey, m, 1);
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error: string }).error).toBe("BUDGET_EXHAUSTED");
  });

  it("400 without the grantor", async () => {
    const t = await makeApp();
    const { m } = await intent(50);
    await createBudget(t, t.apiKey, { token: m.token });
    const res = await t.app.request("/v1/spending/allocate", {
      method: "POST", headers: authHeaders(t.apiKey),
      body: JSON.stringify({ parentMandateId: m.mandate.mandateId, amountUsd: 1 }),
    }, t.env);
    expect(res.status).toBe(400);
  });

  it("403 when a different key attempts to allocate from another's budget", async () => {
    const t = await makeApp();
    const key2 = await addKey(t.env, "Alien");
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    expect((await allocate(t, key2, m, 10)).status).toBe(403);
  });

  it("410 BUDGET_EXPIRED when the budget's expiry has passed", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    await (t.env.DB as SqliteD1)
      .prepare(`UPDATE spending_budgets SET expires_at = ? WHERE mandate_id = ?`)
      .bind(Date.now() - 60_000, `${m.mandate.grantor}#${m.mandate.mandateId}`)
      .run();
    const res = await allocate(t, t.apiKey, m, 10);
    expect(res.status).toBe(410);
    expect(await res.json()).toMatchObject({ error: "BUDGET_EXPIRED" });
  });

  it("410 MANDATE_REVOKED once any link of the chain is revoked here", async () => {
    const t = await makeApp();
    const { m: root, human, agent } = await intent(100);
    const provider = await party();
    const cart = await attenuateToCart(root, provider.did, { spendLimitUsd: 60 }, agent.priv);
    await createBudget(t, t.apiKey, { token: cart.token });
    expect((await allocate(t, t.apiKey, cart, 10)).status).toBe(200);

    // The human revokes the ROOT; the cart's budget must stop allocating.
    const revokedAt = new Date().toISOString();
    const sig = await ed.signAsync(new TextEncoder().encode(mandateRevocationPayload(root.mandate.mandateId, revokedAt)), human.priv);
    expect((await t.app.request(`/v1/mandates/${encodeURIComponent(root.mandate.mandateId)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: root.token, revokedAt, revoker: human.did, signature: Buffer.from(sig).toString("base64url") }),
    }, t.env)).status).toBe(200);

    const res = await allocate(t, t.apiKey, cart, 10);
    expect(res.status).toBe(410);
    expect(await res.json()).toMatchObject({ error: "MANDATE_REVOKED" });
  });

  it("404 for an unknown mandate, and for a legacy (unverified-limit) budget", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    expect((await allocate(t, t.apiKey, m, 10)).status).toBe(404);
    // A pre-018 row: caller-chosen limit, limit_source defaulted to 'caller'.
    await (t.env.DB as SqliteD1)
      .prepare(`INSERT INTO spending_budgets (mandate_id, limit_usd, allocated_usd, owner_key_hash, expires_at, created_at) VALUES (?, 1000000, 0, ?, NULL, ?)`)
      .bind(`${m.mandate.grantor}#${m.mandate.mandateId}`, t.keyHash, Date.now())
      .run();
    expect((await allocate(t, t.apiKey, m, 10)).status).toBe(404);
    // Re-creating from the token replaces the legacy row with the verified limit.
    const res = await createBudget(t, t.apiKey, { token: m.token });
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ limitUsd: 100 });
    expect((await allocate(t, t.apiKey, m, 10)).status).toBe(200);
  });
});

// ─── POST /v1/spending/release/:allocationId ──────────────────────────────────

describe("POST /v1/spending/release/:allocationId", () => {
  function release(t: TestApp, m: SignedMandate, allocationId: string) {
    return t.app.request(`/v1/spending/release/${allocationId}`, {
      method: "POST",
      headers: authHeaders(t.apiKey),
      body: JSON.stringify({ parentMandateId: m.mandate.mandateId, grantor: m.mandate.grantor }),
    }, t.env);
  }

  it("restores the allocated amount to the budget pool", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    const { allocationId } = await (await allocate(t, t.apiKey, m, 40)).json() as { allocationId: string };
    const res = await release(t, m, allocationId);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ released: true, remainingUsd: 100 });
  });

  it("idempotent on double-release (released: false, no error)", async () => {
    const t = await makeApp();
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    const { allocationId } = await (await allocate(t, t.apiKey, m, 20)).json() as { allocationId: string };
    await release(t, m, allocationId);
    const res2 = await release(t, m, allocationId);
    expect(res2.status).toBe(200);
    expect(await res2.json()).toMatchObject({ released: false });
  });
});

// ─── GET /v1/spending/status/:mandateId ───────────────────────────────────────

describe("GET /v1/spending/status/:mandateId", () => {
  it("returns budget state after allocations", async () => {
    const t = await makeApp();
    const { m } = await intent(200);
    await createBudget(t, t.apiKey, { token: m.token });
    await allocate(t, t.apiKey, m, 75);
    const res = await status(t, t.apiKey, m);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ allocatedUsd: 75, remainingUsd: 125, allocationCount: 1, grantor: m.mandate.grantor });
  });

  it("403 when a different key queries another's budget", async () => {
    const t = await makeApp();
    const key2 = await addKey(t.env, "Spy");
    const { m } = await intent(100);
    await createBudget(t, t.apiKey, { token: m.token });
    expect((await status(t, key2, m)).status).toBe(403);
  });

  it("400 without ?grantor, 404 for an unknown mandate", async () => {
    const t = await makeApp();
    expect((await t.app.request(`/v1/spending/status/abc`, { headers: { Authorization: `Bearer ${t.apiKey}` } }, t.env)).status).toBe(400);
    const { m } = await intent(100);
    expect((await status(t, t.apiKey, m)).status).toBe(404);
  });
});
