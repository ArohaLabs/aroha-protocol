/**
 * HTTP route tests for /v1/sar — the full Hono request/response cycle
 * against an in-memory SQLite database, matching the pattern in
 * agents.test.ts. A SAR built by @aroha-sdk/registry's client code must
 * verify here end to end. The route verifies with the same package's
 * Worker-safe `@aroha-sdk/registry/sar` subpath (it once carried an
 * independent WebCrypto copy, now deleted), so what these tests pin is the
 * route's wiring and its own rules — no auth, shape before crypto, replace
 * on republish, expiry on query — rather than agreement between two copies.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPair, generateDid, generateDID } from "@aroha-sdk/core";
import { buildSar } from "@aroha-sdk/registry";
import { makeApp } from "../test-utils/make-app.js";

async function contentAddressed() {
  const kp = await generateKeyPair();
  return { did: generateDid(kp.publicKey), ...kp };
}

describe("POST /v1/sar — interop with the real @aroha-sdk/registry client", () => {
  it("accepts a SAR built by the reference implementation, no auth required", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({
      did: a.did,
      privateKey: a.privateKey,
      capabilities: ["book-flight"],
      transports: [`http://127.0.0.1/${a.did}`],
    });

    // Deliberately no Authorization header — publishing a SAR must not
    // require an API key (spec §7.4's whole point).
    const res = await app.request(
      "/v1/sar",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) },
      env,
    );
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true, did: a.did });
  });

  it("rejects a SAR with a tampered field", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["cheap"] });
    const tampered = { ...sar, capabilities: ["expensive", "drain-wallet"] };

    const res = await app.request(
      "/v1/sar",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(tampered) },
      env,
    );
    expect(res.status).toBe(422);
  });

  it("rejects a namespaced (non-content-addressed) DID — self-certifying only", async () => {
    const { app, env } = await makeApp();
    const identity = await generateDID("acme.research-agent", "http://127.0.0.1/x");
    const sar = await buildSar({ did: identity.did, privateKey: identity.privateKey });

    const res = await app.request(
      "/v1/sar",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) },
      env,
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("not_self_certifying");
  });

  it("rejects a correctly SIGNED record whose capabilities are not strings (shape before crypto)", async () => {
    // A valid signature over junk is still junk: the index stores and queries
    // capabilities as strings (json_each in querySar), so the package's
    // hasSarShape refuses it before any signature check.
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: [{ id: "x" }] as never });
    const res = await app.request(
      "/v1/sar",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) },
      env,
    );
    expect(res.status).toBe(422);
    expect(await res.json()).toEqual({ error: "SAR rejected: bad_shape" });
  });

  it("rejects malformed JSON", async () => {
    const { app, env } = await makeApp();
    const res = await app.request(
      "/v1/sar",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" },
      env,
    );
    expect(res.status).toBe(400);
  });

  it("republishing the same DID replaces the prior record, not duplicates it", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const v1 = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["v1"] });
    await new Promise((r) => setTimeout(r, 5));
    const v2 = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["v2"] });

    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(v1) }, env);
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(v2) }, env);

    const res = await app.request(`/v1/sar?did=${encodeURIComponent(a.did)}`, {}, env);
    const body = (await res.json()) as { records: Array<{ capabilities: string[] }> };
    expect(body.records).toHaveLength(1);
    expect(body.records[0].capabilities).toEqual(["v2"]);
  });
});

describe("GET /v1/sar — public, no auth required", () => {
  it("queries by capability", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const b = await contentAddressed();
    const sarA = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["book-flight"] });
    const sarB = await buildSar({ did: b.did, privateKey: b.privateKey, capabilities: ["book-hotel"] });
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sarA) }, env);
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sarB) }, env);

    const res = await app.request("/v1/sar?capability=book-flight", {}, env);
    const body = (await res.json()) as { records: Array<{ did: string }> };
    expect(body.records.map((r) => r.did)).toEqual([a.did]);
  });

  it("does not false-positive on a capability substring", async () => {
    // json_each equality, not LIKE — "book-flight-refundable" must not match
    // a query for "book-flight".
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["book-flight-refundable"] });
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) }, env);

    const res = await app.request("/v1/sar?capability=book-flight", {}, env);
    const body = (await res.json()) as { records: unknown[] };
    expect(body.records).toHaveLength(0);
  });

  it("excludes an expired record", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["short-lived"], ttlMs: 1 });
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) }, env);
    await new Promise((r) => setTimeout(r, 20));

    const res = await app.request("/v1/sar?capability=short-lived", {}, env);
    const body = (await res.json()) as { records: unknown[] };
    expect(body.records).toHaveLength(0);
  });

  it("returns everything with no filter", async () => {
    const { app, env } = await makeApp();
    const a = await contentAddressed();
    const sar = await buildSar({ did: a.did, privateKey: a.privateKey, capabilities: ["x"] });
    await app.request("/v1/sar", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sar) }, env);

    const res = await app.request("/v1/sar", {}, env);
    const body = (await res.json()) as { records: Array<{ did: string }> };
    expect(body.records.some((r) => r.did === a.did)).toBe(true);
  });
});
