// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The admin secret is compared in constant time and fails closed; the
// credential key is derived from a separate secret when one is set.

import { describe, it, expect } from "vitest";
import { constantTimeEqual, credentialSigningKey, MIN_SECRET_LENGTH } from "./secrets.js";
import { makeApp } from "./test-utils/make-app.js";

describe("constantTimeEqual", () => {
  it("matches equal strings and rejects every kind of difference", async () => {
    expect(await constantTimeEqual("a".repeat(40), "a".repeat(40))).toBe(true);
    expect(await constantTimeEqual("a".repeat(40), "a".repeat(39) + "b")).toBe(false);
    expect(await constantTimeEqual("a".repeat(40), "a".repeat(41))).toBe(false);
    expect(await constantTimeEqual("", "a")).toBe(false);
  });
});

describe("admin routes fail closed on a weak or missing ADMIN_SECRET", () => {
  const weak = "short-secret";

  it("refuses with 503 when ADMIN_SECRET is unset — even for an empty bearer", async () => {
    const { app, env } = await makeApp();
    const res = await app.request(
      "/v1/admin/audit",
      { headers: { Authorization: "Bearer " } },
      { ...env, ADMIN_SECRET: undefined },
    );
    expect(res.status).toBe(503);
  });

  it(`refuses with 503 when ADMIN_SECRET is shorter than ${MIN_SECRET_LENGTH} chars, even when the token matches`, async () => {
    const { app, env } = await makeApp();
    const res = await app.request(
      "/v1/admin/audit",
      { headers: { Authorization: `Bearer ${weak}` } },
      { ...env, ADMIN_SECRET: weak },
    );
    expect(res.status).toBe(503);
    expect(await res.text()).not.toContain(weak);
  });

  it("403s a wrong secret and admits the right one", async () => {
    const { app, env } = await makeApp();
    const wrong = await app.request("/v1/admin/audit", { headers: { Authorization: "Bearer " + "z".repeat(40) } }, env);
    expect(wrong.status).toBe(403);
    const right = await app.request("/v1/admin/audit", { headers: { Authorization: `Bearer ${env.ADMIN_SECRET}` } }, env);
    expect(right.status).toBe(200);
  });

  it("applies the same rule to /health/caps", async () => {
    const { app, env } = await makeApp();
    const res = await app.request("/health/caps?cid=x", { headers: { Authorization: `Bearer ${weak}` } }, { ...env, ADMIN_SECRET: weak });
    expect(res.status).toBe(503);
  });
});

describe("credentialSigningKey", () => {
  async function sign(key: CryptoKey) {
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("probe")));
  }

  it("returns null when no usable secret exists", async () => {
    expect(await credentialSigningKey({})).toBeNull();
    expect(await credentialSigningKey({ ADMIN_SECRET: "short" })).toBeNull();
  });

  it("does not fall back to ADMIN_SECRET when CREDENTIAL_SECRET is set but too short", async () => {
    expect(await credentialSigningKey({ ADMIN_SECRET: "a".repeat(40), CREDENTIAL_SECRET: "short" })).toBeNull();
  });

  it("prefers CREDENTIAL_SECRET, so rotating ADMIN_SECRET leaves credentials intact", async () => {
    const credential = "c".repeat(40);
    const k1 = await credentialSigningKey({ ADMIN_SECRET: "a".repeat(40), CREDENTIAL_SECRET: credential });
    const k2 = await credentialSigningKey({ ADMIN_SECRET: "b".repeat(40), CREDENTIAL_SECRET: credential });
    expect(await sign(k1!)).toEqual(await sign(k2!));
  });

  it("derives a key that differs from one keyed by the raw secret", async () => {
    const secret = "a".repeat(40);
    const derived = await credentialSigningKey({ ADMIN_SECRET: secret });
    const raw = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    expect(await sign(derived!)).not.toEqual(await sign(raw));
  });
});
