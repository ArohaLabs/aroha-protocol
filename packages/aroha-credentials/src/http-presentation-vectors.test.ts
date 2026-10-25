// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Holds test-vectors/http-presentation-v1.json (scripts/gen-http-presentation-vectors.ts)
 * to the reference: every target, body hash, signing payload, proof and header
 * value must still be what this package computes, and every refusal must
 * still carry its code. The Python SDK checks the same file.
 */

import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  HTTP_MANDATE_HEADER,
  HTTP_MANDATE_PRESENTATION_PURPOSE,
  InMemoryHttpPresentationNonces,
  httpBodySha256,
  httpMethodForProof,
  httpPresentationSigningPayload,
  httpRequestTarget,
  presentMandateHttp,
  verifyHttpMandateRequest,
  verifyHttpPresentation,
} from "./http-mandate.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("../test-vectors/http-presentation-v1.json", import.meta.url)), "utf8"));
const fromHex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const bytes = (b64u: string) => new Uint8Array(Buffer.from(b64u, "base64url"));
const ctx = (v: { audience: string; method: string; url: string; body: string; now: string }) => ({
  ...v, body: bytes(v.body), now: Date.parse(v.now), nonces: new InMemoryHttpPresentationNonces(),
});

describe("http-presentation-v1 vectors", () => {
  it("constants", () => {
    expect(V.header).toBe(HTTP_MANDATE_HEADER);
    expect(V.purpose).toBe(HTTP_MANDATE_PRESENTATION_PURPOSE);
  });

  it("presentations are reproduced byte for byte and verify", async () => {
    expect(V.presentations.length).toBeGreaterThanOrEqual(4);
    for (const c of V.presentations) {
      const k = V.keys[c.present.holder];
      const e = c.expected;
      expect(httpMethodForProof(c.present.method), c.name).toBe(e.method);
      expect(httpRequestTarget(c.present.url), c.name).toBe(e.target);
      expect(httpRequestTarget(c.verify.url), c.name).toBe(e.target);
      expect(httpBodySha256(bytes(c.present.body)), c.name).toBe(e.bodySha256);
      const mandateId = JSON.parse(Buffer.from(V.tokens[c.present.token], "base64url").toString("utf8")).mandate.mandateId;
      expect(httpPresentationSigningPayload({
        audience: V.audience, method: e.method, target: e.target, bodySha256: e.bodySha256,
        mandateId, holder: k.did, nonce: c.present.nonce, expires: e.expires,
      }), c.name).toBe(e.signingPayload);
      const h = (await presentMandateHttp({
        token: V.tokens[c.present.token], holderDid: k.did, holderPrivateKey: fromHex(k.privateKeyHex),
        audience: V.audience, method: c.present.method, url: c.present.url, body: bytes(c.present.body),
        ttlMs: c.present.ttlMs, nonce: c.present.nonce, now: Date.parse(V.presentedAt),
      }))[HTTP_MANDATE_HEADER];
      expect(h, c.name).toBe(e.headerValue);
      expect(Buffer.from(h, "base64url").toString("utf8"), c.name).toBe(e.headerJson);
      expect(JSON.parse(e.headerJson).proof, c.name).toBe(e.proof);
      const r = await verifyHttpPresentation(h, ctx(c.verify));
      expect(r.ok ? { ok: true, holder: r.holder } : r, c.name).toEqual(e.verify);
    }
  });

  it("refusals carry their codes", async () => {
    expect(V.refusals.length).toBeGreaterThanOrEqual(25);
    for (const c of V.refusals) {
      const r = await verifyHttpPresentation(c.headerValue, ctx(c.verify));
      expect(r.ok ? "ok" : r.code, c.name).toBe(c.expectedCode);
    }
  });

  it("replay", async () => {
    const c = V.replay;
    const nonces = new InMemoryHttpPresentationNonces();
    const codes = [];
    for (let i = 0; i < c.expectedCodes.length; i++) {
      const r = await verifyHttpPresentation(c.headerValue, { ...ctx(c.verify), nonces });
      codes.push(r.ok ? null : r.code);
    }
    expect(codes).toEqual(c.expectedCodes);
  });

  it("mandate requests", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    for (const c of V.mandateRequests) {
      const r = await verifyHttpMandateRequest(c.headerValue, {
        ...ctx(c.verify), expectedRoot: c.expectedRoot, trustedRoots: c.trustedRoots, isRevoked: null,
      });
      const summary = r.ok
        ? { ok: true, holder: r.holder, rootGrantor: r.rootGrantor, mandateId: r.mandate.mandateId }
        : { ok: false, code: r.code, status: r.status };
      expect(summary, c.name).toEqual(c.expected);
    }
  });
});
