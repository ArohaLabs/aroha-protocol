// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** T4/C2, N4, N1: registry server auth/bind defaults, https-only client, one managed URL. */

import { describe, it, expect } from "vitest";
import * as core from "@aroha-sdk/core/endpoints";
import { createArohaRegistryServer } from "./http-server.js";
import { ArohaHttpRegistry, httpKelSource, AROHA_MANAGED_REGISTRY_URL } from "./http-registry.js";
import * as ed from "@noble/ed25519";
import { generateDid } from "@aroha-sdk/core/identity";

describe("registration proof of possession, client <-> server end to end", () => {
  it("registers through the challenge exchange; refuses replays, wrong keys and missing proofs", async () => {
    const server = createArohaRegistryServer({ port: 47293, apiKey: "k" });
    await server.listen();
    try {
      const base = "http://127.0.0.1:47293";
      const priv = ed.utils.randomPrivateKey();
      const pub = await ed.getPublicKeyAsync(priv);
      const did = generateDid(pub);
      const reg = new ArohaHttpRegistry({ baseUrl: base, apiKey: "k" });
      await reg.register(did, "QmZ", pub, { signer: { privateKey: priv } });
      expect(await reg.resolveByDID(did)).toMatchObject({ manifestCID: "QmZ", active: true });

      // A callback signer (HSM/KMS-held key) works the same way.
      const priv2 = ed.utils.randomPrivateKey();
      const pub2 = await ed.getPublicKeyAsync(priv2);
      await reg.register("did:aroha:named-agent", "QmN", pub2, { signer: { sign: (m) => ed.signAsync(m, priv2) } });

      // A z-DID cannot be registered under a key it does not encode.
      await expect(reg.register(did, "QmZ", pub2, { signer: { privateKey: priv2 } }))
        .rejects.toThrow(/only be registered with the key it encodes/);

      // Server side: a signature by the wrong key, a reused nonce, and no proof are refused.
      const hdr = { "Content-Type": "application/json", Authorization: "Bearer k" };
      const ch = await fetch(`${base}/v1/agents/challenge`, { method: "POST", headers: hdr, body: JSON.stringify({ did: "did:aroha:x" }) });
      const { nonce } = (await ch.json()) as { nonce: string };
      const msg = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did: "did:aroha:x", nonce }));
      const body = {
        did: "did:aroha:x", manifestCID: "Qm", publicKeyB64: Buffer.from(pub).toString("base64url"),
        challengeNonce: nonce, challengeSignature: Buffer.from(await ed.signAsync(msg, priv2)).toString("base64url"),
      };
      expect((await fetch(`${base}/v1/agents`, { method: "POST", headers: hdr, body: JSON.stringify(body) })).status).toBe(403);
      const again = { ...body, challengeSignature: Buffer.from(await ed.signAsync(msg, priv)).toString("base64url") };
      expect((await fetch(`${base}/v1/agents`, { method: "POST", headers: hdr, body: JSON.stringify(again) })).status).toBe(403);
      const noProof = { did: "did:aroha:y", manifestCID: "Qm", publicKeyB64: Buffer.from(pub).toString("base64url") };
      expect((await fetch(`${base}/v1/agents`, { method: "POST", headers: hdr, body: JSON.stringify(noProof) })).status).toBe(400);
    } finally {
      await server.close();
    }
  });
});

describe("createArohaRegistryServer", () => {
  it("binds loopback by default and needs no apiKey there", () => {
    const s = createArohaRegistryServer({ port: 47290 });
    expect(s.hostname).toBe("127.0.0.1");
  });

  it("refuses a non-loopback bind without an apiKey", () => {
    expect(() => createArohaRegistryServer({ port: 47291, hostname: "0.0.0.0" })).toThrow(/apiKey is required/);
    expect(() => createArohaRegistryServer({ port: 47292, hostname: "0.0.0.0", apiKey: "k" })).not.toThrow();
  });
});

describe("ArohaHttpRegistry / httpKelSource", () => {
  it("refuses http:// to a remote registry, allows loopback and the opt-in", () => {
    expect(() => new ArohaHttpRegistry({ apiKey: "k", baseUrl: "http://r.example" })).toThrow(/registry URL/);
    expect(() => new ArohaHttpRegistry({ apiKey: "k", baseUrl: "https://r.example", fallbackUrls: ["http://m.example"] })).toThrow();
    expect(() => new ArohaHttpRegistry({ apiKey: "k", baseUrl: "http://localhost:3001" })).not.toThrow();
    expect(() => new ArohaHttpRegistry({ apiKey: "k", baseUrl: "http://r.example", allowInsecureHttp: true })).not.toThrow();
    expect(() => httpKelSource("http://r.example")).toThrow(/registry URL/);
  });

  it("re-exports core's single managed registry URL", () => {
    expect(AROHA_MANAGED_REGISTRY_URL).toBe(core.AROHA_MANAGED_REGISTRY_URL);
  });
});
