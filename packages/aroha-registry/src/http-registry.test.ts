// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ArohaHttpRegistry and httpKelSource against a stubbed fetch: request
 * shape, DID hashing, fallback rules (5xx/network → next mirror, 4xx →
 * stop), and the KEL source's fail-closed handling of 409.
 */

import { describe, it, expect, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import { incept, resolveKelState } from "@aroha-sdk/core";
import * as ed from "@noble/ed25519";
import { ArohaHttpRegistry, RegistryHttpError, httpKelSource } from "./http-registry.js";

const PRIV = new Uint8Array(32).fill(3);
const PUB = await ed.getPublicKeyAsync(PRIV);

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const didHash = (did: string) => "0x" + bytesToHex(keccak_256(new TextEncoder().encode(did)));

type Call = { url: string; init?: RequestInit };
function stub(handler: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const calls: Call[] = [];
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return handler(url, init);
  });
  return { calls, fetch: fetch as unknown as typeof globalThis.fetch };
}

describe("ArohaHttpRegistry", () => {
  it("register runs the challenge exchange and POSTs the signed record with the API key", async () => {
    const s = stub((url) => (url.endsWith("/challenge") ? json(200, { nonce: "n-1", expiresAt: 0 }) : json(201, {})));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://r.example/", apiKey: "k1", fetch: s.fetch });
    await reg.register("did:aroha:a", "QmCID", PUB, { capabilityIds: ["x"], signer: { privateKey: PRIV } });
    expect(s.calls[0].url).toBe("https://r.example/v1/agents/challenge");
    expect(JSON.parse(String(s.calls[0].init?.body))).toEqual({ did: "did:aroha:a" });
    expect(s.calls[1].url).toBe("https://r.example/v1/agents");
    expect(s.calls[1].init?.method).toBe("POST");
    expect((s.calls[1].init?.headers as Record<string, string>).Authorization).toBe("Bearer k1");
    const body = JSON.parse(String(s.calls[1].init?.body));
    // capabilityIds are no longer sent — the server indexes them from the verified manifest.
    expect(Object.keys(body).sort()).toEqual(["challengeNonce", "challengeSignature", "did", "manifestCID", "publicKeyB64"]);
    expect(body.publicKeyB64).toBe(Buffer.from(PUB).toString("base64url"));
    expect(body.challengeNonce).toBe("n-1");
    const msg = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did: "did:aroha:a", nonce: "n-1" }));
    expect(await ed.verifyAsync(Buffer.from(body.challengeSignature, "base64url"), msg, PUB)).toBe(true);
  });

  it("register refuses without a signer, and with a signer that does not hold the key", async () => {
    const s = stub(() => json(201, {}));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://r.example", apiKey: "k", fetch: s.fetch });
    await expect(reg.register("did:aroha:a", "Qm", PUB)).rejects.toThrow(/signer is required/);
    await expect(reg.register("did:aroha:a", "Qm", PUB, { signer: { privateKey: new Uint8Array(32).fill(9) } }))
      .rejects.toThrow(/does not match/);
    expect(s.calls).toHaveLength(0);
  });

  it("deactivate / updateManifest address the keccak DID hash", async () => {
    const s = stub(() => json(200, {}));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://r.example", apiKey: "k", fetch: s.fetch });
    await reg.deactivate("did:aroha:a");
    await reg.updateManifest("did:aroha:a", "QmNew");
    expect(s.calls[0]).toMatchObject({ url: `https://r.example/v1/agents/${didHash("did:aroha:a")}`, init: { method: "DELETE" } });
    expect(s.calls[1].url).toBe(`https://r.example/v1/agents/${didHash("did:aroha:a")}/manifest`);
    expect(JSON.parse(String(s.calls[1].init?.body))).toEqual({ manifestCID: "QmNew" });
  });

  it("resolveByDID: 404 → null, 200 → record", async () => {
    const reg404 = new ArohaHttpRegistry({ baseUrl: "https://r.example", apiKey: "k", fetch: stub(() => json(404, {})).fetch });
    expect(await reg404.resolveByDID("did:aroha:x")).toBeNull();
    const reg200 = new ArohaHttpRegistry({ baseUrl: "https://r.example", apiKey: "k", fetch: stub(() => json(200, { did: "did:aroha:x", active: true })).fetch });
    expect(await reg200.resolveByDID("did:aroha:x")).toMatchObject({ did: "did:aroha:x" });
  });

  it("queryByCapability encodes each id", async () => {
    const s = stub(() => json(200, []));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://r.example", apiKey: "k", fetch: s.fetch });
    await reg.queryByCapability(["a b", "c,d"]);
    expect(s.calls[0].url).toBe("https://r.example/v1/agents?capabilities=a%20b,c%2Cd");
  });

  it("falls back to the next URL on 5xx and network errors", async () => {
    let n = 0;
    const s = stub((url) => {
      n++;
      if (url.startsWith("https://primary")) return json(503, { error: "down" });
      if (url.startsWith("https://mirror1")) throw new TypeError("fetch failed");
      return json(200, { did: "did:aroha:x" });
    });
    const reg = new ArohaHttpRegistry({
      baseUrl: "https://primary", fallbackUrls: ["https://mirror1", "https://mirror2/"], apiKey: "k", fetch: s.fetch,
    });
    expect(await reg.resolveByDID("did:aroha:x")).toMatchObject({ did: "did:aroha:x" });
    expect(n).toBe(3);
  });

  it("does NOT fall back on a 4xx (a caller error, not an outage)", async () => {
    const s = stub(() => json(401, { error: "bad key" }));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://primary", fallbackUrls: ["https://mirror"], apiKey: "k", fetch: s.fetch });
    await expect(reg.register("did:aroha:a", "Qm", PUB, { signer: { privateKey: PRIV } })).rejects.toBeInstanceOf(RegistryHttpError);
    expect(s.calls).toHaveLength(1);
  });

  it("throws the last error when every URL fails", async () => {
    const s = stub(() => json(500, { error: "boom" }));
    const reg = new ArohaHttpRegistry({ baseUrl: "https://a", fallbackUrls: ["https://b"], apiKey: "k", fetch: s.fetch });
    await expect(reg.queryByCapability(["x"])).rejects.toMatchObject({ statusCode: 500 });
  });
});

describe("httpKelSource", () => {
  it("returns the stored events, which the caller then verifies", async () => {
    const person = await incept({ kind: "person" });
    const s = stub(() => json(200, { did: person.did, events: person.kel, sequence: 0 }));
    const source = httpKelSource("https://r.example/", { fetch: s.fetch });
    expect(s.calls).toHaveLength(0);
    const state = await resolveKelState(person.did, source);
    expect(state?.kind).toBe("person");
    expect(s.calls[0].url).toBe(`https://r.example/v1/kel/${encodeURIComponent(person.did)}`);
  });

  it("404 → null", async () => {
    const source = httpKelSource("https://r.example", { fetch: stub(() => json(404, { error: "Not found" })).fetch });
    expect(await source("did:aroha:Exyz")).toBeNull();
  });

  it("409 (duplicity / stale) throws so verifiers fail closed — and is not retried on a mirror", async () => {
    const s = stub(() => json(409, { code: "duplicity" }));
    const source = httpKelSource("https://a", { fallbackUrls: ["https://b"], fetch: s.fetch });
    await expect(source("did:aroha:Exyz")).rejects.toMatchObject({ statusCode: 409 });
    expect(s.calls).toHaveLength(1);
  });

  it("rejects an answer for a different DID", async () => {
    const source = httpKelSource("https://r.example", { fetch: stub(() => json(200, { did: "did:aroha:Eother", events: [] })).fetch });
    await expect(source("did:aroha:Exyz")).rejects.toThrow(/not did:aroha:Exyz/);
  });

  it("tries fallbacks on 5xx / network errors", async () => {
    const person = await incept({ kind: "person" });
    const s = stub((url) => (url.startsWith("https://a") ? json(502, {}) : json(200, { did: person.did, events: person.kel })));
    const source = httpKelSource("https://a", { fallbackUrls: ["https://b"], fetch: s.fetch });
    expect(await source(person.did)).toEqual(person.kel);
  });
});
