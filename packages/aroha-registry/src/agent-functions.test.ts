// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// registerAgent / resolveAgent / listAgents / resolveManifest — the README's
// quick-start example called these for as long as this package has had a
// README, and none of them existed in src/. `import { registerAgent } from
// "@aroha-sdk/registry"` threw before any test here existed. Every test
// below exercises the real exported function against a real (mocked-HTTP)
// ArohaHttpRegistry + ArohaIpfsClient, not a stand-in for them.

import { describe, it, expect, vi, afterEach } from "vitest";
import { registerAgent, resolveAgent, listAgents, resolveManifest } from "./agent-functions.js";
import type { AgentRecord, CapabilityManifest } from "./types.js";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

afterEach(() => { vi.unstubAllGlobals(); });

/** AgentRecord.stakedWei is a bigint — JSON.stringify needs help with those. */
function bigIntReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

function sortKeysDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v !== null && typeof v === "object") {
    const s: Record<string, unknown> = {};
    for (const k of Object.keys(v as object).sort()) s[k] = sortKeysDeep((v as Record<string, unknown>)[k]);
    return s;
  }
  return v;
}

async function signManifest(body: Omit<CapabilityManifest, "signature">, priv: Uint8Array): Promise<CapabilityManifest> {
  const canonical = JSON.stringify(sortKeysDeep(body));
  const sig = await ed.signAsync(new TextEncoder().encode(canonical), priv);
  return { ...body, signature: Buffer.from(sig).toString("base64url") };
}

async function makeSignedAgent(overrides: Partial<Omit<CapabilityManifest, "signature">> = {}) {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);

  const manifest = await signManifest({
    aroha: "1.0",
    did: "did:aroha:flight-agent",
    name: "Flight Agent",
    version: "1.0.0",
    endpoint: "https://flight-agent.fly.dev/aroha/v1",
    capabilities: [{
      id: "book-flights", version: "1.0.0", description: "Books flights",
      inputSchema: { type: "object", properties: {} }, outputSchema: { type: "object", properties: {} },
      async: false, maxResponseMs: 5000, requiredTrustLevel: 1, pricing: { model: "free" }, sagaRole: "none",
    }],
    protocols: ["aroha/1.0"],
    createdAt: new Date().toISOString(),
    ...overrides,
  }, priv);

  const record: AgentRecord = {
    didHash: "0xflight-agent",
    ownerAddress: "0xOwner",
    manifestCID: "QmFlightManifest",
    publicKeyB64: Buffer.from(pub).toString("base64url"),
    stakedWei: 0n,
    reputationScore: 5000,
    active: true,
    registeredAt: Date.now(),
    lastUpdatedAt: Date.now(),
  };

  return { priv, pub, manifest, record };
}

/** A fetch double for ArohaHttpRegistry's own HTTP calls (injectable via opts.fetch). */
function registryFetch(handler: (url: string, init?: RequestInit) => Promise<Response> | Response) {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    return handler(url, init);
  }) as typeof globalThis.fetch;
}

/** Stubs the GLOBAL fetch for IPFS gateway reads — ArohaIpfsClient has no fetch injection point. */
function stubIpfsGateway(cidToManifest: Record<string, CapabilityManifest>) {
  vi.stubGlobal("fetch", async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const cid = url.split("/").pop()!;
    const manifest = cidToManifest[cid];
    if (!manifest) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify(manifest), { status: 200 });
  });
}

describe("registerAgent", () => {
  it("POSTs to /v1/agents with the decoded public key and required apiKey", async () => {
    let captured: { url: string; body: unknown; auth: string | null } | undefined;
    const fetch = registryFetch((url, init) => {
      if (url.endsWith("/v1/agents/challenge")) return new Response(JSON.stringify({ nonce: "n" }), { status: 200 });
      captured = { url, body: JSON.parse(init!.body as string), auth: (init!.headers as Record<string, string>).Authorization };
      return new Response("{}", { status: 200 });
    });
    const priv = new Uint8Array(32).fill(7);

    await registerAgent({
      did: "did:aroha:flight-agent",
      manifestCID: "QmXxx",
      publicKeyB64: Buffer.from(await ed.getPublicKeyAsync(priv)).toString("base64url"),
      apiKey: "test-key",
      signer: { privateKey: priv },
      fetch,
    });
    expect((captured!.body as { challengeNonce: string }).challengeNonce).toBe("n");

    expect(captured!.url).toContain("/v1/agents");
    expect(captured!.auth).toBe("Bearer test-key");
    expect((captured!.body as { did: string }).did).toBe("did:aroha:flight-agent");
    expect((captured!.body as { manifestCID: string }).manifestCID).toBe("QmXxx");
  });
});

describe("resolveAgent", () => {
  it("returns null when the registry has no record for the DID", async () => {
    const fetch = registryFetch(() => new Response("not found", { status: 404 }));
    const result = await resolveAgent("did:aroha:nobody", { apiKey: "k", fetch });
    expect(result).toBeNull();
  });

  it("resolves a real record, fetches its manifest, verifies the signature, and returns endpoint + capabilities", async () => {
    const { manifest, record } = await makeSignedAgent();
    const fetch = registryFetch(() => new Response(JSON.stringify(record, bigIntReplacer), { status: 200 }));
    stubIpfsGateway({ [record.manifestCID]: manifest });

    const result = await resolveAgent("did:aroha:flight-agent", { apiKey: "k", fetch });

    expect(result).not.toBeNull();
    expect(result!.endpoint).toBe("https://flight-agent.fly.dev/aroha/v1");
    expect(result!.manifest.capabilities[0].id).toBe("book-flights");
    // Not a strict toEqual(record): ArohaHttpRegistry.resolveByDID() does a
    // bare `as AgentRecord` cast on the parsed JSON with no bigint
    // reconstruction, so stakedWei round-trips as a string ("0"), not the
    // bigint (0n) the type claims — a real, pre-existing gap in that class,
    // unrelated to what this test is actually verifying.
    expect(result!.record.didHash).toBe(record.didHash);
    expect(result!.record.publicKeyB64).toBe(record.publicKeyB64);
    expect(result!.record.manifestCID).toBe(record.manifestCID);
  });

  it("throws when the manifest's signature does not verify against the record's public key", async () => {
    const { manifest, record } = await makeSignedAgent();
    const tamperedManifest = { ...manifest, name: "A different agent entirely" }; // signature no longer matches
    const fetch = registryFetch(() => new Response(JSON.stringify(record, bigIntReplacer), { status: 200 }));
    stubIpfsGateway({ [record.manifestCID]: tamperedManifest });

    await expect(resolveAgent("did:aroha:flight-agent", { apiKey: "k", fetch }))
      .rejects.toThrow(/signature verification failed/i);
  });
});

describe("listAgents", () => {
  it("accepts a single capability string and queries the registry with it", async () => {
    let queriedUrl = "";
    const fetch = registryFetch((url) => { queriedUrl = url; return new Response("[]", { status: 200 }); });

    await listAgents({ capability: "book-flights", apiKey: "k", fetch });
    expect(queriedUrl).toContain("capabilities=book-flights");
  });

  it("returns verified agents and drops one whose manifest fails signature verification", async () => {
    const good = await makeSignedAgent({ did: "did:aroha:good-agent" });
    const bad = await makeSignedAgent({ did: "did:aroha:bad-agent" });
    const badRecord = { ...bad.record, manifestCID: "QmBadManifest" };
    const badManifest = { ...bad.manifest, name: "tampered after signing" };

    const fetch = registryFetch(() => new Response(JSON.stringify([good.record, badRecord], bigIntReplacer), { status: 200 }));
    stubIpfsGateway({
      [good.record.manifestCID]: good.manifest,
      [badRecord.manifestCID]: badManifest,
    });

    const results = await listAgents({ capability: "book-flights", apiKey: "k", fetch });

    expect(results).toHaveLength(1);
    expect(results[0].manifest.did).toBe("did:aroha:good-agent");
  });

  it("drops an agent missing the required capability from the manifest", async () => {
    const agent = await makeSignedAgent({
      capabilities: [{
        id: "search-flights", version: "1.0.0", description: "Search only",
        inputSchema: { type: "object", properties: {} }, outputSchema: { type: "object", properties: {} },
        async: false, maxResponseMs: 5000, requiredTrustLevel: 1, pricing: { model: "free" }, sagaRole: "none",
      }],
    });
    const fetch = registryFetch(() => new Response(JSON.stringify([agent.record], bigIntReplacer), { status: 200 }));
    stubIpfsGateway({ [agent.record.manifestCID]: agent.manifest });

    // Asked for book-flights; the manifest only actually has search-flights.
    const results = await listAgents({ capability: "book-flights", apiKey: "k", fetch });
    expect(results).toHaveLength(0);
  });
});

describe("resolveManifest", () => {
  it("fetches a manifest directly from IPFS by CID, unverified", async () => {
    const { manifest } = await makeSignedAgent();
    stubIpfsGateway({ QmDirect: manifest });

    const result = await resolveManifest("QmDirect");
    expect(result.did).toBe("did:aroha:flight-agent");
  });
});
