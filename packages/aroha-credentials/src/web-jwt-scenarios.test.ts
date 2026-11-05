// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * End-to-end scenarios for web identities (spec §4.7) and the JWT form of a
 * mandate (spec §6.10), together and against real things where a test can
 * have them: a real HTTP server on loopback, the real global fetch, the
 * platform's DNS resolver, real Key Event Logs, a real spending ledger.
 * The unit tests beside this file stub the network; these do not.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { generateDid, incept, rotateKel, type KelEvent, type KelSource } from "@aroha-sdk/core";
import {
  attenuateTaskMandate,
  attenuateToCart,
  attenuateToPayment,
  createMandateKeyResolver,
  decodeMandateToken,
  issueIntentMandate,
  issueTaskMandate,
  verifyMandate,
  verifyMandateChain,
  verifyTaskMandate,
  type SignedMandate,
} from "./mandate.js";
import { governedVerification } from "./governed.js";
import { MANDATE_JWT_MAX_LENGTH, signMandateJwt } from "./mandate-jwt.js";
import { buildWebIdentityDocument, createWebIdentityResolver, ed25519PublicKeyToJwk, resolveWebIdentity } from "./web-identity.js";
import { HTTP_MANDATE_HEADER, InMemoryHttpPresentationNonces, presentMandateHttp, verifyHttpMandateRequest } from "./http-mandate.js";
import { verifyHttpSpendRequest } from "./http-spend.js";
import { MapSpendingLedger } from "./spending-ledger.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── A real server for identity documents ─────────────────────────────────────

type Handler = (res: import("node:http").ServerResponse) => void;
const routes = new Map<string, Handler>();
const hits: string[] = [];
let server: Server;
let origin: string;

beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  server = createServer((req, res) => {
    hits.push(req.url ?? "");
    const h = routes.get(req.url ?? "");
    if (typeof h === "function") return h(res);
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections?.();
  await new Promise((r) => server.close(r));
});

interface Party { priv: Uint8Array; pub: Uint8Array; id: string }

let serial = 0;
/** A party with a key, published at a fresh address on the real server. */
async function web(name = "agent"): Promise<Party> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  const path = `/${name}/${++serial}`;
  const id = `${origin}${path}`;
  publish(path, id, pub);
  return { priv, pub, id };
}

function publish(path: string, identity: string, publicKey: Uint8Array, headers: Record<string, string> = {}) {
  const body = JSON.stringify(buildWebIdentityDocument({ identity, publicKey, allowLoopbackHttp: true }));
  routes.set(path, (res) => res.writeHead(200, { "content-type": "application/json", ...headers }).end(body));
}

async function did(): Promise<Party> {
  const priv = ed.utils.randomPrivateKey();
  const pub = await ed.getPublicKeyAsync(priv);
  return { priv, pub, id: generateDid(pub) };
}

/** Real fetch, no address check for loopback (development mode), no cache unless asked. */
const webResolver = (over: Record<string, unknown> = {}) => createMandateKeyResolver({ web: { allowLoopbackHttp: true, maxCacheMs: 0, ...over } });

const forms = [["native", undefined], ["JWT", "jwt"]] as const;

// ─── Every combination of form and name ───────────────────────────────────────

describe.each(forms)("spending chain, %s form", (_name, format) => {
  const options = format ? { format } : {};

  it.each([
    ["web → web → web", [web, web, web]],
    ["did → web → did", [did, web, did]],
    ["web → did → web", [web, did, web]],
    ["did → did → did", [did, did, did]],
  ] as const)("verifies %s over a real server", async (_label, makers) => {
    const [root, middle, leaf] = await Promise.all(makers.map((m) => m()));
    const intent = await issueIntentMandate(root.id, middle.id, { spendLimitUsd: 500, allowedMerchants: ["m-ü", "m-2"], currency: "EUR" }, root.priv, 3_600_000, options);
    const cart = await attenuateToCart(intent, leaf.id, { spendLimitUsd: 300.5, allowedMerchants: ["m-ü"] }, middle.priv);
    const payment = await attenuateToPayment(cart, leaf.id, { spendLimitUsd: 0.01, allowedMerchants: ["m-ü"] }, leaf.priv);
    const r = await verifyMandateChain(payment.token, webResolver(), { expectedRoot: root.id, expectedGrantee: leaf.id, isRevoked: null });
    expect(r.valid, r.reason).toBe(true);
    expect(r.mandate?.constraints).toEqual({ spendLimitUsd: 0.01, allowedMerchants: ["m-ü"], currency: "EUR" });
    expect(r.chain).toHaveLength(3);
  });

  it("survives a round trip through decode and JSON, and can then be attenuated", async () => {
    const a = await web(), b = await web(), c = await web();
    const intent = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv, 3_600_000, options);
    const stored = JSON.parse(JSON.stringify(decodeMandateToken(intent.token))) as SignedMandate;
    const cart = await attenuateToCart(stored, c.id, { spendLimitUsd: 40 }, b.priv);
    expect((await verifyMandateChain(cart.token, webResolver(), { expectedRoot: a.id, isRevoked: null })).valid).toBe(true);
  });

  it("refuses a chain longer than maxDepth, and one at the limit passes", async () => {
    const parties = await Promise.all(Array.from({ length: 9 }, () => did()));
    let m = await issueIntentMandate(parties[0].id, parties[1].id, { spendLimitUsd: 100 }, parties[0].priv, 3_600_000, options);
    for (let i = 1; i < 7; i++) m = await attenuateToCart(m, parties[i + 1].id, { spendLimitUsd: 100 - i }, parties[i].priv);
    expect((await verifyMandateChain(m.token, undefined, { isRevoked: null, maxDepth: 7 })).valid).toBe(true);
    expect((await verifyMandateChain(m.token, undefined, { isRevoked: null, maxDepth: 6 })).valid).toBe(false);
  });

  it("charges every link through an HTTP spend, and refuses the cent over a parent's limit", async () => {
    const human = await web(), agent = await web(), a = await web(), b = await web();
    const ledger = new MapSpendingLedger();
    const resolveKey = webResolver();
    const intent = await issueIntentMandate(human.id, agent.id, { spendLimitUsd: 100 }, human.priv, 600_000, options);
    const cartA = await attenuateToCart(intent, a.id, { spendLimitUsd: 80 }, agent.priv);
    const cartB = await attenuateToCart(intent, b.id, { spendLimitUsd: 80 }, agent.priv);
    const request = { audience: "https://api.example.com", method: "POST", url: "https://api.example.com/pay", body: "{}" };

    const spend = async (m: SignedMandate, holder: Party, amountUsd: number) =>
      verifyHttpSpendRequest(
        (await presentMandateHttp({ token: m.token, holderDid: holder.id, holderPrivateKey: holder.priv, ...request }))[HTTP_MANDATE_HEADER],
        { ...request, url: "/pay", nonces: new InMemoryHttpPresentationNonces(), resolvePublicKey: resolveKey, resolveKey, expectedRoot: human.id, isRevoked: null, ledger, amountUsd },
      );

    expect(await spend(cartA, a, 60)).toMatchObject({ ok: true });
    // Sibling mandates share the parent's $100: $40 fits, the next cent does not.
    expect(await spend(cartB, b, 40.01)).toMatchObject({ ok: false, code: "OVER_LIMIT" });
    expect(await spend(cartB, b, 40)).toMatchObject({ ok: true });
    expect(await spend(cartA, a, 0.01)).toMatchObject({ ok: false, code: "OVER_LIMIT" });
  });
});

describe.each(forms)("task chain, %s form", (_name, format) => {
  it("verifies between web identities over a real server", async () => {
    const a = await web(), b = await web(), c = await web();
    const root = await issueTaskMandate(a.id, b.id, ["read", "archive"], { maxDelegationDepth: 2 }, a.priv, 3_600_000, format ? { format } : {});
    const child = await attenuateTaskMandate(root, c.id, ["read"], { maxDelegationDepth: 1 }, b.priv);
    const key = await createWebIdentityResolver({ allowLoopbackHttp: true })(b.id);
    const r = await verifyTaskMandate(child.token, key!, c.id);
    expect(r.valid, r.reason).toBe(true);
    expect(r.mandate?.allowed).toEqual(["read"]);
  });
});

// ─── Identity documents, for real ─────────────────────────────────────────────

describe("identity documents over real HTTP", () => {
  const opts = { allowLoopbackHttp: true };

  it("does not follow a real redirect to a valid document", async () => {
    const a = await web();
    const target = a.id.slice(origin.length);
    routes.set("/moved", (res) => res.writeHead(302, { location: target }).end());
    const before = hits.length;
    const r = await resolveWebIdentity(`${origin}/moved`, opts);
    expect(r.ok).toBe(false);
    expect(hits.slice(before)).toEqual(["/moved"]);
  });

  it("drops an oversized response that lies about its length, or sends none", async () => {
    routes.set("/huge", (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write(`{"pad":"${"x".repeat(64 * 1024)}`);
      res.end('"}');
    });
    const r = await resolveWebIdentity(`${origin}/huge`, opts);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/more than/);
  });

  it("gives up on a host that accepts and never answers", async () => {
    routes.set("/slow", () => undefined);
    const started = Date.now();
    const r = await resolveWebIdentity(`${origin}/slow`, { ...opts, timeoutMs: 100 });
    expect(r.ok).toBe(false);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("gives up on a host that sends half a body and stalls", async () => {
    routes.set("/stall", (res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"client_id":');
    });
    const started = Date.now();
    const r = await resolveWebIdentity(`${origin}/stall`, { ...opts, timeoutMs: 100 });
    expect(r.ok).toBe(false);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("refuses invalid UTF-8", async () => {
    routes.set("/latin1", (res) => res.writeHead(200).end(Buffer.from([0x7b, 0xff, 0x7d])));
    expect((await resolveWebIdentity(`${origin}/latin1`, opts)).ok).toBe(false);
  });

  it("reads the key set from a real jwks_uri, and refuses a host serving another's document", async () => {
    const a = await web();
    const id = `${origin}/indirect`;
    routes.set("/indirect", (res) => res.writeHead(200).end(JSON.stringify({ client_id: id, jwks_uri: `${origin}/keys?v=1` })));
    routes.set("/keys?v=1", (res) => res.writeHead(200).end(JSON.stringify({ keys: [ed25519PublicKeyToJwk(a.pub)] })));
    const r = await resolveWebIdentity(id, opts);
    expect(r.ok && Buffer.from(r.key).equals(Buffer.from(a.pub))).toBe(true);

    const stolen = `${origin}/stolen`;
    routes.set("/stolen", (res) => res.writeHead(200).end(JSON.stringify(buildWebIdentityDocument({ identity: a.id, publicKey: a.pub, allowLoopbackHttp: true }))));
    expect((await resolveWebIdentity(stolen, opts)).ok).toBe(false);
  });

  it("honours Cache-Control from a real response, and a key change takes effect", async () => {
    const a = await web();
    const path = a.id.slice(origin.length);
    const next = await did();
    publish(path, a.id, a.pub, { "cache-control": "max-age=60" });
    const resolve = createWebIdentityResolver(opts);
    const before = hits.length;
    expect(Buffer.from((await resolve(a.id))!).equals(Buffer.from(a.pub))).toBe(true);
    await resolve(a.id);
    expect(hits.length - before).toBe(1);

    publish(path, a.id, next.pub, { "cache-control": "no-store" });
    const fresh = createWebIdentityResolver(opts);
    expect(Buffer.from((await fresh(a.id))!).equals(Buffer.from(next.pub))).toBe(true);
    await fresh(a.id);
    expect(hits.length - before).toBe(3);
  });

  it("resolves many verifications of one chain concurrently and fails none", async () => {
    const a = await web(), b = await web();
    const intent = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 1 }, a.priv, 3_600_000, { format: "jwt" });
    const resolveKey = createMandateKeyResolver({ web: { allowLoopbackHttp: true } });
    const all = await Promise.all(Array.from({ length: 50 }, () => verifyMandateChain(intent.token, resolveKey, { isRevoked: null })));
    expect(all.every((r) => r.valid)).toBe(true);
  });
});

describe("internal addresses, through the platform resolver and real DNS", () => {
  it("never requests a loopback address named directly, even in a token", async () => {
    const a = await did();
    const before = hits.length;
    for (const id of [`https://127.0.0.1:${new URL(origin).port}/x`, "https://localhost/x", "https://[::1]/x", "https://2130706433/x", "https://0x7f.1/x", "http://169.254.169.254/latest/meta-data"]) {
      const m = await issueIntentMandate(id, "b", { spendLimitUsd: 1 }, a.priv);
      expect((await verifyMandateChain(m.token, createMandateKeyResolver({ web: true }), { isRevoked: null })).valid, id).toBe(false);
    }
    expect(hits.length).toBe(before);
  });

  it("refuses a public-looking name that really resolves to loopback (localtest.me)", async () => {
    const r = await resolveWebIdentity("https://localtest.me/agent");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/special-use address|could not be resolved/);
  });
});

// ─── Limits a token can reach ─────────────────────────────────────────────────

describe("limits", () => {
  it("an address at the length limit works through the whole chain", async () => {
    const a = await did();
    const path = `/${"a".repeat(1_900)}`;
    const id = `${origin}${path}`;
    expect(id.length).toBeLessThanOrEqual(2048);
    publish(path, id, a.pub);
    const m = await issueIntentMandate(id, "https://agents.example.com/b", { spendLimitUsd: 1 }, a.priv, 3_600_000, { format: "jwt" });
    expect((await verifyMandateChain(m.token, webResolver(), { expectedRoot: id, isRevoked: null })).valid).toBe(true);
  });

  it("an issuer cannot mint a JWT its own verifier would refuse", async () => {
    const a = await did(), b = await did();
    const allowedMerchants = Array.from({ length: 2_000 }, (_, i) => `https://merchant-${i}.example.com/checkout`);
    await expect(issueIntentMandate(a.id, b.id, { spendLimitUsd: 1, allowedMerchants }, a.priv, 3_600_000, { format: "jwt" })).rejects.toThrow(/too long|longer than/);
    expect(MANDATE_JWT_MAX_LENGTH).toBe(16 * 1024);
  });

  it("an eight-link JWT chain fits in an HTTP presentation", async () => {
    const parties = await Promise.all(Array.from({ length: 9 }, () => web()));
    let m = await issueIntentMandate(parties[0].id, parties[1].id, { spendLimitUsd: 100 }, parties[0].priv, 3_600_000, { format: "jwt" });
    for (let i = 1; i < 8; i++) m = await attenuateToCart(m, parties[i + 1].id, { spendLimitUsd: 100 - i }, parties[i].priv);
    const request = { audience: "https://api.example.com", method: "GET", url: "https://api.example.com/x", body: "" };
    const holder = parties[8];
    const header = (await presentMandateHttp({ token: m.token, holderDid: holder.id, holderPrivateKey: holder.priv, ...request }))[HTTP_MANDATE_HEADER];
    expect(header.length).toBeLessThan(32_768);
    const resolveKey = webResolver();
    const r = await verifyHttpMandateRequest(header, { ...request, url: "/x", nonces: new InMemoryHttpPresentationNonces(), resolvePublicKey: resolveKey, resolveKey, expectedRoot: parties[0].id, isRevoked: null });
    expect(r.ok, r.ok ? "" : r.reason).toBe(true);
  });
});

// ─── Governed chains and key rotation ─────────────────────────────────────────

describe("the governed profile with JWT-form chains", () => {
  async function world() {
    const alice = await incept({ kind: "person" });
    const shopper = await incept({ kind: "agent", controller: alice.did });
    const provider = await incept({ kind: "agent", controller: alice.did });
    const logs = new Map<string, KelEvent[]>([alice, shopper, provider].map((i) => [i.did, i.kel]));
    const kelSource: KelSource = async (id) => logs.get(id) ?? null;
    const intent = await issueIntentMandate(alice.did, shopper.did, { spendLimitUsd: 500 }, alice.privateKey, 3_600_000, { format: "jwt" });
    const cart = await attenuateToCart(intent, provider.did, { spendLimitUsd: 100 }, shopper.privateKey);
    return { alice, shopper, provider, logs, kelSource, intent, cart };
  }

  it("verifies an E-form person root through its Key Event Log", async () => {
    const w = await world();
    const profile = governedVerification({ kelSource: w.kelSource, isRevoked: async () => false, expectedRoot: w.alice.did });
    const r = await verifyMandateChain(w.cart.token, undefined, profile);
    expect(r.valid, r.reason).toBe(true);
  });

  it("refuses a JWT signed with a key the log has rotated away", async () => {
    const w = await world();
    const rotated = await rotateKel(w.shopper);
    w.logs.set(w.shopper.did, rotated.kel);
    const profile = governedVerification({ kelSource: w.kelSource, isRevoked: async () => false, expectedRoot: w.alice.did });
    expect((await verifyMandateChain(w.cart.token, undefined, profile)).valid).toBe(false);
  });

  it("a kid in the header does not choose the key", async () => {
    const w = await world();
    const thief = await did();
    const forged = await signMandateJwt("spending", w.intent.mandate as unknown as Record<string, unknown>, thief.priv, "the-real-kid");
    expect((await verifyMandateChain(forged, undefined, { kelSource: w.kelSource, isRevoked: null })).valid).toBe(false);
  });
});

// ─── Forms do not mix ─────────────────────────────────────────────────────────

describe("forms cannot be mixed or swapped", () => {
  it("refuses a JWT leaf on a native parent, and a native leaf in a JWT chain", async () => {
    const a = await did(), b = await did(), c = await did();
    const native = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv);
    const jwtRoot = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv, 3_600_000, { format: "jwt" });
    const jwtChild = await attenuateToCart(jwtRoot, c.id, { spendLimitUsd: 50 }, b.priv);
    expect((await verifyMandateChain(`${native.token}~${jwtChild.jwt}`, undefined, { isRevoked: null })).valid).toBe(false);
    expect((await verifyMandateChain(`${jwtRoot.jwt}~${native.token}`, undefined, { isRevoked: null })).valid).toBe(false);
  });

  it("a native signature does not verify as a JWT, nor a JWT signature as a native token", async () => {
    const a = await did(), b = await did();
    const native = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv);
    const jwt = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv, 3_600_000, { format: "jwt" });
    const swappedJwt = `${jwt.token.split(".").slice(0, 2).join(".")}.${native.signature}`;
    expect((await verifyMandateChain(swappedJwt, undefined, { isRevoked: null })).valid).toBe(false);
    const raw = JSON.parse(Buffer.from(native.token, "base64url").toString("utf8"));
    raw.signature = jwt.signature;
    expect((await verifyMandateChain(Buffer.from(JSON.stringify(raw)).toString("base64url"), undefined, { isRevoked: null })).valid).toBe(false);
  });

  it("a mandate's signature does not verify as a task mandate of the same grantor", async () => {
    const a = await did(), b = await did();
    const spending = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv, 3_600_000, { format: "jwt" });
    const task = await issueTaskMandate(a.id, b.id, ["x"], {}, a.priv, 3_600_000, { format: "jwt" });
    expect((await verifyTaskMandate(spending.token, a.pub)).valid).toBe(false);
    expect((await verifyMandate(task.token, a.pub, undefined, { isRevoked: null })).valid).toBe(false);
  });
});

// ─── The ledger keeps its keys ────────────────────────────────────────────────

describe("spending ledger with JWT-form mandates", () => {
  it("issuing against a ledger allocates from the parent the same way", async () => {
    const a = await did(), b = await did(), c = await did();
    const ledger = new MapSpendingLedger();
    const intent = await issueIntentMandate(a.id, b.id, { spendLimitUsd: 100 }, a.priv, 3_600_000, { ledger, format: "jwt" });
    await attenuateToCart(intent, c.id, { spendLimitUsd: 70 }, b.priv, undefined, { ledger });
    await expect(attenuateToCart(intent, c.id, { spendLimitUsd: 31 }, b.priv, undefined, { ledger })).rejects.toThrow();
    const ok = await attenuateToCart(intent, c.id, { spendLimitUsd: 30 }, b.priv, undefined, { ledger });
    expect(ok.allocationId).toBeDefined();
  });
});
