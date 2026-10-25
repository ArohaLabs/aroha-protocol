// Test helpers for agent registration under the registry's real rules.
//
// POST /v1/agents now requires, for every non-E-DID, a proof of key
// possession over a server-issued nonce (POST /v1/agents/challenge), and it
// only indexes capabilities from a manifest block whose bytes hash to its
// CID. Tests that are about something else entirely (visibility, grants,
// analytics…) should not each re-implement that, so they go through
// `postAgent`, which performs the challenge with a real Ed25519 key, and
// `manifestWith`, which mints a genuine CIDv0 for a capability list.

import { vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { isInceptionDid } from "@aroha-sdk/core/identity";
import { buildCIDv0 } from "./cid-builder.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

type RequestApp = { request: (path: string, init?: RequestInit, env?: unknown) => Response | Promise<Response> };

export function toB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)));
}

export async function newKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array; publicKeyB64: string }> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey, publicKeyB64: toB64(publicKey) };
}

/** A raw Ed25519 private key, a WebCrypto private key, or any signing function. */
export type Signer = Uint8Array | CryptoKey | ((message: Uint8Array) => Promise<Uint8Array>);

export async function signChallenge(signer: Signer, did: string, nonce: string): Promise<string> {
  const message = new TextEncoder().encode(JSON.stringify({ action: "prove-ownership", did, nonce }));
  if (signer instanceof Uint8Array) return toB64(await ed.signAsync(message, signer));
  if (typeof signer === "function") return toB64(await signer(message));
  return toB64(new Uint8Array(await crypto.subtle.sign("Ed25519", signer, message)));
}

// ─── Manifests ───────────────────────────────────────────────────────────────

const blocks = new Map<string, Uint8Array>();

/** A real CIDv0 for a manifest declaring these capabilities; served by `stubManifestFetch`. */
export async function manifestWith(capabilities: Array<string | { id: string }>): Promise<string> {
  const manifest = { capabilities: capabilities.map((c) => (typeof c === "string" ? { id: c } : c)) };
  const { cid, block } = await buildCIDv0(manifest);
  blocks.set(cid, block);
  return cid;
}

/**
 * Stub fetch as an IPFS gateway that honours Accept: application/vnd.ipld.raw
 * for every CID minted by `manifestWith`; anything else gets plain JSON
 * with no capabilities (which the registry, correctly, does not index).
 */
export function stubManifestFetch(): void {
  vi.stubGlobal("fetch", async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const cid = url.split("/").pop() ?? "";
    const block = blocks.get(cid);
    if (block) {
      return new Response(block, { status: 200, headers: { "Content-Type": "application/vnd.ipld.raw" } });
    }
    return new Response(JSON.stringify({ capabilities: [] }), { status: 200 });
  });
}

// ─── Registration ───────────────────────────────────────────────────────────

/**
 * POST /v1/agents with a genuine challenge proof.
 *
 * - `privateKey` given → it signs, and `body.publicKeyB64` is sent as-is
 *   (so a test can still pair a key with the wrong signer on purpose).
 * - no `privateKey` → a fresh keypair is generated and REPLACES
 *   `body.publicKeyB64`, since a placeholder key can never sign.
 * - E-DIDs, bodies that already carry a challenge, bodies without a did,
 *   and requests the API key cannot authenticate are sent untouched, so a
 *   test of the route's own error paths still sees exactly what it sent.
 */
export async function postAgent(
  app: RequestApp,
  env: unknown,
  apiKey: string,
  body: Record<string, unknown>,
  privateKey?: Signer,
): Promise<Response> {
  const send = (b: Record<string, unknown>) =>
    app.request("/v1/agents", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify(b),
    }, env);

  const did = body.did;
  if (typeof did !== "string" || isInceptionDid(did) || body.challengeNonce || body.challengeSignature) {
    return send(body);
  }

  let signer: Signer | undefined = privateKey;
  const out = { ...body };
  if (!signer) {
    const kp = await newKeypair();
    signer = kp.privateKey;
    if (out.publicKeyB64 !== undefined) out.publicKeyB64 = kp.publicKeyB64;
  }

  const challengeRes = await app.request("/v1/agents/challenge", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ did }),
  }, env);
  if (challengeRes.status !== 200) return send(out);
  const { nonce } = (await challengeRes.json()) as { nonce: string };
  out.challengeNonce = nonce;
  out.challengeSignature = await signChallenge(signer, did, nonce);
  return send(out);
}

/** postAgent + parse: the didHash and the key that now owns the DID. */
export async function registerAgent(
  app: RequestApp,
  env: unknown,
  apiKey: string,
  body: Record<string, unknown> & { did: string },
): Promise<{ status: number; didHash: string; privateKey: Uint8Array; publicKeyB64: string }> {
  const kp = await newKeypair();
  const res = await postAgent(app, env, apiKey, { manifestCID: "QmTest", ...body, publicKeyB64: kp.publicKeyB64 }, kp.privateKey);
  const json = (await res.json().catch(() => ({}))) as { didHash?: string };
  return { status: res.status, didHash: json.didHash ?? "", privateKey: kp.privateKey, publicKeyB64: kp.publicKeyB64 };
}

/**
 * Write an agent row directly, bypassing POST /v1/agents. Only for tests
 * that need a row with a key nobody holds the private half of (a fixed
 * cross-SDK test vector, say) — the route would rightly refuse to register
 * it, because nothing can prove possession.
 */
export async function seedAgentRow(
  env: { DB: unknown },
  row: { did: string; didHash: string; publicKeyB64: string; ownerKeyHash: string; visibility?: string },
): Promise<void> {
  const now = Date.now();
  await (env.DB as D1Database)
    .prepare(
      `INSERT INTO agent_records (did_hash, did, owner_key_hash, org_name, manifest_cid, public_key_b64,
         registered_at, last_updated_at, visibility)
       VALUES (?, ?, ?, 'Test Org', 'QmSeed', ?, ?, ?, ?)`,
    )
    .bind(row.didHash, row.did, row.ownerKeyHash, row.publicKeyB64, now, now, row.visibility ?? "public")
    .run();
}
