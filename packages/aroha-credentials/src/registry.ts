// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — Human Credential Registry
 *
 * Stores signed HumanCredentials so that any agent in the network can
 * verify a human user's identity and roles by credential ID, without
 * requiring the full credential token to be re-sent on every message.
 *
 * Flow:
 *   1. Personal Agent issues a HumanCredential (issueHumanCredential)
 *   2. Personal Agent registers it in the registry  (CredentialRegistry.register)
 *   3. Human sends a Aroha message with credentialId in the body
 *   4. Provider agent looks up the credential (CredentialRegistry.resolve)
 *   5. Provider verifies the stored credential's signature and checks roles
 *
 * The registry is exposed as HTTP endpoints by ArohaServer when
 * ArohaServerOptions.credentialRegistry is set:
 *
 *   POST   /aroha/credentials          — register (verifies sig before storing)
 *   GET    /aroha/credentials/:id      — resolve by ID (public)
 *   DELETE /aroha/credentials/:id      — revoke (requires issuer proof header)
 *
 * Remote agents use CredentialRegistryClient to call these endpoints.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { type HumanCredential } from "./types.js";
import { verifyHumanCredential, isExpiredAt } from "./credentials.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── CredentialStore interface ────────────────────────────────────────────────

export interface CredentialStore {
  set(id: string, credential: HumanCredential): Promise<void> | void;
  get(id: string): Promise<HumanCredential | undefined> | HumanCredential | undefined;
  delete(id: string): Promise<boolean> | boolean;
  values(): AsyncIterable<HumanCredential> | Iterable<HumanCredential>;
}

// ─── Default in-process store ─────────────────────────────────────────────────

export class MapCredentialStore implements CredentialStore {
  private readonly store = new Map<string, HumanCredential>();

  set(id: string, credential: HumanCredential): void {
    this.store.set(id, credential);
  }

  get(id: string): HumanCredential | undefined {
    return this.store.get(id);
  }

  delete(id: string): boolean {
    return this.store.delete(id);
  }

  values(): Iterable<HumanCredential> {
    return this.store.values();
  }

  get size(): number { return this.store.size; }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

export class CredentialRegistry {
  private readonly store: CredentialStore;

  constructor(store: CredentialStore = new MapCredentialStore()) {
    this.store = store;
  }

  /**
   * Register a credential after verifying its Ed25519 signature.
   *
   * @param credential     The credential to store
   * @param issuerPublicKey  Ed25519 public key of credential.issuerDID (32 bytes)
   * @returns `true` if stored successfully, `false` if signature is invalid
   */
  async register(credential: HumanCredential, issuerPublicKey: Uint8Array): Promise<boolean> {
    const { serializeCredential } = await import("./credentials.js");
    const token = serializeCredential(credential);
    const result = await verifyHumanCredential(token, issuerPublicKey);
    if (!result.valid) return false;
    await this.store.set(credential.credentialId, credential);
    return true;
  }

  /**
   * Register a credential that has already been verified.
   * Use this when the calling code has already confirmed validity
   * (e.g., the issuing agent registering its own credential).
   */
  registerTrusted(credential: HumanCredential): void {
    this.store.set(credential.credentialId, credential);
  }

  /**
   * Resolve a credential by ID.
   * Returns null if not found, or if the credential has expired (auto-evicts).
   */
  resolve(credentialId: string): HumanCredential | null {
    const cred = this.store.get(credentialId);
    if (!cred) return null;
    if (cred instanceof Promise) return null; // async store: use async resolveAsync instead
    const credTyped = cred as HumanCredential;
    if (isExpiredAt(credTyped.expiresAt)) {
      this.store.delete(credentialId); // evict expired
      return null;
    }
    return credTyped;
  }

  /**
   * Revoke a credential by ID.
   * @returns `true` if it existed and was removed, `false` if not found
   */
  revoke(credentialId: string): boolean {
    const result = this.store.delete(credentialId);
    if (result instanceof Promise) return false;
    return result as boolean;
  }

  /**
   * List all active (non-expired) credentials for a given userId.
   */
  listForUser(userId: string): HumanCredential[] {
    const now = Date.now();
    const results: HumanCredential[] = [];
    const vals = this.store.values();
    for (const cred of vals as Iterable<HumanCredential>) {
      if (cred.userId === userId && !isExpiredAt(cred.expiresAt, now)) {
        results.push(cred);
      }
    }
    return results;
  }

  /** Total number of stored credentials (including potentially expired ones). */
  get size(): number {
    const s = this.store as MapCredentialStore;
    return s.size ?? 0;
  }

  /**
   * Evict all expired credentials. Called periodically to free memory.
   * Returns the number of credentials evicted.
   */
  evictExpired(): number {
    const now = Date.now();
    let count = 0;
    const vals = this.store.values();
    for (const cred of vals as Iterable<HumanCredential>) {
      if (isExpiredAt(cred.expiresAt, now)) {
        this.store.delete(cred.credentialId);
        count++;
      }
    }
    return count;
  }
}

// ─── HTTP Client ───────────────────────────────────────────────────────────────

/**
 * HTTP client for remote credential registry lookups.
 *
 * Any agent can use this to query the registry hosted by a Personal Agent
 * (or any ArohaServer with credentialRegistry configured).
 */
export class CredentialRegistryClient {
  constructor(private readonly baseUrl: string) {}

  /**
   * Register a credential in the remote registry.
   * The registry will verify the credential's signature before storing.
   */
  async register(credential: HumanCredential): Promise<{ ok: boolean; reason?: string }> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(credential),
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    return { ok: false, reason: String(body.error ?? res.statusText) };
  }

  /**
   * Resolve a credential by ID from the remote registry.
   * Returns null if not found or expired.
   */
  async resolve(credentialId: string): Promise<HumanCredential | null> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials/${encodeURIComponent(credentialId)}`);
    if (!res.ok) return null;
    return res.json() as Promise<HumanCredential>;
  }

  /**
   * Revoke a credential.
   *
   * The caller must provide a revocation proof: a base64url Ed25519 signature
   * over `{credentialId, action:"revoke"}` using the issuer's private key.
   * This is checked server-side before deletion.
   */
  async revoke(credentialId: string, revokeProof: string): Promise<{ ok: boolean; reason?: string }> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials/${encodeURIComponent(credentialId)}`, {
      method: "DELETE",
      headers: { "X-Revoke-Proof": revokeProof },
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({})) as Record<string, unknown>;
    return { ok: false, reason: String(body.error ?? res.statusText) };
  }

  /**
   * List all active credentials for a userId.
   */
  async listForUser(userId: string): Promise<HumanCredential[]> {
    const res = await fetch(`${this.baseUrl}/aroha/credentials?userId=${encodeURIComponent(userId)}`);
    if (!res.ok) return [];
    return res.json() as Promise<HumanCredential[]>;
  }
}

// ─── Revoke proof helpers ──────────────────────────────────────────────────────

/**
 * Build a revocation proof to pass to CredentialRegistryClient.revoke().
 * Signs `{action:"revoke",credentialId}` with the issuer's private key.
 */
export async function buildRevokeProof(
  credentialId: string,
  issuerPrivateKey: Uint8Array
): Promise<string> {
  const payload = JSON.stringify({ action: "revoke", credentialId });
  const bytes = new TextEncoder().encode(payload);
  const sig = await ed.signAsync(bytes, issuerPrivateKey);
  return Buffer.from(sig).toString("base64url");
}

/**
 * Verify a revocation proof server-side.
 */
export async function verifyRevokeProof(
  credentialId: string,
  proof: string,
  issuerPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const payload = JSON.stringify({ action: "revoke", credentialId });
    const bytes = new TextEncoder().encode(payload);
    const sig = Buffer.from(proof, "base64url");
    return await ed.verifyAsync(sig, bytes, issuerPublicKey);
  } catch {
    return false;
  }
}
