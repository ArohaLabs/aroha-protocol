// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Per-principal signing keys.
 *
 * WHY: hosted for many users, a single per-install key would make every user
 * the same grantor — every mandate the server issued would carry one DID, and
 * nothing could tell one person's authority from another's. Each principal
 * (the `sub` of a verified access token, qualified by its issuer) gets its own
 * Ed25519 key and content-addressed DID instead.
 *
 * The key store is pluggable: implement `PrincipalKeyStore` over an HSM, a
 * KMS or a vault. The default `FilePrincipalKeyStore` keeps one 0600 key file
 * per principal under `<dir>/principals/<sha256(principal)>/identity.key`
 * (directories 0700). The stdio transport's single local user keeps the
 * pre-existing `<dir>/identity.key`, so an upgrade keeps its DID.
 */

import { join } from "node:path";
import { createHash } from "node:crypto";
import { defaultIdentityDir, loadOrCreateIdentity, type McpIdentity } from "./identity.js";

/** The principal the stdio transport (one local user) signs as. */
export const LOCAL_PRINCIPAL = "local";

export interface PrincipalKeyStore {
  /**
   * The signing identity for `principal`, created on first use. Must return
   * the same key for the same principal across calls and restarts, and must
   * never return one principal's key for another.
   */
  get(principal: string): Promise<McpIdentity>;
}

/**
 * Build the principal identifier for an OAuth subject. The issuer is part of
 * it: the same `sub` from two authorization servers is two different people.
 */
export function principalFromToken(issuer: string | undefined, sub: string): string {
  return `${issuer ?? ""}|${sub}`;
}

/** File-backed default: one 0600 key file per principal. */
export class FilePrincipalKeyStore implements PrincipalKeyStore {
  private readonly cache = new Map<string, Promise<McpIdentity>>();

  constructor(private readonly dir: string = defaultIdentityDir()) {}

  /** The directory a principal's key lives in (the file name never contains the raw principal). */
  dirFor(principal: string): string {
    if (principal === LOCAL_PRINCIPAL) return this.dir;
    const digest = createHash("sha256").update(principal, "utf8").digest("hex");
    return join(this.dir, "principals", digest);
  }

  get(principal: string): Promise<McpIdentity> {
    if (typeof principal !== "string" || principal.length === 0) {
      return Promise.reject(new Error("PrincipalKeyStore: a principal is required"));
    }
    let entry = this.cache.get(principal);
    if (!entry) {
      entry = loadOrCreateIdentity(this.dirFor(principal));
      // A failed load is not cached: the next call retries instead of
      // pinning a transient filesystem error for the life of the process.
      entry.catch(() => this.cache.delete(principal));
      this.cache.set(principal, entry);
    }
    return entry;
  }
}
