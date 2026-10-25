// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Agent certification tier and the facts behind it — "know your agent"
 * inputs a counterparty can check, not a judgement about behaviour.
 *
 * TIERS, lowest to highest; an agent's tier is the highest whose fact holds:
 *
 *   unverified          registered, nothing further proven (or inactive)
 *   domain_verified     the owner proved a domain names this DID
 *                       (POST /v1/agents/:didHash/verify-domain)
 *   kel_person_rooted   a rotatable E-DID whose verified Key Event Log names
 *                       a person controller; neither log is revoked and
 *                       neither has a recorded duplicity alarm
 *   audited             an operator recorded an independent audit
 *                       (POST /v1/agents/:didHash/audited, admin secret)
 *
 * Every fact is returned beside the tier, so a relying party can apply its
 * own policy (for example, "audited AND kel_person_rooted") instead of
 * trusting the ordering.
 *
 * WHAT THIS IS NOT. Not a reputation score, a safety rating, or a statement
 * that an agent behaves well. "audited" records only that an operator
 * entered an audit reference; the registry does not assess the audit.
 */

import { isInceptionDid, resolveKelState, type KelState } from "@aroha-sdk/core/identity";
import type { AgentRow, RegistryRepository } from "./repository.js";
import { RepositoryKelStore } from "./kel-store.js";
import { kelSourceFor, registryKeyResolver } from "./routes/mandates.js";

export type CertificationTier = "unverified" | "domain_verified" | "kel_person_rooted" | "audited";
export const CERTIFICATION_TIERS: readonly CertificationTier[] = [
  "unverified", "domain_verified", "kel_person_rooted", "audited",
];

export interface AgentFacts {
  active: boolean;
  domainVerified: boolean;
  domain: string | null;
  kelPersonRooted: boolean;
  controller: string | null;
  audited: boolean;
  auditedAt: string | null;
  auditReference: string | null;
}

/** Verified KEL state for an E-DID, or null (not an E-DID, nothing stored, or it does not verify). */
export async function verifiedKelState(repo: RegistryRepository, did: string): Promise<KelState | null> {
  if (!isInceptionDid(did)) return null;
  try {
    return await resolveKelState(did, kelSourceFor(repo));
  } catch {
    return null;
  }
}

export async function computeAgentFacts(db: D1Database, repo: RegistryRepository, row: AgentRow): Promise<AgentFacts> {
  const audit = await db
    .prepare(`SELECT audited_at, audit_reference FROM agent_records WHERE did_hash = ?`)
    .bind(row.didHash)
    .first<{ audited_at: number | null; audit_reference: string | null }>();

  let kelPersonRooted = false;
  let controller: string | null = null;
  if (isInceptionDid(row.did)) {
    const state = await verifiedKelState(repo, row.did);
    if (state && state.controller && !state.revoked && !state.controllerRevoked) {
      const store = new RepositoryKelStore(repo);
      const alarms = await Promise.all([store.getDuplicity(row.did), store.getDuplicity(state.controller)]);
      kelPersonRooted = alarms.every((a) => a === null);
      controller = state.controller;
    }
  }
  return {
    active: row.active,
    domainVerified: row.domainVerified === true && !!row.domain,
    domain: row.domainVerified ? row.domain : null,
    kelPersonRooted,
    controller,
    audited: audit?.audited_at != null,
    auditedAt: audit?.audited_at != null ? new Date(audit.audited_at).toISOString() : null,
    auditReference: audit?.audit_reference ?? null,
  };
}

export function tierFromFacts(f: AgentFacts): CertificationTier {
  if (!f.active) return "unverified";
  if (f.audited) return "audited";
  if (f.kelPersonRooted) return "kel_person_rooted";
  if (f.domainVerified) return "domain_verified";
  return "unverified";
}

/**
 * The key the registry currently vouches for, for an ACTIVE agent row:
 * an E-DID's from its verified KEL (null once revoked, controller-revoked or
 * forked), anything else as mandate verification resolves it.
 */
export async function currentAgentKey(repo: RegistryRepository, row: AgentRow): Promise<Uint8Array | null> {
  if (isInceptionDid(row.did)) {
    const store = new RepositoryKelStore(repo);
    if (await store.getDuplicity(row.did)) return null;
    const state = await verifiedKelState(repo, row.did);
    if (!state || state.revoked || state.controllerRevoked || !state.currentKey) return null;
    if (state.controller && (await store.getDuplicity(state.controller))) return null;
    return state.currentKey;
  }
  return registryKeyResolver(repo)(row.did);
}
