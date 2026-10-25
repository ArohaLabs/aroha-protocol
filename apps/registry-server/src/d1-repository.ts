// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * D1Repository — Cloudflare D1 (SQLite) implementation of RegistryRepository.
 *
 * All SQL here is ANSI-compatible. To write a PostgresRepository:
 *   • Replace D1Database with a Postgres client (postgres.js / node-postgres)
 *   • Change `INTEGER` booleans (0/1) to native BOOLEAN
 *   • Replace batch() with a single transaction
 *   • The query shapes, column names, and method signatures stay identical
 */

import type { D1Database } from "@cloudflare/workers-types";
import type {
  AgentRow, McpRow, SkillRow, RevokedKeyRow, RegistryRepository,
  DiscoveryStats, AnalyticsSummary, RoutingSignalRow, RoutingPriorRow, AuditLogRow,
  Visibility, ResourceType, AccessGrantRow, CreateGrantInput,
  KycIssuerRow, VerifiedCallerRow, CallerAttestationRow,
  FirmLicenseRow, SubdomainClaimRow, SarRow,
  SpaceRow,
  SpaceMemberRow,
  SpaceResourceRow,
  SpaceInviteRow,
  KelDeactivationReason,
  KelLogRow,
  IdentityLinkageRow,
} from "./repository.js";

// Raw shape coming back from D1 — snake_case, booleans as 0/1
interface D1AgentRow {
  did_hash: string;
  did: string;
  owner_key_hash: string;
  org_name: string;
  manifest_cid: string;
  public_key_b64: string;
  staked_wei: string;
  reputation_score: number;
  active: number;
  registered_at: number;
  last_updated_at: number;
  endpoint_url: string | null;
  key_version: number | null;
  key_rotated_at: number | null;
  verification_tier: string | null;
  domain: string | null;
  domain_verified: number;
  discovery_eligible_at: number | null;
  org_signature: string | null;
  visibility: string | null;
  controller_did?: string | null;
  deactivated_reason?: string | null;
}

/**
 * SQL predicate restricting rows to what `viewer` is allowed to see:
 * public records, records they own, or records they hold a live grant for.
 *
 * Binds three params in order: viewerKeyHash, now, viewerKeyHash.
 * An anonymous viewer passes "" — which never matches a SHA-256 key hash,
 * so they see public records only.
 */
function visibilityFilter(alias: string): string {
  return `(
    ${alias}.visibility = 'public'
    OR ${alias}.owner_key_hash = ?
    OR EXISTS (
      SELECT 1 FROM access_grants g
      WHERE g.resource_did_hash = ${alias}.did_hash
        AND g.revoked_at IS NULL
        AND (g.expires_at IS NULL OR g.expires_at > ?)
        AND g.grantee_key_hash = ?
    )
  )`;
}

function asVisibility(v: string | null | undefined): Visibility {
  return v === "private" ? "private" : v === "unlisted" ? "unlisted" : "public";
}

interface D1McpRow {
  did_hash: string; did: string; owner_key_hash: string; org_name: string;
  name: string; description: string; endpoint_url: string; tool_ids: string;
  manifest_cid: string; active: number; registered_at: number;
  last_updated_at: number; visibility: string | null;
}

function toMcpRow(r: D1McpRow): McpRow {
  return {
    didHash: r.did_hash, did: r.did, ownerKeyHash: r.owner_key_hash, orgName: r.org_name,
    name: r.name, description: r.description, endpointUrl: r.endpoint_url,
    toolIds: JSON.parse(r.tool_ids || "[]"),
    manifestCID: r.manifest_cid, active: r.active === 1,
    registeredAt: r.registered_at, lastUpdatedAt: r.last_updated_at,
    visibility: asVisibility(r.visibility),
  };
}

interface D1SkillRow {
  did_hash: string; did: string; owner_key_hash: string; org_name: string;
  name: string; description: string; skill_type: string; endpoint_url: string;
  manifest_cid: string; active: number; registered_at: number;
  last_updated_at: number; visibility: string | null;
}

function toSkillRow(r: D1SkillRow): SkillRow {
  return {
    didHash: r.did_hash, did: r.did, ownerKeyHash: r.owner_key_hash, orgName: r.org_name,
    name: r.name, description: r.description, skillType: r.skill_type,
    endpointUrl: r.endpoint_url, manifestCID: r.manifest_cid, active: r.active === 1,
    registeredAt: r.registered_at, lastUpdatedAt: r.last_updated_at,
    visibility: asVisibility(r.visibility),
  };
}

/** Table name for a resource type — validated, never interpolated from user input. */
function tableFor(t: ResourceType): string {
  return t === "agent" ? "agent_records" : t === "mcp" ? "mcp_records" : "skill_records";
}

function fromD1(r: D1AgentRow): AgentRow {
  return {
    didHash: r.did_hash,
    did: r.did,
    ownerKeyHash: r.owner_key_hash,
    orgName: r.org_name ?? "",
    manifestCID: r.manifest_cid,
    publicKeyB64: r.public_key_b64,
    stakedWei: r.staked_wei,
    reputationScore: r.reputation_score,
    active: r.active === 1,
    registeredAt: r.registered_at,
    lastUpdatedAt: r.last_updated_at,
    endpointUrl: r.endpoint_url ?? undefined,
    keyVersion: r.key_version ?? 1,
    keyRotatedAt: r.key_rotated_at ?? null,
    verificationTier: (r.verification_tier === 'org-signed' ? 'org-signed' : r.verification_tier === 'domain' ? 'domain' : 'community'),
    domain: r.domain ?? null,
    domainVerified: r.domain_verified === 1,
    discoveryEligibleAt: r.discovery_eligible_at ?? null,
    orgSignature: r.org_signature ?? null,
    visibility: asVisibility(r.visibility),
    controllerDid: r.controller_did ?? null,
    deactivatedReason: r.deactivated_reason ?? null,
  };
}

export class D1Repository implements RegistryRepository {
  constructor(private readonly db: D1Database) {}

  async insertAgent(row: AgentRow, capabilityIds: string[]): Promise<void> {
    const now = row.registeredAt;
    await this.db.batch([
      this.db
        .prepare(
          // INSERT OR REPLACE handles re-registration of a previously deactivated DID.
          // The full row is replaced so owner, manifest, and reputation reset cleanly.
          // visibility is written explicitly: INSERT OR REPLACE deletes and
          // re-inserts, so relying on the column default would silently reset a
          // private agent to public on re-registration.
          `INSERT OR REPLACE INTO agent_records
             (did_hash, did, owner_key_hash, org_name, manifest_cid, public_key_b64,
              staked_wei, reputation_score, active, registered_at, last_updated_at, endpoint_url,
              verification_tier, domain, domain_verified, discovery_eligible_at, org_signature,
              visibility, key_version, controller_did)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
        )
        .bind(
          row.didHash, row.did, row.ownerKeyHash, row.orgName, row.manifestCID,
          row.publicKeyB64, row.stakedWei, row.reputationScore, now, now,
          row.endpointUrl ?? null,
          row.verificationTier ?? 'community', row.domain ?? null,
          row.discoveryEligibleAt ?? null, row.orgSignature ?? null,
          row.visibility ?? 'public',
          // Written explicitly (it used to fall to the column default of 1)
          // because an E-DID registers at whatever version its KEL has
          // reached — a log that already rotated twice registers at 3.
          row.keyVersion ?? 1,
          // From the verified KEL's inception (routes/agents.ts), so the
          // controller cascade reaches this row from the moment it exists.
          // deactivated_reason is not listed: REPLACE resets it to NULL,
          // which is right for a fresh registration.
          row.controllerDid ?? null,
        ),
      // Index each capability — INSERT OR IGNORE is safe for re-registrations
      ...capabilityIds.map((id) =>
        this.db
          .prepare(`INSERT OR IGNORE INTO capability_index (capability_id, did_hash) VALUES (?, ?)`)
          .bind(id, row.didHash),
      ),
    ]);
  }

  async getAgent(didHash: string): Promise<AgentRow | null> {
    const row = await this.db
      .prepare(
        `SELECT a.*, GROUP_CONCAT(ci.capability_id) AS capability_ids
         FROM agent_records a
         LEFT JOIN capability_index ci ON ci.did_hash = a.did_hash
         WHERE a.did_hash = ? AND a.active = 1
         GROUP BY a.did_hash`,
      )
      .bind(didHash)
      .first<D1AgentRow & { capability_ids: string | null }>();
    if (!row) return null;
    return { ...fromD1(row), capabilityIds: row.capability_ids ? row.capability_ids.split(",") : [] };
  }

  async getAgentAny(didHash: string): Promise<AgentRow | null> {
    const row = await this.db
      .prepare(
        `SELECT a.*, GROUP_CONCAT(ci.capability_id) AS capability_ids
         FROM agent_records a
         LEFT JOIN capability_index ci ON ci.did_hash = a.did_hash
         WHERE a.did_hash = ?
         GROUP BY a.did_hash`,
      )
      .bind(didHash)
      .first<D1AgentRow & { capability_ids: string | null }>();
    if (!row) return null;
    return { ...fromD1(row), capabilityIds: row.capability_ids ? row.capability_ids.split(",") : [] };
  }

  async deactivateAgentByOrgName(didHash: string, orgName: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE agent_records SET active = 0, last_updated_at = ?
         WHERE did_hash = ? AND org_name = ? AND active = 1`,
      )
      .bind(Date.now(), didHash, orgName)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deactivateAgent(didHash: string, ownerKeyHash: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE agent_records
         SET active = 0, last_updated_at = ?
         WHERE did_hash = ? AND owner_key_hash = ? AND active = 1`,
      )
      .bind(Date.now(), didHash, ownerKeyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async updateManifest(
    didHash: string,
    manifestCID: string,
    capabilityIds: string[],
    ownerKeyHash: string,
  ): Promise<boolean> {
    const now = Date.now();
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE agent_records
           SET manifest_cid = ?, last_updated_at = ?
           WHERE did_hash = ? AND owner_key_hash = ? AND active = 1`,
        )
        .bind(manifestCID, now, didHash, ownerKeyHash),
      // Replace capability index atomically
      this.db
        .prepare(`DELETE FROM capability_index WHERE did_hash = ?`)
        .bind(didHash),
      ...capabilityIds.map((id) =>
        this.db
          .prepare(`INSERT OR IGNORE INTO capability_index (capability_id, did_hash) VALUES (?, ?)`)
          .bind(id, didHash),
      ),
    ]);
    return (results[0].meta.changes ?? 0) > 0;
  }

  async updateManifestByOrgName(
    didHash: string,
    manifestCID: string,
    capabilityIds: string[],
    orgName: string,
  ): Promise<boolean> {
    const now = Date.now();
    const results = await this.db.batch([
      this.db
        .prepare(
          `UPDATE agent_records SET manifest_cid = ?, last_updated_at = ?
           WHERE did_hash = ? AND org_name = ? AND active = 1`,
        )
        .bind(manifestCID, now, didHash, orgName),
      this.db.prepare(`DELETE FROM capability_index WHERE did_hash = ?`).bind(didHash),
      ...capabilityIds.map((id) =>
        this.db
          .prepare(`INSERT OR IGNORE INTO capability_index (capability_id, did_hash) VALUES (?, ?)`)
          .bind(id, didHash),
      ),
    ]);
    return (results[0].meta.changes ?? 0) > 0;
  }

  async queryByCapability(capabilityIds: string[], viewerKeyHash?: string | null): Promise<AgentRow[]> {
    if (capabilityIds.length === 0) return [];

    const viewer = viewerKeyHash ?? "";
    const now = Date.now();

    // Find agents that have ALL requested capabilities (intersection),
    // restricted to what this viewer is allowed to see.
    const placeholders = capabilityIds.map(() => "?").join(", ");
    const { results } = await this.db
      .prepare(
        `SELECT a.*
         FROM agent_records a
         WHERE a.active = 1
           AND (
             SELECT COUNT(DISTINCT ci.capability_id)
             FROM capability_index ci
             WHERE ci.did_hash = a.did_hash
               AND ci.capability_id IN (${placeholders})
           ) = ?
           AND ${visibilityFilter("a")}`,
      )
      .bind(...capabilityIds, capabilityIds.length, viewer, now, viewer)
      .all<D1AgentRow>();

    return results.map(fromD1);
  }

  async listAgents(limit: number, offset: number, viewerKeyHash?: string | null): Promise<AgentRow[]> {
    const now = Date.now();
    const viewer = viewerKeyHash ?? "";
    const { results } = await this.db
      .prepare(
        `SELECT a.*, GROUP_CONCAT(ci.capability_id) AS capability_ids
         FROM agent_records a
         LEFT JOIN capability_index ci ON ci.did_hash = a.did_hash
         WHERE a.active = 1
           AND (a.discovery_eligible_at IS NULL OR a.discovery_eligible_at <= ?)
           AND ${visibilityFilter("a")}
         GROUP BY a.did_hash
         ORDER BY a.registered_at DESC
         LIMIT ? OFFSET ?`,
      )
      .bind(now, viewer, now, viewer, limit, offset)
      .all<D1AgentRow & { capability_ids: string | null }>();
    return results.map((r) => ({ ...fromD1(r), capabilityIds: r.capability_ids ? r.capability_ids.split(",") : [] }));
  }

  async setVerificationTier(
    didHash: string,
    ownerKeyHash: string,
    tier: 'community' | 'domain' | 'org-signed',
    domain: string,
  ): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE agent_records
         SET verification_tier = ?, domain = ?, domain_verified = 1, last_updated_at = ?
         WHERE did_hash = ? AND owner_key_hash = ? AND active = 1`,
      )
      .bind(tier, domain, Date.now(), didHash, ownerKeyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  // ── MCPs ────────────────────────────────────────────────────────────────────

  async insertMcp(row: McpRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO mcp_records
           (did_hash, did, owner_key_hash, org_name, name, description,
            endpoint_url, tool_ids, manifest_cid, active, registered_at, last_updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
      )
      .bind(
        row.didHash, row.did, row.ownerKeyHash, row.orgName, row.name, row.description,
        row.endpointUrl, JSON.stringify(row.toolIds), row.manifestCID,
        row.registeredAt, row.registeredAt,
      )
      .run();
  }

  async getMcp(didHash: string): Promise<McpRow | null> {
    const r = await this.db
      .prepare(`SELECT * FROM mcp_records WHERE did_hash = ? AND active = 1`)
      .bind(didHash)
      .first<D1McpRow>();
    if (!r) return null;
    return toMcpRow(r);
  }

  async listMcps(limit: number, offset: number, viewerKeyHash?: string | null): Promise<McpRow[]> {
    const viewer = viewerKeyHash ?? "";
    const now = Date.now();
    const { results } = await this.db
      .prepare(
        `SELECT m.* FROM mcp_records m
         WHERE m.active = 1 AND ${visibilityFilter("m")}
         ORDER BY m.registered_at DESC LIMIT ? OFFSET ?`,
      )
      .bind(viewer, now, viewer, limit, offset)
      .all<D1McpRow>();
    return results.map(toMcpRow);
  }

  async deactivateMcpByOrgName(didHash: string, orgName: string): Promise<boolean> {
    const result = await this.db
      .prepare(`UPDATE mcp_records SET active = 0, last_updated_at = ? WHERE did_hash = ? AND org_name = ? AND active = 1`)
      .bind(Date.now(), didHash, orgName)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  // ── Skills ───────────────────────────────────────────────────────────────────

  async insertSkill(row: SkillRow): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO skill_records
           (did_hash, did, owner_key_hash, org_name, name, description,
            skill_type, endpoint_url, manifest_cid, active, registered_at, last_updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
      )
      .bind(
        row.didHash, row.did, row.ownerKeyHash, row.orgName, row.name, row.description,
        row.skillType, row.endpointUrl, row.manifestCID, row.registeredAt, row.registeredAt,
      )
      .run();
  }

  async getSkill(didHash: string): Promise<SkillRow | null> {
    const r = await this.db
      .prepare(`SELECT * FROM skill_records WHERE did_hash = ? AND active = 1`)
      .bind(didHash)
      .first<D1SkillRow>();
    if (!r) return null;
    return toSkillRow(r);
  }

  async listSkills(
    limit: number, offset: number, skillType?: string, viewerKeyHash?: string | null,
  ): Promise<SkillRow[]> {
    const viewer = viewerKeyHash ?? "";
    const now = Date.now();
    const vis = visibilityFilter("s");
    const sql = skillType
      ? `SELECT s.* FROM skill_records s WHERE s.active = 1 AND s.skill_type = ? AND ${vis} ORDER BY s.registered_at DESC LIMIT ? OFFSET ?`
      : `SELECT s.* FROM skill_records s WHERE s.active = 1 AND ${vis} ORDER BY s.registered_at DESC LIMIT ? OFFSET ?`;
    const stmt = skillType
      ? this.db.prepare(sql).bind(skillType, viewer, now, viewer, limit, offset)
      : this.db.prepare(sql).bind(viewer, now, viewer, limit, offset);
    const { results } = await stmt.all<D1SkillRow>();
    return results.map(toSkillRow);
  }

  async deactivateSkillByOrgName(didHash: string, orgName: string): Promise<boolean> {
    const result = await this.db
      .prepare(`UPDATE skill_records SET active = 0, last_updated_at = ? WHERE did_hash = ? AND org_name = ? AND active = 1`)
      .bind(Date.now(), didHash, orgName)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async rotateKey(
    didHash: string,
    newPublicKeyB64: string,
    expectedVersion: number,
  ): Promise<{ keyVersion: number } | "conflict" | null> {
    const current = await this.db
      .prepare(
        `SELECT public_key_b64, key_version FROM agent_records WHERE did_hash = ? AND active = 1`,
      )
      .bind(didHash)
      .first<{ public_key_b64: string; key_version: number | null }>();

    if (!current) return null;
    const oldVersion = current.key_version ?? 1;
    if (oldVersion !== expectedVersion) return "conflict";

    const now = Date.now();
    const newVersion = oldVersion + 1;

    // Version-guarded compare-and-swap, in one batch (one transaction):
    // the UPDATE only lands while the row is still at the version the
    // signature was verified against, and the archive INSERT only runs when
    // that UPDATE changed a row (changes() = 1). Two rotations racing on the
    // same current key used to both succeed, the second silently replacing
    // the first and archiving the same old key twice.
    const [updated] = await this.db.batch([
      this.db
        .prepare(
          `UPDATE agent_records
           SET public_key_b64 = ?, key_version = ?, key_rotated_at = ?, last_updated_at = ?
           WHERE did_hash = ? AND active = 1 AND COALESCE(key_version, 1) = ?`,
        )
        .bind(newPublicKeyB64, newVersion, now, now, didHash, oldVersion),
      this.db
        .prepare(
          `INSERT INTO revoked_keys (did_hash, public_key_b64, key_version, rotated_at)
           SELECT ?, ?, ?, ? WHERE changes() = 1`,
        )
        .bind(didHash, current.public_key_b64, oldVersion, now),
    ]);

    if ((updated?.meta.changes ?? 0) !== 1) return "conflict";
    return { keyVersion: newVersion };
  }

  async getRevokedKeys(didHash: string): Promise<RevokedKeyRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT public_key_b64, key_version, rotated_at
         FROM revoked_keys
         WHERE did_hash = ?
         ORDER BY key_version DESC`,
      )
      .bind(didHash)
      .all<{ public_key_b64: string; key_version: number; rotated_at: number }>();

    return results.map((r) => ({
      publicKeyB64: r.public_key_b64,
      keyVersion: r.key_version,
      rotatedAt: r.rotated_at,
    }));
  }

  async consumeRotationNonce(nonce: string, didHash: string, expiresAt: number): Promise<boolean> {
    // Reject stale nonces before touching the DB — prevents inserting rows that
    // would immediately be pruned and closes a narrow replay window near TTL expiry.
    if (expiresAt <= Date.now()) return false;

    const result = await this.db
      .prepare(
        `INSERT OR IGNORE INTO rotation_nonces (nonce, did_hash, expires_at) VALUES (?, ?, ?)`,
      )
      .bind(nonce, didHash, expiresAt)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async pruneExpiredRotationNonces(): Promise<void> {
    await this.db
      .prepare(
        `DELETE FROM rotation_nonces WHERE expires_at < ?`,
      )
      .bind(Date.now())
      .run();
  }

  // ── Visibility & access grants ─────────────────────────────────────────────

  async setVisibility(
    didHash: string,
    resourceType: ResourceType,
    visibility: Visibility,
    ownerKeyHash: string,
  ): Promise<boolean> {
    // tableFor() maps a validated union to a literal — no user input is interpolated.
    const result = await this.db
      .prepare(
        `UPDATE ${tableFor(resourceType)}
         SET visibility = ?, last_updated_at = ?
         WHERE did_hash = ? AND owner_key_hash = ?`,
      )
      .bind(visibility, Date.now(), didHash, ownerKeyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  /** Confirm the caller owns the resource before mutating grants on it. */
  async ownsResource(
    didHash: string, resourceType: ResourceType, ownerKeyHash: string,
  ): Promise<boolean> {
    const r = await this.db
      .prepare(`SELECT 1 AS ok FROM ${tableFor(resourceType)} WHERE did_hash = ? AND owner_key_hash = ?`)
      .bind(didHash, ownerKeyHash)
      .first<{ ok: number }>();
    return !!r;
  }

  async createGrant(input: CreateGrantInput, ownerKeyHash: string): Promise<AccessGrantRow | null> {
    if (!(await this.ownsResource(input.resourceDidHash, input.resourceType, ownerKeyHash))) {
      return null;
    }
    const now = Date.now();
    const caps = input.capabilities?.length ? JSON.stringify(input.capabilities) : null;

    // Re-granting an existing live pair updates it rather than colliding with
    // the partial unique index.
    await this.db
      .prepare(
        `UPDATE access_grants SET revoked_at = ?
         WHERE resource_did_hash = ? AND revoked_at IS NULL
           AND ((grantee_did IS NOT NULL AND grantee_did = ?)
             OR (grantee_key_hash IS NOT NULL AND grantee_key_hash = ?))`,
      )
      .bind(now, input.resourceDidHash, input.granteeDid ?? null, input.granteeKeyHash ?? null)
      .run();

    await this.db
      .prepare(
        `INSERT INTO access_grants
           (resource_did_hash, resource_type, grantee_did, grantee_key_hash,
            capabilities, granted_by_key_hash, note, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        input.resourceDidHash, input.resourceType,
        input.granteeDid ?? null, input.granteeKeyHash ?? null,
        caps, ownerKeyHash, input.note ?? null, input.expiresAt ?? null, now,
      )
      .run();

    // Read the id back rather than trusting meta.last_row_id — that field isn't
    // portable across drivers, and the partial unique indexes guarantee exactly
    // one live row for this (resource, grantee) pair.
    const inserted = await this.db
      .prepare(
        `SELECT id FROM access_grants
         WHERE resource_did_hash = ? AND revoked_at IS NULL
           AND ((grantee_did IS NOT NULL AND grantee_did = ?)
             OR (grantee_key_hash IS NOT NULL AND grantee_key_hash = ?))
         ORDER BY created_at DESC LIMIT 1`,
      )
      .bind(input.resourceDidHash, input.granteeDid ?? null, input.granteeKeyHash ?? null)
      .first<{ id: number }>();

    const id = inserted?.id ?? 0;
    return {
      id,
      resourceDidHash: input.resourceDidHash,
      resourceType: input.resourceType,
      granteeDid: input.granteeDid ?? null,
      granteeKeyHash: input.granteeKeyHash ?? null,
      capabilities: input.capabilities?.length ? input.capabilities : null,
      grantedByKeyHash: ownerKeyHash,
      note: input.note ?? null,
      expiresAt: input.expiresAt ?? null,
      createdAt: now,
      revokedAt: null,
    };
  }

  async revokeGrant(id: number, ownerKeyHash: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE access_grants SET revoked_at = ?
         WHERE id = ? AND granted_by_key_hash = ? AND revoked_at IS NULL`,
      )
      .bind(Date.now(), id, ownerKeyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async listGrants(resourceDidHash: string, ownerKeyHash: string): Promise<AccessGrantRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT * FROM access_grants
         WHERE resource_did_hash = ? AND granted_by_key_hash = ? AND revoked_at IS NULL
         ORDER BY created_at DESC`,
      )
      .bind(resourceDidHash, ownerKeyHash)
      .all<{
        id: number; resource_did_hash: string; resource_type: string;
        grantee_did: string | null; grantee_key_hash: string | null;
        capabilities: string | null; granted_by_key_hash: string;
        note: string | null; expires_at: number | null;
        created_at: number; revoked_at: number | null;
      }>();

    return results.map((r) => ({
      id: r.id,
      resourceDidHash: r.resource_did_hash,
      resourceType: (r.resource_type === "mcp" ? "mcp" : r.resource_type === "skill" ? "skill" : "agent") as ResourceType,
      granteeDid: r.grantee_did,
      granteeKeyHash: r.grantee_key_hash,
      capabilities: r.capabilities ? (JSON.parse(r.capabilities) as string[]) : null,
      grantedByKeyHash: r.granted_by_key_hash,
      note: r.note,
      expiresAt: r.expires_at,
      createdAt: r.created_at,
      revokedAt: r.revoked_at,
    }));
  }

  async getOwnerKeyHashForOrg(
    didHash: string,
    resourceType: ResourceType,
    orgName: string,
  ): Promise<string | null> {
    const r = await this.db
      .prepare(`SELECT owner_key_hash FROM ${tableFor(resourceType)} WHERE did_hash = ? AND org_name = ?`)
      .bind(didHash, orgName)
      .first<{ owner_key_hash: string }>();
    return r?.owner_key_hash ?? null;
  }

  async hasGrant(
    resourceDidHash: string,
    grantee: { did?: string | null; keyHash?: string | null },
  ): Promise<boolean> {
    if (!grantee.did && !grantee.keyHash) return false;
    const r = await this.db
      .prepare(
        `SELECT 1 AS ok FROM access_grants
         WHERE resource_did_hash = ?
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)
           AND ((grantee_did IS NOT NULL AND grantee_did = ?)
             OR (grantee_key_hash IS NOT NULL AND grantee_key_hash = ?))
         LIMIT 1`,
      )
      .bind(resourceDidHash, Date.now(), grantee.did ?? null, grantee.keyHash ?? null)
      .first<{ ok: number }>();
    return !!r;
  }

  async insertKey(keyHash: string, orgName: string, ownerId: string, label?: string | null): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO api_keys (key_hash, org_name, owner_id, created_at, active, label) VALUES (?, ?, ?, ?, 1, ?)`,
      )
      .bind(keyHash, orgName, ownerId, Date.now(), label ?? null)
      .run();
  }

  async getKey(keyHash: string): Promise<{ orgName: string; active: boolean; orgPublicKeyB64: string | null } | null> {
    const row = await this.db
      .prepare(`SELECT org_name, active, org_public_key_b64 FROM api_keys WHERE key_hash = ?`)
      .bind(keyHash)
      .first<{ org_name: string; active: number; org_public_key_b64: string | null }>();
    if (!row) return null;
    return { orgName: row.org_name, active: row.active === 1, orgPublicKeyB64: row.org_public_key_b64 ?? null };
  }

  async setOrgKey(keyHash: string, orgPublicKeyB64: string, domain: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE api_keys
         SET org_public_key_b64 = ?, org_key_domain = ?, org_key_verified_at = ?
         WHERE key_hash = ? AND active = 1`,
      )
      .bind(orgPublicKeyB64, domain, Date.now(), keyHash)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async listKeysByOwner(ownerId: string): Promise<{ keyHash: string; createdAt: number; label: string | null }[]> {
    const { results } = await this.db
      .prepare(
        `SELECT key_hash, created_at, label FROM api_keys
         WHERE owner_id = ? AND active = 1
         ORDER BY created_at DESC`,
      )
      .bind(ownerId)
      .all<{ key_hash: string; created_at: number; label: string | null }>();
    // The label is what makes this list actionable: three identical rows
    // differing only by a hash is a list somebody revokes from by guessing.
    return results.map((r) => ({ keyHash: r.key_hash, createdAt: r.created_at, label: r.label ?? null }));
  }

  async revokeKey(targetHash: string, ownerId: string): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE api_keys SET active = 0
         WHERE key_hash = ? AND owner_id = ? AND active = 1`,
      )
      .bind(targetHash, ownerId)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async recordEvent(eventType: string, didHash: string | null): Promise<void> {
    await this.db
      .prepare(`INSERT INTO analytics_events (event_type, did_hash, created_at) VALUES (?, ?, ?)`)
      .bind(eventType, didHash, Date.now())
      .run();
  }

  async getAgentDiscoveryStats(didHash: string): Promise<DiscoveryStats> {
    const now = Date.now();
    const day7  = now - 7  * 24 * 60 * 60 * 1000;
    const day30 = now - 30 * 24 * 60 * 60 * 1000;

    const [r1, r2, r3] = await this.db.batch([
      this.db.prepare(
        `SELECT COUNT(*) AS n FROM analytics_events WHERE event_type = 'agent.discovered' AND did_hash = ?`,
      ).bind(didHash),
      this.db.prepare(
        `SELECT COUNT(*) AS n FROM analytics_events WHERE event_type = 'agent.discovered' AND did_hash = ? AND created_at >= ?`,
      ).bind(didHash, day7),
      this.db.prepare(
        `SELECT COUNT(*) AS n FROM analytics_events WHERE event_type = 'agent.discovered' AND did_hash = ? AND created_at >= ?`,
      ).bind(didHash, day30),
    ]);

    return {
      total:  (r1.results[0] as { n: number } | undefined)?.n ?? 0,
      last7d:  (r2.results[0] as { n: number } | undefined)?.n ?? 0,
      last30d: (r3.results[0] as { n: number } | undefined)?.n ?? 0,
    };
  }

  async getAnalyticsSummary(): Promise<AnalyticsSummary> {
    const now = Date.now();
    const day7 = now - 7 * 24 * 60 * 60 * 1000;
    const verifiedMinScore = 7_000;
    const verifiedMinAgeMs = 7 * 24 * 60 * 60 * 1000;

    const [active, verified, events7d, regs7d] = await this.db.batch([
      this.db.prepare(`SELECT COUNT(*) AS n FROM agent_records WHERE active = 1`),
      this.db.prepare(
        `SELECT COUNT(*) AS n FROM agent_records WHERE active = 1 AND reputation_score >= ? AND registered_at <= ?`,
      ).bind(verifiedMinScore, now - verifiedMinAgeMs),
      this.db.prepare(`SELECT COUNT(*) AS n FROM analytics_events WHERE created_at >= ?`).bind(day7),
      this.db.prepare(
        `SELECT COUNT(*) AS n FROM analytics_events WHERE event_type = 'agent.registered' AND created_at >= ?`,
      ).bind(day7),
    ]);

    return {
      activeAgents:    (active.results[0]   as { n: number } | undefined)?.n ?? 0,
      verifiedAgents:  (verified.results[0]  as { n: number } | undefined)?.n ?? 0,
      totalEvents7d:   (events7d.results[0]  as { n: number } | undefined)?.n ?? 0,
      registrations7d: (regs7d.results[0]    as { n: number } | undefined)?.n ?? 0,
    };
  }

  async getModelCatalog(provider?: string): Promise<import("./repository.js").ModelCatalogRow[]> {
    const sql = provider
      ? `SELECT * FROM model_catalog WHERE active = 1 AND provider = ? ORDER BY tier ASC, input_price_per_mtok ASC`
      : `SELECT * FROM model_catalog WHERE active = 1 ORDER BY tier ASC, input_price_per_mtok ASC`;
    const stmt = provider ? this.db.prepare(sql).bind(provider) : this.db.prepare(sql);
    const { results } = await stmt.all<{
      model_id: string; provider: string; tier: number;
      input_price_per_mtok: number; output_price_per_mtok: number;
      context_window: number; avg_latency_ms: number;
      quality_reasoning: number; quality_code: number; quality_extraction: number;
      quality_creative: number; quality_classification: number; quality_summarization: number;
      active: number; updated_at: number;
    }>();
    return results.map(r => ({
      modelId:               r.model_id,
      provider:              r.provider,
      tier:                  r.tier,
      inputPricePerMtok:     r.input_price_per_mtok,
      outputPricePerMtok:    r.output_price_per_mtok,
      contextWindow:         r.context_window,
      avgLatencyMs:          r.avg_latency_ms,
      qualityReasoning:      r.quality_reasoning,
      qualityCode:           r.quality_code,
      qualityExtraction:     r.quality_extraction,
      qualityCreative:       r.quality_creative,
      qualityClassification: r.quality_classification,
      qualitySummarization:  r.quality_summarization,
      active:                r.active === 1,
      updatedAt:             r.updated_at,
    }));
  }

  async upsertModel(row: import("./repository.js").ModelCatalogRow): Promise<void> {
    await this.db.prepare(`
      INSERT INTO model_catalog
        (model_id, provider, tier, input_price_per_mtok, output_price_per_mtok,
         context_window, avg_latency_ms,
         quality_reasoning, quality_code, quality_extraction, quality_creative,
         quality_classification, quality_summarization, active, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(model_id) DO UPDATE SET
        provider=excluded.provider, tier=excluded.tier,
        input_price_per_mtok=excluded.input_price_per_mtok,
        output_price_per_mtok=excluded.output_price_per_mtok,
        context_window=excluded.context_window, avg_latency_ms=excluded.avg_latency_ms,
        quality_reasoning=excluded.quality_reasoning, quality_code=excluded.quality_code,
        quality_extraction=excluded.quality_extraction, quality_creative=excluded.quality_creative,
        quality_classification=excluded.quality_classification,
        quality_summarization=excluded.quality_summarization,
        active=excluded.active, updated_at=excluded.updated_at
    `).bind(
      row.modelId, row.provider, row.tier,
      row.inputPricePerMtok, row.outputPricePerMtok,
      row.contextWindow, row.avgLatencyMs,
      row.qualityReasoning, row.qualityCode, row.qualityExtraction,
      row.qualityCreative, row.qualityClassification, row.qualitySummarization,
      row.active ? 1 : 0, row.updatedAt,
    ).run();
  }

  async updateReputationScore(didHash: string, signalScore: number, alpha = 0.1): Promise<number | null> {
    const row = await this.db
      .prepare("SELECT reputation_score FROM agent_records WHERE did_hash = ? AND active = 1")
      .bind(didHash)
      .first<{ reputation_score: number }>();
    if (!row) return null;

    const current = row.reputation_score ?? 5000;
    // Scale incoming signal (0-1) to the stored 0-10000 range before blending.
    const updated = Math.round(alpha * signalScore * 10000 + (1 - alpha) * current);
    const now     = Date.now();

    await this.db
      .prepare("UPDATE agent_records SET reputation_score = ?, last_updated_at = ? WHERE did_hash = ?")
      .bind(updated, now, didHash)
      .run();

    return updated;
  }

  async recordRoutingSignals(signals: RoutingSignalRow[]): Promise<void> {
    if (signals.length === 0) return;
    const now = Date.now();
    const stmts = signals.map((s) =>
      this.db.prepare(
        `INSERT INTO routing_signals
           (model_id, task_type, complexity_bucket, quality, token_count, api_key_hash, created_at)
         VALUES (?,?,?,?,?,?,?)`,
      ).bind(s.modelId, s.taskType, s.complexityBucket, s.quality, s.tokenCount, s.apiKeyHash, now),
    );
    await this.db.batch(stmts);
  }

  async getRoutingPriors(modelId?: string): Promise<RoutingPriorRow[]> {
    const sql = modelId
      ? `SELECT model_id, task_type, complexity_bucket,
                1.0 + SUM(quality)         AS alpha,
                1.0 + SUM(1.0 - quality)   AS beta,
                COUNT(*)                   AS observations
           FROM routing_signals
           WHERE model_id = ?
           GROUP BY model_id, task_type, complexity_bucket`
      : `SELECT model_id, task_type, complexity_bucket,
                1.0 + SUM(quality)         AS alpha,
                1.0 + SUM(1.0 - quality)   AS beta,
                COUNT(*)                   AS observations
           FROM routing_signals
           GROUP BY model_id, task_type, complexity_bucket`;

    const stmt = modelId ? this.db.prepare(sql).bind(modelId) : this.db.prepare(sql);
    const { results } = await stmt.all<{
      model_id: string; task_type: string; complexity_bucket: number;
      alpha: number; beta: number; observations: number;
    }>();
    return results.map((r) => ({
      modelId:          r.model_id,
      taskType:         r.task_type,
      complexityBucket: r.complexity_bucket,
      alpha:            r.alpha,
      beta:             r.beta,
      observations:     r.observations,
    }));
  }

  async checkAndIncrementSignalRate(keyHash: string, didHash: string, limit: number): Promise<boolean> {
    // 24-hour window aligned to midnight UTC
    const windowStart = Math.floor(Date.now() / 86_400_000) * 86_400_000;

    const existing = await this.db
      .prepare(`SELECT count FROM signal_rate_limits WHERE key_hash = ? AND did_hash = ? AND window_start = ?`)
      .bind(keyHash, didHash, windowStart)
      .first<{ count: number }>();

    if (existing && existing.count >= limit) return false;

    await this.db.prepare(`
      INSERT INTO signal_rate_limits (key_hash, did_hash, window_start, count)
      VALUES (?, ?, ?, 1)
      ON CONFLICT(key_hash, did_hash, window_start) DO UPDATE SET count = count + 1
    `).bind(keyHash, didHash, windowStart).run();

    return true;
  }

  async recordAuditAction(action: string, actor: string, target?: string, ip?: string): Promise<void> {
    await this.db.prepare(
      `INSERT INTO admin_audit_log (action, actor, target, ip, created_at) VALUES (?,?,?,?,?)`,
    ).bind(action, actor, target ?? null, ip ?? null, Date.now()).run();
  }

  async listAuditLog(limit: number, offset: number): Promise<AuditLogRow[]> {
    const { results } = await this.db
      .prepare(`SELECT id, action, actor, target, ip, created_at FROM admin_audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(limit, offset)
      .all<{ id: number; action: string; actor: string; target: string | null; ip: string | null; created_at: number }>();
    return results.map((r) => ({
      id: r.id, action: r.action, actor: r.actor,
      target: r.target, ip: r.ip, createdAt: r.created_at,
    }));
  }

  // ── Caller uniqueness (Sybil-resistant reputation) ────────────────────────

  async insertKycIssuer(issuerDid: string, publicKeyB64: string, domain: string): Promise<boolean> {
    const existing = await this.db
      .prepare(`SELECT 1 AS ok FROM kyc_issuers WHERE issuer_did = ? AND revoked_at IS NULL`)
      .bind(issuerDid).first<{ ok: number }>();
    if (existing) return false;

    await this.db.prepare(
      `INSERT INTO kyc_issuers (issuer_did, public_key_b64, domain, registered_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(issuer_did) DO UPDATE SET
         public_key_b64 = excluded.public_key_b64, domain = excluded.domain,
         registered_at = excluded.registered_at, revoked_at = NULL`,
    ).bind(issuerDid, publicKeyB64, domain, Date.now()).run();
    return true;
  }

  async getKycIssuer(issuerDid: string): Promise<KycIssuerRow | null> {
    const r = await this.db
      .prepare(
        `SELECT issuer_did, public_key_b64, domain, registered_at, revoked_at
         FROM kyc_issuers WHERE issuer_did = ? AND revoked_at IS NULL`,
      )
      .bind(issuerDid)
      .first<{ issuer_did: string; public_key_b64: string; domain: string; registered_at: number; revoked_at: number | null }>();
    if (!r) return null;
    return {
      issuerDid: r.issuer_did, publicKeyB64: r.public_key_b64, domain: r.domain,
      registeredAt: r.registered_at, revokedAt: r.revoked_at,
    };
  }

  async insertVerifiedCallerNullifier(row: Omit<VerifiedCallerRow, "revokedAt">): Promise<boolean> {
    // The actual Sybil-resistance check: a live row for this exact nullifier
    // already existing means this certified secret was already spent for
    // this scope — reject rather than overwrite.
    const existing = await this.db
      .prepare(`SELECT 1 AS ok FROM verified_caller_nullifiers WHERE nullifier = ? AND revoked_at IS NULL`)
      .bind(row.nullifier).first<{ ok: number }>();
    if (existing) return false;

    await this.db.prepare(
      `INSERT INTO verified_caller_nullifiers
         (nullifier, scope, commitment, issuer_did, caller_did, verified_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(row.nullifier, row.scope, row.commitment, row.issuerDid, row.callerDid, row.verifiedAt).run();
    return true;
  }

  async isCallerVerified(callerDid: string): Promise<boolean> {
    const r = await this.db
      .prepare(`SELECT 1 AS ok FROM verified_caller_nullifiers WHERE caller_did = ? AND revoked_at IS NULL LIMIT 1`)
      .bind(callerDid).first<{ ok: number }>();
    return !!r;
  }

  async insertCallerAttestation(row: Omit<CallerAttestationRow, "id">): Promise<boolean> {
    const existing = await this.db
      .prepare(`SELECT 1 AS ok FROM caller_attestations WHERE saga_id = ? AND caller_did = ?`)
      .bind(row.sagaId, row.callerDid).first<{ ok: number }>();
    if (existing) return false;

    await this.db.prepare(
      `INSERT INTO caller_attestations
         (saga_id, agent_did_hash, caller_did, success, domain, caller_weight, submitted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      row.sagaId, row.agentDidHash, row.callerDid, row.success ? 1 : 0,
      row.domain, row.callerWeight, row.submittedAt,
    ).run();
    return true;
  }

  async listCallerAttestations(agentDidHash: string, domain: string, limit: number): Promise<CallerAttestationRow[]> {
    const { results } = await this.db
      .prepare(
        `SELECT id, saga_id, agent_did_hash, caller_did, success, domain, caller_weight, submitted_at
         FROM caller_attestations WHERE agent_did_hash = ? AND domain = ?
         ORDER BY submitted_at DESC LIMIT ?`,
      )
      .bind(agentDidHash, domain, limit)
      .all<{
        id: number; saga_id: string; agent_did_hash: string; caller_did: string;
        success: number; domain: string; caller_weight: number; submitted_at: number;
      }>();
    return results.map((r) => ({
      id: r.id, sagaId: r.saga_id, agentDidHash: r.agent_did_hash, callerDid: r.caller_did,
      success: !!r.success, domain: r.domain, callerWeight: r.caller_weight, submittedAt: r.submitted_at,
    }));
  }

  // ── Vanity subdomain provisioning ────────────────────────────────────────

  async upsertFirmLicense(firmDid: string, publicKeyHex: string, name = ""): Promise<void> {
    await this.db.prepare(
      `INSERT INTO firm_licenses (firm_did, public_key_hex, name, licensed_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(firm_did) DO UPDATE SET
         public_key_hex = excluded.public_key_hex, name = excluded.name,
         licensed_at = excluded.licensed_at, revoked_at = NULL`,
    ).bind(firmDid, publicKeyHex, name, Date.now()).run();
  }

  async revokeFirmLicense(firmDid: string): Promise<boolean> {
    const existing = await this.db
      .prepare(`SELECT 1 AS ok FROM firm_licenses WHERE firm_did = ? AND revoked_at IS NULL`)
      .bind(firmDid).first<{ ok: number }>();
    if (!existing) return false;

    await this.db.prepare(`UPDATE firm_licenses SET revoked_at = ? WHERE firm_did = ?`)
      .bind(Date.now(), firmDid).run();
    return true;
  }

  async getFirmLicense(firmDid: string): Promise<FirmLicenseRow | null> {
    const r = await this.db
      .prepare(
        `SELECT firm_did, public_key_hex, name, licensed_at, revoked_at
         FROM firm_licenses WHERE firm_did = ? AND revoked_at IS NULL`,
      )
      .bind(firmDid)
      .first<{ firm_did: string; public_key_hex: string; name: string; licensed_at: number; revoked_at: number | null }>();
    if (!r) return null;
    return {
      firmDid: r.firm_did, publicKeyHex: r.public_key_hex, name: r.name,
      licensedAt: r.licensed_at, revokedAt: r.revoked_at,
    };
  }

  async getSubdomainClaim(subdomain: string): Promise<SubdomainClaimRow | null> {
    const r = await this.db
      .prepare(
        `SELECT subdomain, firm_did, target, hostname, created_at, updated_at, disputed_at, dispute_reason
         FROM subdomain_claims WHERE subdomain = ?`,
      )
      .bind(subdomain)
      .first<{ subdomain: string; firm_did: string; target: string; hostname: string; created_at: number; updated_at: number; disputed_at: number | null; dispute_reason: string | null }>();
    if (!r) return null;
    return {
      subdomain: r.subdomain, firmDid: r.firm_did, target: r.target,
      hostname: r.hostname, createdAt: r.created_at, updatedAt: r.updated_at,
      disputedAt: r.disputed_at, disputeReason: r.dispute_reason,
    };
  }

  async getSubdomainClaimByFirm(firmDid: string): Promise<SubdomainClaimRow | null> {
    const r = await this.db
      .prepare(
        `SELECT subdomain, firm_did, target, hostname, created_at, updated_at, disputed_at, dispute_reason
         FROM subdomain_claims WHERE firm_did = ? LIMIT 1`,
      )
      .bind(firmDid)
      .first<{ subdomain: string; firm_did: string; target: string; hostname: string; created_at: number; updated_at: number; disputed_at: number | null; dispute_reason: string | null }>();
    if (!r) return null;
    return {
      subdomain: r.subdomain, firmDid: r.firm_did, target: r.target,
      hostname: r.hostname, createdAt: r.created_at, updatedAt: r.updated_at,
      disputedAt: r.disputed_at, disputeReason: r.dispute_reason,
    };
  }

  async putSubdomainClaim(row: Omit<SubdomainClaimRow, "createdAt" | "updatedAt" | "disputedAt" | "disputeReason">): Promise<void> {
    const now = Date.now();
    await this.db.prepare(
      `INSERT INTO subdomain_claims (subdomain, firm_did, target, hostname, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(subdomain) DO UPDATE SET
         target = excluded.target, hostname = excluded.hostname, updated_at = excluded.updated_at`,
    ).bind(row.subdomain, row.firmDid, row.target, row.hostname, now, now).run();
  }

  async putSubdomainDispute(subdomain: string, reason: string): Promise<boolean> {
    const res = await this.db.prepare(
      `UPDATE subdomain_claims SET disputed_at = ?, dispute_reason = ? WHERE subdomain = ?`,
    ).bind(Date.now(), reason, subdomain).run();
    return (res.meta.changes ?? 0) > 0;
  }

  // ── Signed Agent Record index (M5 — federated discovery) ─────────────────────

  async upsertSar(row: SarRow): Promise<void> {
    await this.db.prepare(
      `INSERT INTO sar_records
         (did, capabilities, transports, settlement_rails, terms, issued_at, ttl, signature, stored_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(did) DO UPDATE SET
         capabilities = excluded.capabilities, transports = excluded.transports,
         settlement_rails = excluded.settlement_rails, terms = excluded.terms,
         issued_at = excluded.issued_at, ttl = excluded.ttl,
         signature = excluded.signature, stored_at = excluded.stored_at`,
    ).bind(
      row.did, JSON.stringify(row.capabilities), JSON.stringify(row.transports),
      JSON.stringify(row.settlementRails), JSON.stringify(row.terms),
      row.issuedAt, row.ttl, row.signature, row.storedAt,
    ).run();
  }

  async querySar(opts: { capability?: string; did?: string; now: number; limit?: number; offset?: number }): Promise<SarRow[]> {
    // json_each expands the capabilities JSON array so "does this record
    // declare X" is a real query rather than a LIKE-on-serialized-JSON hack,
    // which would both false-positive on substrings and miss escaped values.
    const clauses = ["(issued_at + ttl) >= ?"];
    const params: unknown[] = [opts.now];
    if (opts.did) {
      clauses.push("did = ?");
      params.push(opts.did);
    }
    if (opts.capability) {
      clauses.push(
        "did IN (SELECT sr.did FROM sar_records sr, json_each(sr.capabilities) je WHERE je.value = ?)",
      );
      params.push(opts.capability);
    }
    const rows = await this.db
      .prepare(
        `SELECT * FROM sar_records WHERE ${clauses.join(" AND ")} ORDER BY stored_at, did` +
        (opts.limit !== undefined ? ` LIMIT ? OFFSET ?` : ""),
      )
      .bind(...params, ...(opts.limit !== undefined ? [opts.limit, opts.offset ?? 0] : []))
      .all<{
        did: string; capabilities: string; transports: string; settlement_rails: string;
        terms: string; issued_at: number; ttl: number; signature: string; stored_at: number;
      }>();
    return (rows.results ?? []).map((r) => ({
      did: r.did,
      capabilities: JSON.parse(r.capabilities),
      transports: JSON.parse(r.transports),
      settlementRails: JSON.parse(r.settlement_rails),
      terms: JSON.parse(r.terms),
      issuedAt: r.issued_at,
      ttl: r.ttl,
      signature: r.signature,
      storedAt: r.stored_at,
    }));
  }

  // ── Registration ownership challenges (M6 — publish & claim) ─────────────────

  async createRegistrationChallenge(nonce: string, did: string, keyHash: string, expiresAt: number): Promise<void> {
    await this.db
      .prepare(`INSERT INTO registration_challenges (nonce, did, key_hash, expires_at) VALUES (?, ?, ?, ?)`)
      .bind(nonce, did, keyHash, expiresAt)
      .run();
  }

  async consumeRegistrationChallenge(nonce: string, did: string, keyHash: string, now: number): Promise<boolean> {
    // A single DELETE with every condition in the WHERE clause is atomic
    // under SQLite's serialised write model — the same pattern
    // spending_budgets' allocation check uses (see schema.sql) — so there is
    // no read-then-write race where two requests could both observe the
    // challenge as valid before either deletes it.
    const result = await this.db
      .prepare(
        `DELETE FROM registration_challenges
         WHERE nonce = ? AND did = ? AND key_hash = ? AND expires_at >= ?`,
      )
      .bind(nonce, did, keyHash, now)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  // ── Personal agent names (M7 — key-derived naming, spec §7.10) ─────────────

  async mintPersonalName(row: { label: string; didHash: string; did: string; ownerKeyHash: string; mintedAt: number }): Promise<boolean> {
    const existing = await this.db
      .prepare(`SELECT did_hash FROM personal_names WHERE label = ?`)
      .bind(row.label)
      .first<{ did_hash: string }>();
    if (existing) return existing.did_hash === row.didHash;

    await this.db
      .prepare(
        `INSERT INTO personal_names (label, did_hash, did, owner_key_hash, minted_at) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(row.label, row.didHash, row.did, row.ownerKeyHash, row.mintedAt)
      .run();
    return true;
  }

  async lookupPersonalName(label: string): Promise<{ did: string } | null> {
    // Resolves only while the agent's row is active: a label is a routing
    // entry, and routing callers to a revoked (or controller-revoked,
    // migration 015) agent is discovery of a deactivated agent by another
    // name. The label stays bound — mint is first-wins — so a re-registered
    // agent resolves again.
    const row = await this.db
      .prepare(
        `SELECT p.did FROM personal_names p
         JOIN agent_records a ON a.did_hash = p.did_hash AND a.active = 1
         WHERE p.label = ?`,
      )
      .bind(label)
      .first<{ did: string }>();
    return row ? { did: row.did } : null;
  }

  // ── Relay connect tokens (M10 — relay broker, spec §6.3) ────────────────────

  async consumeRelayConnectProof(signatureHash: string, didHash: string, expiresAt: number): Promise<boolean> {
    // INSERT OR IGNORE is the guard: the primary key admits each proof once.
    const result = await this.db
      .prepare(`INSERT OR IGNORE INTO relay_connect_proofs (signature_hash, did_hash, expires_at) VALUES (?, ?, ?)`)
      .bind(signatureHash, didHash, expiresAt)
      .run();
    return (result.meta.changes ?? 0) === 1;
  }

  async createRelayConnectToken(token: string, didHash: string, expiresAt: number): Promise<void> {
    await this.db
      .prepare(`INSERT INTO relay_connect_tokens (token, did_hash, expires_at) VALUES (?, ?, ?)`)
      .bind(token, didHash, expiresAt)
      .run();
  }

  async consumeRelayConnectToken(token: string, didHash: string, now: number): Promise<boolean> {
    const result = await this.db
      .prepare(
        `DELETE FROM relay_connect_tokens WHERE token = ? AND did_hash = ? AND expires_at >= ?`,
      )
      .bind(token, didHash, now)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  // ─── Spaces ─────────────────────────────────────────────────────────────
  //
  // Every method that changes membership or contents also writes or revokes
  // rows in access_grants, tagged via_space_id. That tag is what lets a
  // removal undo exactly what a space granted and leave a hand-written grant
  // for the same pair alone — somebody given direct access to one agent
  // before being invited keeps it after being removed, which is what they
  // were told when it was granted.

  async createSpace(input: {
    id: string; name: string; description: string | null;
    ownerKeyHash: string; ownerOrg: string;
  }): Promise<SpaceRow> {
    const now = Date.now();
    await this.db
      .prepare(
        "INSERT INTO spaces (id, name, description, owner_key_hash, owner_org, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .bind(input.id, input.name, input.description, input.ownerKeyHash, input.ownerOrg, now)
      .run();
    return {
      id: input.id, name: input.name, description: input.description,
      ownerKeyHash: input.ownerKeyHash, ownerOrg: input.ownerOrg,
      createdAt: now, archivedAt: null,
    };
  }

  async getSpace(id: string): Promise<SpaceRow | null> {
    const row = await this.db.prepare("SELECT * FROM spaces WHERE id = ?").bind(id).first();
    return row ? toSpaceRow(row as Record<string, unknown>) : null;
  }

  async listSpacesOwnedBy(keyHash: string): Promise<SpaceRow[]> {
    const { results } = await this.db
      .prepare("SELECT * FROM spaces WHERE owner_key_hash = ? AND archived_at IS NULL ORDER BY created_at DESC")
      .bind(keyHash).all();
    return (results ?? []).map((r) => toSpaceRow(r as Record<string, unknown>));
  }

  async listSpacesJoinedBy(keyHash: string): Promise<SpaceRow[]> {
    const { results } = await this.db
      .prepare(
        "SELECT s.* FROM spaces s JOIN space_members m ON m.space_id = s.id" +
        " WHERE m.member_key_hash = ? AND m.removed_at IS NULL AND s.archived_at IS NULL" +
        " ORDER BY m.created_at DESC",
      )
      .bind(keyHash).all();
    return (results ?? []).map((r) => toSpaceRow(r as Record<string, unknown>));
  }

  async isSpaceMember(spaceId: string, keyHash: string): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT 1 AS ok FROM space_members WHERE space_id = ? AND member_key_hash = ? AND removed_at IS NULL")
      .bind(spaceId, keyHash).first();
    return row !== null;
  }

  async listSpaceMembers(spaceId: string): Promise<SpaceMemberRow[]> {
    const { results } = await this.db
      .prepare("SELECT * FROM space_members WHERE space_id = ? AND removed_at IS NULL ORDER BY created_at")
      .bind(spaceId).all();
    return (results ?? []).map((raw) => {
      const r = raw as Record<string, unknown>;
      return {
        spaceId: String(r.space_id), memberKeyHash: String(r.member_key_hash),
        memberOrg: String(r.member_org), invitedBy: String(r.invited_by),
        createdAt: Number(r.created_at),
        removedAt: r.removed_at == null ? null : Number(r.removed_at),
      };
    });
  }

  async listSpaceResources(spaceId: string): Promise<SpaceResourceRow[]> {
    const { results } = await this.db
      .prepare("SELECT * FROM space_resources WHERE space_id = ? AND removed_at IS NULL ORDER BY created_at")
      .bind(spaceId).all();
    return (results ?? []).map((raw) => {
      const r = raw as Record<string, unknown>;
      return {
        spaceId: String(r.space_id), resourceDidHash: String(r.resource_did_hash),
        resourceType: String(r.resource_type) as ResourceType, addedBy: String(r.added_by),
        createdAt: Number(r.created_at),
        removedAt: r.removed_at == null ? null : Number(r.removed_at),
      };
    });
  }

  async createSpaceInvite(input: {
    id: string; spaceId: string; codeHash: string;
    createdBy: string; note: string | null; expiresAt: number | null;
  }): Promise<SpaceInviteRow> {
    const now = Date.now();
    await this.db
      .prepare(
        "INSERT INTO space_invites (id, space_id, code_hash, created_by, note, expires_at, created_at)" +
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(input.id, input.spaceId, input.codeHash, input.createdBy, input.note, input.expiresAt, now)
      .run();
    return {
      id: input.id, spaceId: input.spaceId, createdBy: input.createdBy, note: input.note,
      expiresAt: input.expiresAt, createdAt: now,
      redeemedBy: null, redeemedAt: null, revokedAt: null,
    };
  }

  async findSpaceInviteByCodeHash(codeHash: string): Promise<(SpaceInviteRow & { spaceId: string }) | null> {
    const raw = await this.db.prepare("SELECT * FROM space_invites WHERE code_hash = ?").bind(codeHash).first();
    if (!raw) return null;
    const r = raw as Record<string, unknown>;
    return {
      id: String(r.id), spaceId: String(r.space_id), createdBy: String(r.created_by),
      note: r.note == null ? null : String(r.note),
      expiresAt: r.expires_at == null ? null : Number(r.expires_at),
      createdAt: Number(r.created_at),
      redeemedBy: r.redeemed_by == null ? null : String(r.redeemed_by),
      redeemedAt: r.redeemed_at == null ? null : Number(r.redeemed_at),
      revokedAt: r.revoked_at == null ? null : Number(r.revoked_at),
    };
  }

  async joinSpace(input: {
    spaceId: string; inviteId: string; memberKeyHash: string;
    memberOrg: string; invitedBy: string;
  }): Promise<{ grantsCreated: number } | null> {
    const now = Date.now();
    // The invitation is consumed FIRST. If the fan-out below fails partway, a
    // one-time code that has already been used must not be usable again: the
    // safe loss is a member holding fewer grants than intended, which the
    // owner can repair, never a code that admits a second firm.
    //
    // Consumption and membership are one batch (one transaction), and the
    // membership INSERT only runs when the conditional UPDATE actually
    // claimed the invite (changes() = 1). The route's "is it still unused?"
    // read happens before this, so two redeemers racing on one code both
    // pass it; before, both then joined — the UPDATE simply changed nothing
    // for the second one and nobody looked. Now exactly one wins and the
    // other gets null.
    const [claimed] = await this.db.batch([
      this.db
        .prepare(
          "UPDATE space_invites SET redeemed_by = ?, redeemed_at = ?" +
          " WHERE id = ? AND redeemed_at IS NULL AND revoked_at IS NULL" +
          " AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(input.memberKeyHash, now, input.inviteId, now),
      this.db
        .prepare(
          "INSERT INTO space_members (space_id, member_key_hash, member_org, invited_by, created_at)" +
          " SELECT ?, ?, ?, ?, ? WHERE changes() = 1" +
          " ON CONFLICT (space_id, member_key_hash)" +
          " DO UPDATE SET removed_at = NULL, created_at = excluded.created_at",
        )
        .bind(input.spaceId, input.memberKeyHash, input.memberOrg, input.invitedBy, now),
    ]);
    if ((claimed?.meta.changes ?? 0) !== 1) return null;

    const resources = await this.listSpaceResources(input.spaceId);
    let grantsCreated = 0;
    for (const r of resources) {
      grantsCreated += await this.grantViaSpace(input.spaceId, r, input.memberKeyHash, input.invitedBy, now);
    }
    return { grantsCreated };
  }

  async addSpaceResource(input: {
    spaceId: string; resourceDidHash: string; resourceType: ResourceType; addedBy: string;
  }): Promise<{ grantsCreated: number }> {
    const now = Date.now();
    await this.db
      .prepare(
        "INSERT INTO space_resources (space_id, resource_did_hash, resource_type, added_by, created_at)" +
        " VALUES (?, ?, ?, ?, ?)" +
        " ON CONFLICT (space_id, resource_did_hash)" +
        " DO UPDATE SET removed_at = NULL, created_at = excluded.created_at",
      )
      .bind(input.spaceId, input.resourceDidHash, input.resourceType, input.addedBy, now)
      .run();

    const members = await this.listSpaceMembers(input.spaceId);
    const resource: SpaceResourceRow = {
      spaceId: input.spaceId, resourceDidHash: input.resourceDidHash,
      resourceType: input.resourceType, addedBy: input.addedBy,
      createdAt: now, removedAt: null,
    };
    let grantsCreated = 0;
    for (const m of members) {
      grantsCreated += await this.grantViaSpace(input.spaceId, resource, m.memberKeyHash, input.addedBy, now);
    }
    return { grantsCreated };
  }

  /**
   * One space-derived grant.
   *
   * Idempotent, and it deliberately does NOT overwrite a live grant that
   * already covers the pair: a hand-written one carries no via_space_id, and
   * replacing it would mean removing the member later silently revoked
   * something a person granted directly.
   */
  private async grantViaSpace(
    spaceId: string,
    resource: SpaceResourceRow,
    granteeKeyHash: string,
    grantedBy: string,
    now: number,
  ): Promise<number> {
    const existing = await this.db
      .prepare(
        "SELECT 1 AS ok FROM access_grants" +
        " WHERE resource_did_hash = ? AND grantee_key_hash = ? AND revoked_at IS NULL",
      )
      .bind(resource.resourceDidHash, granteeKeyHash).first();
    if (existing) return 0;

    await this.db
      .prepare(
        "INSERT INTO access_grants" +
        " (resource_did_hash, resource_type, grantee_key_hash, granted_by_key_hash, note, created_at, via_space_id)" +
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(
        resource.resourceDidHash, resource.resourceType, granteeKeyHash, grantedBy,
        "via space " + spaceId, now, spaceId,
      )
      .run();
    return 1;
  }

  async removeSpaceResource(spaceId: string, resourceDidHash: string): Promise<{ removed: boolean; grantsRevoked: number }> {
    const now = Date.now();
    const res = await this.db
      .prepare("UPDATE space_resources SET removed_at = ? WHERE space_id = ? AND resource_did_hash = ? AND removed_at IS NULL")
      .bind(now, spaceId, resourceDidHash).run();
    const revoked = await this.db
      .prepare(
        "UPDATE access_grants SET revoked_at = ?" +
        " WHERE via_space_id = ? AND resource_did_hash = ? AND revoked_at IS NULL",
      )
      .bind(now, spaceId, resourceDidHash).run();
    return {
      removed: (res.meta?.changes ?? 0) > 0,
      grantsRevoked: revoked.meta?.changes ?? 0,
    };
  }

  async removeSpaceMember(spaceId: string, memberKeyHash: string): Promise<{ removed: boolean; grantsRevoked: number }> {
    const now = Date.now();
    const res = await this.db
      .prepare("UPDATE space_members SET removed_at = ? WHERE space_id = ? AND member_key_hash = ? AND removed_at IS NULL")
      .bind(now, spaceId, memberKeyHash).run();
    // Only what this space gave them. A grant written by hand for the same
    // pair has no via_space_id and is deliberately untouched.
    const revoked = await this.db
      .prepare(
        "UPDATE access_grants SET revoked_at = ?" +
        " WHERE via_space_id = ? AND grantee_key_hash = ? AND revoked_at IS NULL",
      )
      .bind(now, spaceId, memberKeyHash).run();
    return {
      removed: (res.meta?.changes ?? 0) > 0,
      grantsRevoked: revoked.meta?.changes ?? 0,
    };
  }

  async archiveSpace(spaceId: string): Promise<{ grantsRevoked: number }> {
    const now = Date.now();
    await this.db.prepare("UPDATE spaces SET archived_at = ? WHERE id = ?").bind(now, spaceId).run();
    const revoked = await this.db
      .prepare("UPDATE access_grants SET revoked_at = ? WHERE via_space_id = ? AND revoked_at IS NULL")
      .bind(now, spaceId).run();
    return { grantsRevoked: revoked.meta?.changes ?? 0 };
  }

  // ── Key Event Logs (migration 014) ─────────────────────────────────────────

  async getKelLog(did: string): Promise<KelLogRow | null> {
    const row = await this.db
      .prepare(`SELECT did, events_json, sequence, last_digest, updated_at FROM kel_logs WHERE did = ?`)
      .bind(did)
      .first<{ did: string; events_json: string; sequence: number; last_digest: string; updated_at: number }>();
    if (!row) return null;
    return {
      did: row.did,
      events: JSON.parse(row.events_json) as unknown[],
      sequence: row.sequence,
      lastDigest: row.last_digest,
      updatedAt: row.updated_at,
    };
  }

  async putKelLogIfLonger(row: KelLogRow): Promise<boolean> {
    // The WHERE on the upsert is the whole point: a read-compare-write in the
    // caller cannot stop two concurrent requests from both deciding they are
    // "the longer one", but SQLite evaluates this predicate under its single
    // writer, so a shorter (or equal) log can never overwrite a longer one.
    const result = await this.db
      .prepare(
        `INSERT INTO kel_logs (did, events_json, sequence, last_digest, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(did) DO UPDATE SET
           events_json = excluded.events_json, sequence = excluded.sequence,
           last_digest = excluded.last_digest, updated_at = excluded.updated_at
         WHERE excluded.sequence > kel_logs.sequence`,
      )
      .bind(row.did, JSON.stringify(row.events), row.sequence, row.lastDigest, row.updatedAt)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async recordKelDuplicity(did: string, evidence: unknown, recordedAt: number): Promise<void> {
    await this.db
      .prepare(`INSERT OR IGNORE INTO kel_duplicity (did, evidence_json, recorded_at) VALUES (?, ?, ?)`)
      .bind(did, JSON.stringify(evidence), recordedAt)
      .run();
  }

  async getKelDuplicity(did: string): Promise<unknown | null> {
    const row = await this.db
      .prepare(`SELECT evidence_json FROM kel_duplicity WHERE did = ?`)
      .bind(did)
      .first<{ evidence_json: string }>();
    return row ? (JSON.parse(row.evidence_json) as unknown) : null;
  }

  async insertIdentityLinkage(row: IdentityLinkageRow): Promise<{ inserted: boolean; stored: IdentityLinkageRow }> {
    // INSERT OR IGNORE on the from_did primary key IS the first-wins rule —
    // no read-then-write window in which two linkages could both "win".
    const result = await this.db
      .prepare(
        `INSERT OR IGNORE INTO identity_linkages (from_did, to_did, linkage_json, created_at) VALUES (?, ?, ?, ?)`,
      )
      .bind(row.fromDid, row.toDid, JSON.stringify(row.linkage), row.createdAt)
      .run();
    if ((result.meta.changes ?? 0) > 0) return { inserted: true, stored: row };
    const stored = await this.getIdentityLinkage(row.fromDid);
    // The row cannot vanish between the ignored insert and this read (nothing
    // deletes linkages), but fail loudly rather than report a phantom winner.
    if (!stored) throw new Error(`identity linkage for ${row.fromDid} disappeared`);
    const { conflictCount: _c, ...rest } = stored;
    return { inserted: false, stored: rest };
  }

  async recordIdentityLinkageConflict(fromDid: string, linkage: unknown, recordedAt: number): Promise<void> {
    await this.db
      .prepare(`INSERT INTO identity_linkage_conflicts (from_did, linkage_json, recorded_at) VALUES (?, ?, ?)`)
      .bind(fromDid, JSON.stringify(linkage), recordedAt)
      .run();
  }

  async getIdentityLinkage(fromDid: string): Promise<(IdentityLinkageRow & { conflictCount: number }) | null> {
    const row = await this.db
      .prepare(
        `SELECT l.from_did, l.to_did, l.linkage_json, l.created_at,
                (SELECT COUNT(*) FROM identity_linkage_conflicts c WHERE c.from_did = l.from_did) AS conflict_count
         FROM identity_linkages l WHERE l.from_did = ?`,
      )
      .bind(fromDid)
      .first<{ from_did: string; to_did: string; linkage_json: string; created_at: number; conflict_count: number }>();
    if (!row) return null;
    return {
      fromDid: row.from_did,
      toDid: row.to_did,
      linkage: JSON.parse(row.linkage_json) as unknown,
      createdAt: row.created_at,
      conflictCount: Number(row.conflict_count ?? 0),
    };
  }

  /**
   * Archive a key in revoked_keys unless this agent's archive already holds
   * it. The KEL path can reach the same key twice — a row suspended as
   * 'controller-sealed-ahead' archives its key at once, and the recovery
   * that later arrives supersedes that same key again — and revoked-keys
   * should list each dead key once.
   */
  private archiveKeyStmt(didHash: string, publicKeyB64: string, keyVersion: number, at: number) {
    return this.db
      .prepare(
        `INSERT INTO revoked_keys (did_hash, public_key_b64, key_version, rotated_at)
         SELECT ?, ?, ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM revoked_keys WHERE did_hash = ? AND public_key_b64 = ?)`,
      )
      .bind(didHash, publicKeyB64, keyVersion, at, didHash, publicKeyB64);
  }

  async applyKelKeyState(
    didHash: string,
    state: {
      publicKeyB64: string | null;
      keyVersion: number;
      revoked: boolean;
      controllerRevoked: boolean;
      controllerDid: string | null;
    },
  ): Promise<boolean> {
    const current = await this.db
      .prepare(
        `SELECT public_key_b64, key_version, active, controller_did, deactivated_reason
         FROM agent_records WHERE did_hash = ?`,
      )
      .bind(didHash)
      .first<{
        public_key_b64: string; key_version: number | null; active: number;
        controller_did: string | null; deactivated_reason: string | null;
      }>();
    if (!current) return false;

    const oldVersion = current.key_version ?? 1;
    // A revoked log has no current key; keep the last one on the row so the
    // record still says which key was in force when it died.
    const newKey = state.publicKeyB64 ?? current.public_key_b64;
    const keyChanged = newKey !== current.public_key_b64;
    const dead = state.revoked || state.controllerRevoked;
    const reason: KelDeactivationReason | null =
      state.revoked ? "kel-revoked" : state.controllerRevoked ? "controller-revoked" : null;
    const pending = current.active === 0 && current.deactivated_reason === "controller-sealed-ahead";
    const deactivate = dead && current.active === 1;
    // The sealed event the row was waiting for has arrived: a revoke makes
    // the take-down permanent (new reason), anything else lifts it.
    const settlePending = pending && (dead ? current.deactivated_reason !== reason : true);
    const reactivate = pending && !dead;
    const fillController = state.controllerDid !== null && current.controller_did !== state.controllerDid;
    if (!keyChanged && oldVersion === state.keyVersion && !deactivate && !settlePending && !fillController) return false;

    const now = Date.now();
    const statements = [];
    if (keyChanged) {
      // Same audit trail a registry rotation leaves (see rotateKey).
      statements.push(this.archiveKeyStmt(didHash, current.public_key_b64, oldVersion, now));
    }
    if (deactivate) {
      // The final key is dead too — archive it so revoked-keys answers
      // "which keys of this agent must no longer be trusted" completely.
      statements.push(this.archiveKeyStmt(didHash, newKey, state.keyVersion, now));
    }
    // The state transitions are re-checked against the row as it is at write
    // time (every expression below reads the OLD row), so an owner
    // deactivation landing between the SELECT above and this UPDATE is never
    // undone: only a row still marked 'controller-sealed-ahead' comes back.
    statements.push(
      this.db
        .prepare(
          `UPDATE agent_records
           SET public_key_b64 = ?, key_version = ?,
               key_rotated_at = CASE WHEN ? THEN ? ELSE key_rotated_at END,
               active = CASE
                 WHEN ? AND active = 1 THEN 0
                 WHEN ? AND active = 0 AND deactivated_reason = 'controller-sealed-ahead' THEN 1
                 ELSE active END,
               deactivated_reason = CASE
                 WHEN ? AND (active = 1 OR deactivated_reason = 'controller-sealed-ahead') THEN ?
                 WHEN ? AND active = 0 AND deactivated_reason = 'controller-sealed-ahead' THEN NULL
                 ELSE deactivated_reason END,
               controller_did = COALESCE(?, controller_did),
               last_updated_at = ?
           WHERE did_hash = ?`,
        )
        .bind(
          newKey, state.keyVersion,
          keyChanged ? 1 : 0, now,
          dead ? 1 : 0, reactivate ? 1 : 0,
          dead ? 1 : 0, reason, reactivate ? 1 : 0,
          state.controllerDid,
          now, didHash,
        ),
    );
    await this.db.batch(statements);
    return true;
  }

  async deactivateAgentsControlledBy(controllerDid: string): Promise<string[]> {
    // controller_did is the fast path; the kel_logs arm covers rows the
    // migration-015 backfill could not fill. Both read the controller from
    // the agent's own verified inception, so a person reaches only agents
    // that named them at birth.
    const { results } = await this.db
      .prepare(
        `SELECT a.did_hash, a.public_key_b64, a.key_version
         FROM agent_records a
         WHERE a.active = 1
           AND (
             a.controller_did = ?
             OR (a.controller_did IS NULL AND a.did IN (
               SELECT k.did FROM kel_logs k
               WHERE json_extract(k.events_json, '$[0].type') = 'inception'
                 AND json_extract(k.events_json, '$[0].controller') = ?
             ))
           )`,
      )
      .bind(controllerDid, controllerDid)
      .all<{ did_hash: string; public_key_b64: string; key_version: number | null }>();
    const rows = results ?? [];
    if (rows.length === 0) return [];

    const now = Date.now();
    const statements = [];
    for (const r of rows) {
      statements.push(this.archiveKeyStmt(r.did_hash, r.public_key_b64, r.key_version ?? 1, now));
      statements.push(
        this.db
          .prepare(
            `UPDATE agent_records
             SET active = 0, deactivated_reason = 'controller-revoked', controller_did = ?, last_updated_at = ?
             WHERE did_hash = ? AND active = 1`,
          )
          .bind(controllerDid, now, r.did_hash),
      );
    }
    await this.db.batch(statements);
    return rows.map((r) => r.did_hash);
  }

  async suspendAgentPendingControllerEvent(didHash: string): Promise<boolean> {
    const current = await this.db
      .prepare(`SELECT public_key_b64, key_version FROM agent_records WHERE did_hash = ? AND active = 1`)
      .bind(didHash)
      .first<{ public_key_b64: string; key_version: number | null }>();
    if (!current) return false;
    const now = Date.now();
    const [, update] = await this.db.batch([
      this.archiveKeyStmt(didHash, current.public_key_b64, current.key_version ?? 1, now),
      this.db
        .prepare(
          `UPDATE agent_records
           SET active = 0, deactivated_reason = 'controller-sealed-ahead', last_updated_at = ?
           WHERE did_hash = ? AND active = 1`,
        )
        .bind(now, didHash),
    ]);
    return (update.meta?.changes ?? 0) > 0;
  }
}

/** A spaces row as the repository reports it. */
function toSpaceRow(r: Record<string, unknown>): SpaceRow {
  return {
    id: String(r.id),
    name: String(r.name),
    description: r.description == null ? null : String(r.description),
    ownerKeyHash: String(r.owner_key_hash),
    ownerOrg: String(r.owner_org),
    createdAt: Number(r.created_at),
    archivedAt: r.archived_at == null ? null : Number(r.archived_at),
  };
}
