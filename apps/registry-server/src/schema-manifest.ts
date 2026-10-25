// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The schema this build of the worker requires in order to serve traffic.
//
// Why this exists: production once ran two migrations behind for weeks without
// any signal. Nothing broke until a deploy shipped code that SELECTed the new
// columns, at which point every list endpoint returned a 500 while /health
// still cheerfully reported `db: ok` — because its one query happened not to
// touch the missing columns.
//
// So /health now verifies this manifest against the live database instead of
// inferring health from a single lucky query. A database missing anything
// listed here is reported as `degraded` with the specific gap named, which
// turns "mysterious 500s" into "agent_records is missing discovery_eligible_at".
//
// This is deliberately NOT a full copy of schema.sql — it lists the columns the
// running code depends on, not every column that exists. Two tests keep it
// honest (see schema-drift.test.ts):
//   1. every column named here exists in schema.sql
//   2. every column any migration adds also exists in schema.sql
// Together those mean this file cannot drift from the schema without CI failing.

/** Tables the worker requires, and the columns it reads or writes on each. */
export const REQUIRED_SCHEMA: Record<string, string[]> = {
  agent_records: [
    "did_hash", "did", "owner_key_hash", "org_name", "manifest_cid",
    "public_key_b64", "staked_wei", "reputation_score", "active",
    "registered_at", "last_updated_at", "endpoint_url",
    "key_version", "key_rotated_at",
    // migration 001 — the columns whose absence caused the outage
    "verification_tier", "domain", "domain_verified", "discovery_eligible_at",
    // migration 002
    "org_signature",
    // migration 003
    "visibility",
    // migration 015 — the controller cascade (kel-store.ts)
    "controller_did", "deactivated_reason",
    // migration 019 — operator-recorded audit (certification tier)
    "audited_at", "audit_reference",
  ],
  capability_index: ["capability_id", "did_hash"],
  mcp_records: [
    "did_hash", "did", "owner_key_hash", "org_name", "name", "description",
    "endpoint_url", "tool_ids", "manifest_cid", "active",
    "registered_at", "last_updated_at", "visibility",
  ],
  skill_records: [
    "did_hash", "did", "owner_key_hash", "org_name", "name", "description",
    "skill_type", "endpoint_url", "manifest_cid", "active",
    "registered_at", "last_updated_at", "visibility",
  ],
  api_keys: [
    "key_hash", "org_name", "owner_id", "created_at", "active",
    "verified", "verified_domain",
    "org_public_key_b64", "org_key_domain", "org_key_verified_at",
  ],
  access_grants: [
    "id", "resource_did_hash", "resource_type", "grantee_did", "grantee_key_hash",
    "capabilities", "granted_by_key_hash", "note", "expires_at",
    "created_at", "revoked_at",
  ],
  revoked_keys: ["id", "did_hash", "public_key_b64", "key_version", "rotated_at"],
  rotation_nonces: ["nonce", "did_hash", "expires_at"],
  spending_budgets: [
    "mandate_id", "limit_usd", "allocated_usd", "owner_key_hash",
    "expires_at", "created_at",
    // migration 018 — budgets bound to a verified mandate
    "limit_source", "chain_keys",
  ],
  // migration 018 — external witness for runtime audit heads
  audit_anchors: [
    "install_did", "seq", "hash", "signed_at", "anchored_at", "log_index",
    "prev_anchor_hash", "witness_signature", "witness_key_id", "install_signature",
  ],
  // migration 019 — Shared Signals transmitter (routes/ssf.ts)
  ssf_streams: [
    "stream_id", "owner_key_hash", "iss", "aud", "delivery_method", "endpoint_url",
    "authorization_header", "events_requested", "events_delivered", "description",
    "status", "status_reason", "created_at", "updated_at",
  ],
  ssf_outbox: [
    "stream_id", "jti", "event_type", "set_jwt", "subject_dids", "created_at", "attempts",
    "next_attempt_at", "delivered_at", "failed_at", "last_error",
  ],
  spending_allocations: [
    "allocation_id", "mandate_id", "amount_usd", "allocated_at", "released_at",
  ],
  analytics_events: ["id", "event_type", "did_hash", "created_at"],
  signal_rate_limits: ["key_hash", "did_hash", "window_start", "count"],
  model_catalog: [
    "model_id", "provider", "tier", "input_price_per_mtok",
    "output_price_per_mtok", "context_window", "avg_latency_ms", "active", "updated_at",
  ],
  routing_signals: [
    "id", "model_id", "task_type", "complexity_bucket", "quality",
    "token_count", "api_key_hash", "created_at",
  ],
  admin_audit_log: ["id", "action", "actor", "target", "ip", "created_at"],
  schema_migrations: ["filename", "applied_at"],
  kyc_issuers: ["issuer_did", "public_key_b64", "domain", "registered_at", "revoked_at"],
  verified_caller_nullifiers: [
    "nullifier", "scope", "commitment", "issuer_did", "caller_did", "verified_at", "revoked_at",
  ],
  caller_attestations: [
    "id", "saga_id", "agent_did_hash", "caller_did", "success",
    "domain", "caller_weight", "submitted_at",
  ],
  firm_licenses: ["firm_did", "public_key_hex", "name", "licensed_at", "revoked_at"],
  // migration 014 — rotatable E-DIDs. Listed because every /v1/kel and
  // /v1/linkage request, E-DID registration and E-DID SAR publish reads them:
  // a database that skipped 014 should say so on /health, not 500 there.
  kel_logs: ["did", "events_json", "sequence", "last_digest", "updated_at"],
  kel_duplicity: ["did", "evidence_json", "recorded_at"],
  identity_linkages: ["from_did", "to_did", "linkage_json", "created_at"],
  identity_linkage_conflicts: ["from_did", "linkage_json", "recorded_at"],
  // subdomain_claims is deliberately absent. This manifest lists what the
  // CODE needs, and the vanity-subdomain flow that owned that table has been
  // removed. The table itself is left in the database — dropping a table with
  // rows in it is a separate, destructive decision — but demanding its columns
  // here made /health report "degraded" over a migration for a feature that no
  // longer exists, which is a health check measuring the wrong thing.
};

export interface SchemaGap {
  table: string;
  /** Columns the code needs that the database does not have. */
  missingColumns?: string[];
  /** True when the table itself is absent. */
  missing?: boolean;
}

/** Minimal shape of the D1 binding this check needs — keeps it testable. */
interface QueryableDb {
  prepare(sql: string): {
    bind(...values: unknown[]): { all<T>(): Promise<{ results: T[] }> };
  };
}

/**
 * Compare the live database against REQUIRED_SCHEMA.
 *
 * Returns one entry per table that is absent or short a column. An empty array
 * means the database can serve every query this build issues.
 */
export async function findSchemaGaps(db: QueryableDb): Promise<SchemaGap[]> {
  const gaps: SchemaGap[] = [];

  for (const [table, required] of Object.entries(REQUIRED_SCHEMA)) {
    // pragma_table_info returns zero rows for a table that does not exist,
    // which is indistinguishable here from a table with no columns — and a
    // table with no columns cannot exist, so zero rows means "missing".
    const { results } = await db
      .prepare(`SELECT name FROM pragma_table_info(?)`)
      .bind(table)
      .all<{ name: string }>();

    if (results.length === 0) {
      gaps.push({ table, missing: true });
      continue;
    }

    const present = new Set(results.map((r) => r.name));
    const missingColumns = required.filter((c) => !present.has(c));
    if (missingColumns.length > 0) gaps.push({ table, missingColumns });
  }

  return gaps;
}
