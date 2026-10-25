-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- 003 — Private agents: visibility levels + explicit access grants.
--
-- visibility semantics (agents, MCP servers, and skills alike):
--   'public'   — appears in capability discovery and list results (default,
--                preserves all existing behaviour)
--   'unlisted' — never returned by list/discovery, but resolvable by didHash
--                if you already know it (share-by-link)
--   'private'  — invisible unless the caller is the owner or holds an
--                unexpired access grant; resolve-by-didHash is denied too
--
-- Run once against an existing DB:
--   wrangler d1 execute aroha-registry --remote --file=migrations/003_visibility_and_grants.sql

ALTER TABLE agent_records ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';
ALTER TABLE mcp_records   ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';
ALTER TABLE skill_records ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public';

CREATE INDEX IF NOT EXISTS idx_agent_visibility ON agent_records (visibility);
CREATE INDEX IF NOT EXISTS idx_mcp_visibility   ON mcp_records   (visibility);
CREATE INDEX IF NOT EXISTS idx_skill_visibility ON skill_records (visibility);

-- ─── Access grants ───────────────────────────────────────────────────────────
--
-- One row = "the owner of <resource> grants <grantee> access".
--
-- Two grantee forms, because they serve different layers:
--   grantee_did       — an agent DID. Used at CALL time (the agent-side
--                       allow-list) and for DID-scoped discovery.
--   grantee_key_hash  — an org API key hash. Used at DISCOVERY time, since
--                       registry callers authenticate with an API key.
-- At least one must be non-NULL. Setting both scopes the grant to that agent
-- when reached through that org's key.
--
-- capabilities: JSON array of capability IDs the grant covers; NULL = all of
-- the resource's capabilities.

CREATE TABLE IF NOT EXISTS access_grants (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  resource_did_hash   TEXT    NOT NULL,
  resource_type       TEXT    NOT NULL,  -- 'agent' | 'mcp' | 'skill'
  grantee_did         TEXT,
  grantee_key_hash    TEXT,
  capabilities        TEXT,              -- JSON array; NULL = all
  -- SHA-256 of the API key that created the grant. Must match the resource's
  -- owner_key_hash — enforced in the route, recorded here for audit.
  granted_by_key_hash TEXT    NOT NULL,
  note                TEXT,              -- free-form label, e.g. "CI pipeline"
  expires_at          INTEGER,           -- Unix ms; NULL = no expiry
  created_at          INTEGER NOT NULL,
  revoked_at          INTEGER,           -- soft delete, preserves the audit trail
  CHECK (grantee_did IS NOT NULL OR grantee_key_hash IS NOT NULL)
);

-- One live grant per (resource, grantee). Partial indexes exclude revoked rows
-- so a resource can be re-granted after revocation.
CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_unique_did
  ON access_grants (resource_did_hash, grantee_did)
  WHERE grantee_did IS NOT NULL AND revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_unique_key
  ON access_grants (resource_did_hash, grantee_key_hash)
  WHERE grantee_key_hash IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_grant_resource ON access_grants (resource_did_hash, revoked_at);
CREATE INDEX IF NOT EXISTS idx_grant_key      ON access_grants (grantee_key_hash, revoked_at);
CREATE INDEX IF NOT EXISTS idx_grant_did      ON access_grants (grantee_did, revoked_at);
