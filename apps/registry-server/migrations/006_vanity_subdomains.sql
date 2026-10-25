-- Migration 006: firm licensing + vanity subdomain provisioning
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- Backs POST /v1/provision-subdomain (see routes/provision.ts). A firm's
-- local studio signs a provisioning request with its own firm-level Ed25519
-- key (already minted by store.firm_identity() in aroha-doc-intel — never
-- transmitted) instead of holding a Wix credential itself. This service is
-- the only thing that holds the real Wix DNS API key.
--
-- firm_licenses: the actual access control. A valid signature only proves
-- possession of the firm's private key — it says nothing about whether that
-- DID is a paying customer. Rows here are the licensing decision, populated
-- by an admin-gated route (no automated billing integration exists yet to
-- populate this any other way).
--
-- subdomain_claims: one row per claimed subdomain. PRIMARY KEY on subdomain
-- enforces "one claimant" at the DB level; the firm_did index lets the route
-- enforce "one subdomain per firm" the other direction. Re-provisioning the
-- same (firm_did, subdomain) pair (e.g. after a laptop reinstall picks a new
-- tunnel id) is an idempotent UPDATE of target, not an error — see the ON
-- CONFLICT clause on the insert in d1-repository.ts.
--
-- No separate rate-limit table: the endpoint uses the same in-memory
-- sliding-window limiter (middleware/rate-limit.ts) every other public
-- endpoint in this worker uses, not a DB-backed one.

CREATE TABLE IF NOT EXISTS firm_licenses (
  firm_did        TEXT    PRIMARY KEY,
  public_key_hex  TEXT    NOT NULL,
  name            TEXT    NOT NULL DEFAULT '',
  licensed_at     INTEGER NOT NULL,
  revoked_at      INTEGER
);

CREATE TABLE IF NOT EXISTS subdomain_claims (
  subdomain    TEXT    PRIMARY KEY,
  firm_did     TEXT    NOT NULL,
  target       TEXT    NOT NULL,
  hostname     TEXT    NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subdomain_claims_firm ON subdomain_claims (firm_did);
