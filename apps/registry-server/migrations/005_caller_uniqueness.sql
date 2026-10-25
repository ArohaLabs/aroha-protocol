-- Migration 005: KYC issuers, verified-caller nullifiers, caller attestations
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- Three tables supporting Sybil-resistant reputation weighting:
--
-- kyc_issuers: orgs trusted to certify "this credential commitment belongs
-- to a real, unique verified human/entity" — trust established the same way
-- org-signed agent registration already works (domain ownership proof via
-- .well-known), applied to a distinct issuer role rather than reusing the
-- agent-signing key registration.
--
-- verified_caller_nullifiers: the actual Sybil-resistance mechanism. Each row
-- is a dedup key (a Chaum-Pedersen nullifier — see @aroha-sdk/trust) proving
-- possession of a KYC-certified secret, without revealing the secret. The
-- PRIMARY KEY on nullifier is the enforcement: the same certified secret can
-- never produce two live rows for the same scope, so becoming N "verified"
-- callers costs N distinct KYC certifications, not N free DIDs.
--
-- caller_attestations: individual caller-signed claims about a specific,
-- real interaction (tied to a sagaId). This is the Layer-0 piece that didn't
-- exist anywhere in the codebase before — the only prior reputation-signal
-- path was a single shared admin key POSTing aggregate stats with no
-- per-caller attribution at all.

CREATE TABLE IF NOT EXISTS kyc_issuers (
  issuer_did      TEXT    PRIMARY KEY,
  public_key_b64  TEXT    NOT NULL,
  domain          TEXT    NOT NULL,
  registered_at   INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_kyc_issuers_domain ON kyc_issuers (domain);

CREATE TABLE IF NOT EXISTS verified_caller_nullifiers (
  nullifier       TEXT    PRIMARY KEY,  -- base64url(N) — the dedup key itself
  scope           TEXT    NOT NULL,
  commitment      TEXT    NOT NULL,     -- base64url(P), the credential's public commitment
  issuer_did      TEXT    NOT NULL,     -- which kyc_issuers row certified this
  caller_did      TEXT    NOT NULL,     -- the did:aroha this verification is bound to
  verified_at     INTEGER NOT NULL,
  revoked_at      INTEGER,
  FOREIGN KEY (issuer_did) REFERENCES kyc_issuers (issuer_did)
);
-- Lookup direction the attestation-ingestion path actually needs: given a
-- caller DID, is there a live (non-revoked) verification for it?
CREATE INDEX IF NOT EXISTS idx_nullifier_caller ON verified_caller_nullifiers (caller_did, revoked_at);

CREATE TABLE IF NOT EXISTS caller_attestations (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  saga_id         TEXT    NOT NULL,
  agent_did_hash  TEXT    NOT NULL,
  caller_did      TEXT    NOT NULL,
  success         INTEGER NOT NULL,        -- 0/1
  domain          TEXT    NOT NULL DEFAULT 'general',
  caller_weight   REAL    NOT NULL,        -- resolved at ingestion time from the caller's tier
  submitted_at    INTEGER NOT NULL,
  -- One attestation per (saga, caller): a caller can't inflate a single real
  -- interaction into many signals by resubmitting.
  UNIQUE (saga_id, caller_did)
);
CREATE INDEX IF NOT EXISTS idx_attestations_agent ON caller_attestations (agent_did_hash, domain);
