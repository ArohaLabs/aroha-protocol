-- Migration 008: registration ownership challenges (M6 — publish & claim)
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- See schema.sql's comment on registration_challenges for the design
-- rationale — this closes a real gap where holding a valid API key was
-- sufficient to register any did+publicKeyB64 pair, including one the
-- caller does not control the private key for.

CREATE TABLE IF NOT EXISTS registration_challenges (
  nonce      TEXT    PRIMARY KEY,
  did        TEXT    NOT NULL,
  key_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_challenge_expires ON registration_challenges (expires_at);
