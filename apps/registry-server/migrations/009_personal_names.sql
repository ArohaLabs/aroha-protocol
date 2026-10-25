-- Migration 009: personal agent names (M7 — key-derived naming, spec §7.10)
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- See schema.sql's comment on personal_names for the design rationale —
-- this table is a routing lookup cache, not a trust boundary: the label
-- it stores is independently verifiable by anyone from the DID alone.

CREATE TABLE IF NOT EXISTS personal_names (
  label          TEXT    PRIMARY KEY,
  did_hash       TEXT    NOT NULL UNIQUE,
  did            TEXT    NOT NULL,
  owner_key_hash TEXT    NOT NULL,
  minted_at      INTEGER NOT NULL
);
