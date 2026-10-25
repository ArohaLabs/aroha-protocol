-- Migration 007: Signed Agent Record index (M5 — federated discovery)
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- See schema.sql's own comment on sar_records for the design rationale.
-- One row per DID — a republish replaces the prior record. Verification
-- happens in the route (sar-verify.ts) before a row is ever written.

CREATE TABLE IF NOT EXISTS sar_records (
  did              TEXT    PRIMARY KEY,
  capabilities     TEXT    NOT NULL,
  transports       TEXT    NOT NULL,
  settlement_rails TEXT    NOT NULL,
  terms            TEXT    NOT NULL,
  issued_at        INTEGER NOT NULL,
  ttl              INTEGER NOT NULL,
  signature        TEXT    NOT NULL,
  stored_at        INTEGER NOT NULL
);
