-- Migration 010: relay connect tokens (M10 — relay broker, spec §6.3)
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- See schema.sql's comment on relay_connect_tokens for the design
-- rationale — proves WebSocket-connect key possession before letting a
-- caller claim to BE a given agent DID on its relay Durable Object.

CREATE TABLE IF NOT EXISTS relay_connect_tokens (
  token      TEXT    PRIMARY KEY,
  did_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relay_connect_expires ON relay_connect_tokens (expires_at);
