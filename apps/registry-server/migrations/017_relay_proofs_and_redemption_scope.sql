-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 017: single-use relay connect proofs, and redemption ids scoped
-- to their mandate.
--
-- Run against production D1 (after 016):
--   node scripts/migrate.mjs --remote
--
-- WHY — relay_connect_proofs
--
-- POST /v1/relay/connect accepts a signature over {did, timestamp} and
-- issues a WebSocket token. The timestamp is only bounded to ±5 minutes, so
-- the same signed proof could be presented again and again inside that
-- window, minting a fresh token each time. A server-issued nonce would close
-- that too, but it changes the protocol every relay client speaks; recording
-- each accepted proof (by the SHA-256 of its signature) until its timestamp
-- leaves the window refuses the replay with no client change. Rows expire at
-- timestamp + window and are removed by the scheduled retention job.
CREATE TABLE IF NOT EXISTS relay_connect_proofs (
  signature_hash TEXT    PRIMARY KEY,
  did_hash       TEXT    NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relay_connect_proofs_expires ON relay_connect_proofs (expires_at);

-- WHY — mandate_redemptions keyed by (mandate_id, redemption_id)
--
-- redemption_id is chosen by the redeeming caller (an idempotency handle),
-- yet it was the table's whole primary key. Any caller could therefore
-- occupy an id another mandate's payee later chose — that redemption then
-- failed on the key collision (a 500) after its chain had verified. Scoping
-- the key to mandate_id (`<grantor>#<mandateId>`) keeps ids independent per
-- mandate; a repeat within one mandate is answered 409 by the route.
--
-- SQLite cannot change a primary key in place, so the table is rebuilt.
-- Written to be safe to replay: every step is IF NOT EXISTS / OR IGNORE,
-- and re-running it copies the (already rebuilt) table onto itself.
CREATE TABLE IF NOT EXISTS mandate_redemptions_v017 (
  redemption_id TEXT    NOT NULL,
  mandate_id    TEXT    NOT NULL,
  amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
  merchant      TEXT    NOT NULL,
  redeemed_at   INTEGER NOT NULL,
  actor         TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (mandate_id, redemption_id)
);
INSERT OR IGNORE INTO mandate_redemptions_v017
  (redemption_id, mandate_id, amount_micros, merchant, redeemed_at, actor)
  SELECT redemption_id, mandate_id, amount_micros, merchant, redeemed_at, actor FROM mandate_redemptions;
DROP TABLE mandate_redemptions;
ALTER TABLE mandate_redemptions_v017 RENAME TO mandate_redemptions;
CREATE INDEX IF NOT EXISTS idx_mandate_redemptions_mandate ON mandate_redemptions (mandate_id);
