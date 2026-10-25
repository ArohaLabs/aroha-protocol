-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 018: audit anchors (an external witness for runtime audit heads),
-- and spending budgets bound to a verified mandate.
--
-- Run against production D1 (after 017):
--   node scripts/migrate.mjs --remote
--
-- WHY — audit_anchors
--
-- A runtime signs checkpoints of its audit log's live head, but every piece
-- of evidence stays on the runtime's own machine, so removing the newest
-- checkpoints together with the matching log tail is undetectable from the
-- files alone. POST /v1/audit-anchors records each signed checkpoint here,
-- timestamped, chained (prev_anchor_hash) and countersigned with the
-- registry's key (routes/audit-anchors.ts).
--
-- PERMANENT. This table is deliberately NOT in the retention prune
-- (src/retention.ts): an anchor is only useful if it is still there when a
-- log is checked, possibly years later, and deleting old anchors would
-- recreate exactly the undetectable-truncation gap they close. Rows are
-- small (one per checkpoint, at most every 100 entries / 5 minutes).
--
-- (install_did, log_index) is UNIQUE: two racing appends cannot both take
-- the same position in an install's chain.
CREATE TABLE IF NOT EXISTS audit_anchors (
  install_did       TEXT    NOT NULL,
  seq               INTEGER NOT NULL CHECK (seq >= 0),
  hash              TEXT    NOT NULL,
  signed_at         TEXT    NOT NULL,   -- exactly the string the install signed
  anchored_at       TEXT    NOT NULL,   -- ISO 8601, server time
  log_index         INTEGER NOT NULL CHECK (log_index >= 0),
  prev_anchor_hash  TEXT    NOT NULL DEFAULT '',
  witness_signature TEXT    NOT NULL,   -- base64url Ed25519 over JCS(anchor)
  witness_key_id    TEXT    NOT NULL,
  install_signature TEXT    NOT NULL,   -- the install's own signature, kept as evidence
  PRIMARY KEY (install_did, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_anchors_log ON audit_anchors (install_did, log_index);

-- WHY — spending_budgets.limit_source / chain_keys
--
-- POST /v1/spending/budgets used to take limitUsd from the request body, so
-- any API key holder could open a pool of any size for any mandateId. The
-- route now verifies the mandate token (the same verifyMandateChain path as
-- /v1/mandates), derives the limit from the verified leaf, and keys the
-- budget by `<grantor>#<mandateId>`.
--
-- limit_source: 'mandate' for budgets created that way; existing rows are
-- 'caller' — their limit was never verified. The routes only operate on
-- 'mandate' rows, so legacy budgets stop being usable (allocate / release /
-- status answer 404) and must be re-created by posting the mandate token;
-- a re-create replaces a legacy row with the same key. Rows are kept, not
-- deleted, so their history stays inspectable by the operator.
--
-- chain_keys: JSON array of `<grantor>#<mandateId>` for every link of the
-- verified chain, so allocate can refuse once any of them is revoked here.
ALTER TABLE spending_budgets ADD COLUMN limit_source TEXT NOT NULL DEFAULT 'caller';
ALTER TABLE spending_budgets ADD COLUMN chain_keys TEXT;
