-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 016: spending-mandate revocations and shared redemption totals
-- (routes/mandates.ts — POST/GET /v1/mandates/:mandateId/{revoke,revoked,redeem,redemptions}).
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- WHY
--
-- verifyMandateChain (@aroha-sdk/credentials) asks an isRevoked hook about
-- every link of a chain, and redeemPaymentMandate charges a RedemptionStore —
-- but nothing outside a single process answered either. These tables are the
-- registry's shared memory for both facts.
--
-- mandate_revocations: one row per revoked mandate, first wins and is never
-- removed (revocation is permanent). The signature and signer are kept so a
-- revocation can be re-verified later by anyone auditing the registry.
--
-- mandate_redemption_totals / mandate_redemptions: the exact schema of
-- D1RedemptionStore in @aroha-sdk/credentials (redemption-d1.ts), which the
-- route uses directly — the check-and-add is one D1 batch whose conditional
-- UPDATE is the cap. Amounts are integer micro-USD so repeated decimal
-- redemptions cannot drift past the limit.

-- Keyed by (mandate_id, grantor): a mandateId is chosen by whoever mints the
-- mandate, so the id alone would let anyone mint a valid mandate reusing
-- someone else's id and revoke theirs. `grantor` is the revoked mandate's own
-- grantor, which its signature fixes.
CREATE TABLE IF NOT EXISTS mandate_revocations (
  mandate_id  TEXT    NOT NULL,
  grantor     TEXT    NOT NULL,
  revoked_at  INTEGER NOT NULL,
  revoked_by  TEXT    NOT NULL,
  signature   TEXT    NOT NULL,
  recorded_at INTEGER NOT NULL,
  PRIMARY KEY (mandate_id, grantor)
);

-- mandate_id here holds mandateRedemptionKey(mandate) — `<grantor>#<mandateId>`
-- — for the same reason mandate_revocations is keyed by the grantor too.
CREATE TABLE IF NOT EXISTS mandate_redemption_totals (
  mandate_id      TEXT    PRIMARY KEY,
  limit_micros    INTEGER NOT NULL CHECK (limit_micros >= 0),
  redeemed_micros INTEGER NOT NULL DEFAULT 0 CHECK (redeemed_micros >= 0),
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mandate_redemptions (
  redemption_id TEXT    PRIMARY KEY,
  mandate_id    TEXT    NOT NULL,
  amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
  merchant      TEXT    NOT NULL,
  redeemed_at   INTEGER NOT NULL,
  actor         TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mandate_redemptions_mandate ON mandate_redemptions (mandate_id);
