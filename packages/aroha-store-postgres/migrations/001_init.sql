-- @aroha-sdk/store-postgres schema v1 (table prefix "aroha_")
-- Shared with the Python stores. Idempotent: every statement is IF NOT EXISTS.

-- HttpPresentationNonceStore: one row per claimed "<holder> <nonce>".
CREATE TABLE IF NOT EXISTS aroha_http_nonces (
  key            TEXT   PRIMARY KEY,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS aroha_http_nonces_expires_idx ON aroha_http_nonces (expires_at_ms);

-- EnrollmentStore: outstanding single-use challenges.
CREATE TABLE IF NOT EXISTS aroha_enrollment_challenges (
  challenge      TEXT   PRIMARY KEY,
  account_id     TEXT   NOT NULL,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS aroha_enrollment_challenges_expires_idx ON aroha_enrollment_challenges (expires_at_ms);

-- EnrollmentStore: account -> enrolled DID.
CREATE TABLE IF NOT EXISTS aroha_enrollment_bindings (
  account_id  TEXT        PRIMARY KEY,
  did         TEXT        NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ISpendingLedger: one budget per ledger key (grantor#mandateId), integer micro-USD.
CREATE TABLE IF NOT EXISTS aroha_spending_budgets (
  key               TEXT   PRIMARY KEY,
  limit_micros      BIGINT NOT NULL CHECK (limit_micros >= 0),
  allocated_micros  BIGINT NOT NULL DEFAULT 0 CHECK (allocated_micros >= 0)
);
-- Optional budget expiry (Unix ms; NULL = never expires).
ALTER TABLE aroha_spending_budgets ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT;

-- ISpendingLedger: one row per live allocation; release() deletes it.
CREATE TABLE IF NOT EXISTS aroha_spending_allocations (
  key            TEXT   NOT NULL REFERENCES aroha_spending_budgets (key) ON DELETE CASCADE,
  allocation_id  TEXT   NOT NULL,
  amount_micros  BIGINT NOT NULL CHECK (amount_micros >= 0),
  PRIMARY KEY (key, allocation_id)
);
