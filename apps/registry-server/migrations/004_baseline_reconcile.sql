-- Migration 004: reconcile pre-migrations baseline
--
--   node scripts/migrate.mjs --remote
--
-- Everything here was added to schema.sql before migrations/ existed. schema.sql
-- carried a comment saying these ALTERs were "intentionally NOT in this file"
-- and had to be run by hand on older databases — so on production, nobody ever
-- did. The tables and columns existed in the code and in every freshly created
-- database, and were simply absent from the one deployment that mattered.
--
-- Nothing depended on them from the hot discovery path, so the gap stayed
-- invisible: /v1/agents worked fine. The first key rotation, spending
-- allocation, or analytics write would have thrown "no such table" in
-- production only.
--
-- Found by the schema check added to /health, which compares the live database
-- against the schema this build actually requires.
--
-- Safe to re-run: every CREATE uses IF NOT EXISTS. The two ALTERs are not
-- idempotent (SQLite has no ADD COLUMN IF NOT EXISTS), so scripts/migrate.mjs
-- probes for the column before replaying this file.

-- ─── Key versioning on agent_records ─────────────────────────────────────────

-- Increments on every key rotation; lets mandate verifiers detect a stale
-- cached public key without a full registry round-trip.
ALTER TABLE agent_records ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1;

-- Unix ms of the most recent rotation. Mandate tokens whose issuedAt precedes
-- this were signed with a revoked key and must be rejected. NULL = never rotated.
ALTER TABLE agent_records ADD COLUMN key_rotated_at INTEGER;

-- ─── Key-rotation audit trail ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS revoked_keys (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  did_hash       TEXT    NOT NULL,
  public_key_b64 TEXT    NOT NULL,  -- the key that was rotated OUT
  key_version    INTEGER NOT NULL,  -- version it held before rotation
  rotated_at     INTEGER NOT NULL,
  FOREIGN KEY (did_hash) REFERENCES agent_records (did_hash) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_revoked_did ON revoked_keys (did_hash);

-- Nonce dedup closing the rotate-key replay window that the issuedAt guard
-- alone cannot close.
CREATE TABLE IF NOT EXISTS rotation_nonces (
  nonce      TEXT    PRIMARY KEY,
  did_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nonce_expires ON rotation_nonces (expires_at);

-- ─── Spending ledger ─────────────────────────────────────────────────────────
-- Stops an orchestrator holding one $500 mandate from issuing N children that
-- each claim $500.

CREATE TABLE IF NOT EXISTS spending_budgets (
  mandate_id      TEXT PRIMARY KEY,
  limit_usd       REAL NOT NULL CHECK (limit_usd > 0),
  allocated_usd   REAL NOT NULL DEFAULT 0 CHECK (allocated_usd >= 0),
  owner_key_hash  TEXT NOT NULL DEFAULT '',
  expires_at      INTEGER,
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_budget_owner   ON spending_budgets (owner_key_hash);
CREATE INDEX IF NOT EXISTS idx_budget_expires ON spending_budgets (expires_at);

CREATE TABLE IF NOT EXISTS spending_allocations (
  allocation_id TEXT    PRIMARY KEY,
  mandate_id    TEXT    NOT NULL,
  amount_usd    REAL    NOT NULL CHECK (amount_usd > 0),
  allocated_at  INTEGER NOT NULL,
  released_at   INTEGER,
  FOREIGN KEY (mandate_id) REFERENCES spending_budgets (mandate_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alloc_mandate ON spending_allocations (mandate_id);
CREATE INDEX IF NOT EXISTS idx_alloc_active  ON spending_allocations (mandate_id, released_at);

-- ─── Analytics and signal rate limiting ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS analytics_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT    NOT NULL,
  did_hash   TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analytics_did_hash   ON analytics_events (did_hash);
CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_events (created_at);

-- Caps how many reputation signals one API key can file against one agent per
-- window, so a single caller cannot manufacture a reputation.
CREATE TABLE IF NOT EXISTS signal_rate_limits (
  key_hash     TEXT    NOT NULL,
  did_hash     TEXT    NOT NULL,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_hash, did_hash, window_start)
);

-- ─── Model routing ───────────────────────────────────────────────────────────
-- Catalogue the router selects from, plus observed quality signals fed back by
-- callers. Quality is tracked per task type so the router can prefer a cheap
-- model for extraction and an expensive one for reasoning.

CREATE TABLE IF NOT EXISTS model_catalog (
  model_id               TEXT    PRIMARY KEY,
  provider               TEXT    NOT NULL,
  tier                   INTEGER NOT NULL,
  input_price_per_mtok   REAL    NOT NULL,
  output_price_per_mtok  REAL    NOT NULL,
  context_window         INTEGER NOT NULL,
  avg_latency_ms         INTEGER NOT NULL,
  quality_reasoning      REAL    NOT NULL DEFAULT 0.7,
  quality_code           REAL    NOT NULL DEFAULT 0.7,
  quality_extraction     REAL    NOT NULL DEFAULT 0.7,
  quality_creative       REAL    NOT NULL DEFAULT 0.7,
  quality_classification REAL    NOT NULL DEFAULT 0.7,
  quality_summarization  REAL    NOT NULL DEFAULT 0.7,
  active                 INTEGER NOT NULL DEFAULT 1,
  updated_at             INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_signals (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  model_id          TEXT    NOT NULL,
  task_type         TEXT    NOT NULL,
  complexity_bucket INTEGER NOT NULL CHECK (complexity_bucket BETWEEN 0 AND 9),
  quality           REAL    NOT NULL CHECK (quality BETWEEN 0 AND 1),
  token_count       INTEGER NOT NULL DEFAULT 0,
  api_key_hash      TEXT    NOT NULL,
  created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_routing_signals_model
  ON routing_signals (model_id, task_type, complexity_bucket);

-- ─── Admin audit ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  action     TEXT    NOT NULL,
  actor      TEXT    NOT NULL,
  target     TEXT,
  ip         TEXT,
  created_at INTEGER NOT NULL
);
