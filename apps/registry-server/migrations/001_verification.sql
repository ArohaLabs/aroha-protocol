-- Migration 001: Agent verification tiers and discovery cooldown
--
-- Run against production D1:
--   wrangler d1 execute aroha-registry --file=migrations/001_verification.sql
--
-- SQLite ALTER TABLE only supports ADD COLUMN (not DROP/MODIFY).
-- All new columns have safe defaults so existing rows are immediately valid.

-- ─── agent_records additions ──────────────────────────────────────────────────

-- Trust tier: 'community' (default) | 'domain' (passed .well-known check)
ALTER TABLE agent_records ADD COLUMN verification_tier TEXT NOT NULL DEFAULT 'community';

-- Domain that was verified via /.well-known/aroha-did.json
ALTER TABLE agent_records ADD COLUMN domain TEXT;

-- 1 once .well-known check succeeded; 0 until then
ALTER TABLE agent_records ADD COLUMN domain_verified INTEGER NOT NULL DEFAULT 0;

-- New agents are hidden from public discovery until this timestamp (Unix ms).
-- NULL means immediately eligible (pre-migration rows are treated as eligible).
ALTER TABLE agent_records ADD COLUMN discovery_eligible_at INTEGER;

-- ─── api_keys additions ───────────────────────────────────────────────────────

-- 1 once org email domain has been verified (future email-verification flow)
ALTER TABLE api_keys ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;

-- Domain used for email-domain verification (e.g. "acme.com")
ALTER TABLE api_keys ADD COLUMN verified_domain TEXT;

-- ─── Indexes ─────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_agent_discovery_eligible ON agent_records (discovery_eligible_at);
CREATE INDEX IF NOT EXISTS idx_agent_verification_tier  ON agent_records (verification_tier);
