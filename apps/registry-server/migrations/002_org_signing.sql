-- Migration 002: Org signing keypair and agent org-signature
--
-- Run against production D1:
--   wrangler d1 execute aroha-registry --file=migrations/002_org_signing.sql
--
-- Enables the org-signed verification tier:
--   1. Org registers their Ed25519 public key via PUT /v1/auth/org-key
--      (proven by hosting /.well-known/aroha-org.json at their domain)
--   2. On agent registration, org signs the canonical payload with their private key
--   3. Registry verifies sig → verificationTier = 'org-signed'

-- ─── api_keys additions ───────────────────────────────────────────────────────

-- Ed25519 public key (base64) the org uses to sign agent registrations
ALTER TABLE api_keys ADD COLUMN org_public_key_b64 TEXT;

-- Domain at which the org key was verified (via /.well-known/aroha-org.json)
ALTER TABLE api_keys ADD COLUMN org_key_domain TEXT;

-- Unix ms when org key was last verified
ALTER TABLE api_keys ADD COLUMN org_key_verified_at INTEGER;

-- ─── agent_records additions ─────────────────────────────────────────────────

-- Base64 Ed25519 signature the org produced over the canonical registration payload.
-- Stored for audit — allows offline verification that the org authorised this agent.
ALTER TABLE agent_records ADD COLUMN org_signature TEXT;
