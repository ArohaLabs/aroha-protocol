-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 019: Shared Signals Framework transmitter (streams and a durable
-- delivery outbox), and the operator-set "audited" fact behind the agent
-- certification tier.
--
-- Run against production D1 (after 018):
--   node scripts/migrate.mjs --remote
--
-- WHY — ssf_streams / ssf_outbox
--
-- Revocation used to be pull-only: a verifier asked GET /v1/mandates/:id/revoked
-- or re-fetched a KEL, behind its own caches. Identity platforms learn about
-- revocations through OpenID Shared Signals (SSF) streams instead, so the
-- registry now acts as an SSF transmitter (routes/ssf.ts, ssf.ts): a receiver
-- creates a stream, and every mandate revocation and DID/KEL revocation the
-- registry accepts becomes a signed Security Event Token (SET) queued for each
-- enabled stream.
--
-- ssf_outbox is the durable queue. A row is written in the same request that
-- accepted the revocation; push streams (RFC 8935) are attempted at once and
-- retried by the hourly cron with backoff; poll streams (RFC 8936) keep the
-- row until the receiver acknowledges its jti. Each row holds the exact SET
-- that was signed, so a retry re-sends the same bytes (the same jti).
--
-- authorization_header is the receiver's own credential for its push
-- endpoint (SSF delivery.authorization_header). It is stored so retries can
-- present it, and never returned by any read route.
--
-- RETENTION: outbox rows are pruned 30 days after creation (src/retention.ts).
-- A stream's configuration is kept until its owner deletes it.
CREATE TABLE IF NOT EXISTS ssf_streams (
  stream_id            TEXT    PRIMARY KEY,
  owner_key_hash       TEXT    NOT NULL,
  iss                  TEXT    NOT NULL,   -- the transmitter issuer at creation (request origin)
  aud                  TEXT    NOT NULL,
  delivery_method      TEXT    NOT NULL,   -- 'urn:ietf:rfc:8935' (push) | 'urn:ietf:rfc:8936' (poll)
  endpoint_url         TEXT    NOT NULL,   -- receiver's push URL, or this registry's poll URL
  authorization_header TEXT,               -- push only; never returned
  events_requested     TEXT    NOT NULL DEFAULT '[]',  -- JSON array of event-type URIs
  events_delivered     TEXT    NOT NULL DEFAULT '[]',  -- requested ∩ supported
  description          TEXT,
  status               TEXT    NOT NULL DEFAULT 'enabled' CHECK (status IN ('enabled', 'paused', 'disabled')),
  status_reason        TEXT,
  created_at           INTEGER NOT NULL,
  updated_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssf_streams_owner ON ssf_streams (owner_key_hash);

CREATE TABLE IF NOT EXISTS ssf_outbox (
  stream_id       TEXT    NOT NULL,
  jti             TEXT    NOT NULL,
  event_type      TEXT    NOT NULL,
  set_jwt         TEXT    NOT NULL,   -- the signed SET, compact JWS
  subject_dids    TEXT    NOT NULL DEFAULT '[]',  -- DIDs the SET discloses; visibility re-checked before each delivery
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  delivered_at    INTEGER,            -- push: receiver answered 202; poll: receiver acknowledged
  failed_at       INTEGER,            -- push: retries exhausted
  last_error      TEXT,
  PRIMARY KEY (stream_id, jti)
);
CREATE INDEX IF NOT EXISTS idx_ssf_outbox_pending ON ssf_outbox (delivered_at, failed_at, next_attempt_at);

-- WHY — agent_records.audited_at / audit_reference
--
-- The agent certification tier (agent-tier.ts) is derived only from facts the
-- registry can check: a verified domain, a KEL rooted in a person controller,
-- and — the one fact it cannot check itself — an independent audit, which an
-- operator records through POST /v1/agents/:didHash/audited (admin secret,
-- written to the admin audit log). NULL means "no audit recorded".
ALTER TABLE agent_records ADD COLUMN audited_at INTEGER;
ALTER TABLE agent_records ADD COLUMN audit_reference TEXT;
