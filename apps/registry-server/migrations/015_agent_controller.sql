-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 015: an E-DID agent's controller on its registry row, so that
-- revoking a PERSON deactivates every agent that person controls.
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- WHY THE ROW NEEDS THE CONTROLLER
--
-- A controlled E-DID agent acts for the person its inception names: its
-- authority comes from that person, and the person can recover or revoke it
-- by anchoring a seal in the PERSON's log (see @aroha-sdk/core kel.ts and
-- src/kel-store.ts). Before this migration a registered agent was only
-- deactivated when its OWN log, ending in a revoke, was posted. Two cases
-- slipped through:
--   1. The person revokes ITSELF. Every one of their agents is now acting for
--      an abandoned principal, but no agent log changed, so nothing touched
--      the agent rows — they stayed discoverable with live keys.
--   2. The person anchors a revoke (or recovery) of one agent and only the
--      person's log reaches the registry. GET /v1/kel already refused to serve
--      the agent's now-stale log; the agent ROW still advertised the dead key.
-- Fixing both needs "which active rows does this person control" as a query,
-- hence controller_did (indexed). It is copied from the agent's own verified,
-- hash-committed inception — never from a request — so a person can only ever
-- reach agents that named them at birth.
--
-- deactivated_reason says WHY the KEL path took a row down, because one of
-- those reasons is temporary: 'controller-sealed-ahead' means the controller
-- has sealed an agent event the registry has not seen yet (the stored key is
-- superseded either way — every agent event after inception replaces or kills
-- the key). If that event turns out to be a recovery, the row comes back with
-- the new key when the agent's log arrives; the permanent reasons
-- ('kel-revoked', 'controller-revoked') never lift on their own. NULL for
-- every row taken down any other way (owner/admin deactivation), which the
-- KEL path never reverses.

ALTER TABLE agent_records ADD COLUMN controller_did TEXT;
ALTER TABLE agent_records ADD COLUMN deactivated_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_agent_controller ON agent_records (controller_did);

-- Backfill from the stored logs. Every registered E-DID agent had its log
-- accepted at registration (the route requires it), and kel_logs only ever
-- holds logs that verified, so event 0 is a genuine, hash-committed
-- inception. Rows with no stored log (z-DIDs, named DIDs) have no
-- controller and stay NULL. kel-store.ts also fills the column lazily on the
-- next accepted log, for any row this misses.
UPDATE agent_records
SET controller_did = (
  SELECT json_extract(k.events_json, '$[0].controller')
  FROM kel_logs k
  WHERE k.did = agent_records.did
    AND json_extract(k.events_json, '$[0].type') = 'inception'
)
WHERE controller_did IS NULL
  AND did IN (SELECT did FROM kel_logs);

-- Agents whose controller had ALREADY revoked itself before this migration:
-- take them down now rather than waiting for the next log to arrive. Their
-- final keys are archived first, exactly as kel-store.ts does at runtime, so
-- GET /v1/agents/:didHash/revoked-keys lists them.
-- Idempotent on replay: revoked_keys is keyed by an AUTOINCREMENT id, so
-- OR IGNORE alone could never detect a duplicate. The NOT EXISTS guard is
-- what does — a re-run after a partial apply (archive done, deactivation
-- not) must not archive the same (did_hash, key_version) twice.
INSERT OR IGNORE INTO revoked_keys (did_hash, public_key_b64, key_version, rotated_at)
SELECT a.did_hash, a.public_key_b64, a.key_version, CAST(strftime('%s', 'now') AS INTEGER) * 1000
FROM agent_records a
WHERE a.active = 1
  AND a.controller_did IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM revoked_keys r
    WHERE r.did_hash = a.did_hash AND r.key_version = a.key_version
  )
  AND EXISTS (
    SELECT 1 FROM kel_logs p, json_each(p.events_json) e
    WHERE p.did = a.controller_did AND json_extract(e.value, '$.type') = 'revoke'
  );

UPDATE agent_records
SET active = 0,
    deactivated_reason = 'controller-revoked',
    last_updated_at = CAST(strftime('%s', 'now') AS INTEGER) * 1000
WHERE active = 1
  AND controller_did IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM kel_logs p, json_each(p.events_json) e
    WHERE p.did = agent_records.controller_did AND json_extract(e.value, '$.type') = 'revoke'
  );
