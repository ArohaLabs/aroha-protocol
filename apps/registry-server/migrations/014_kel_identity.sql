-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Migration 014: Key Event Logs for rotatable did:aroha:E… identities, and
-- linkages from legacy DIDs to them.
--
-- Run against production D1:
--   node scripts/migrate.mjs --remote
--
-- WHY THE REGISTRY STORES LOGS IT CANNOT FORGE
--
-- An E-DID commits to its inception event, and every later key change is a
-- hash-chained, self-authenticating event (see @aroha-sdk/core kel.ts). A
-- registry serving such a log cannot substitute a
-- key — but it CAN serve an old prefix, which hides a rotation or a
-- revocation. What it can usefully do is be a durable "longest log seen"
-- memory: kel_logs keeps the longest VERIFIED log per DID, and kel_duplicity
-- records the first proof that somebody forked one. A DID with a duplicity
-- row is refused from then on; nothing ever deletes that row automatically,
-- because a fork means a key was used against its owner and a human has to
-- look.
--
-- events_json is the whole log, not one row per event: logs are short, are
-- always verified as a unit (verifyKel replays from the inception), and a
-- per-event table would invite partial reads that skip the chain check.
-- sequence and last_digest are denormalised from the log so "is this
-- submission longer than what we hold" and freshness checks do not have to
-- parse JSON.

CREATE TABLE IF NOT EXISTS kel_logs (
  did         TEXT    PRIMARY KEY,
  events_json TEXT    NOT NULL,
  sequence    INTEGER NOT NULL,
  last_digest TEXT    NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- One row per DID: the FIRST evidence wins (INSERT OR IGNORE), matching the
-- core InMemoryKelStore. Later evidence for an already-alarmed DID adds
-- nothing — the DID is refused either way.
CREATE TABLE IF NOT EXISTS kel_duplicity (
  did           TEXT    PRIMARY KEY,
  evidence_json TEXT    NOT NULL,
  recorded_at   INTEGER NOT NULL
);

-- Linkages from a legacy DID (z-form or named) to its E-DID successor.
-- from_did is the PRIMARY KEY because the first linkage per `from` wins and
-- is never overwritten: a z-DID IS its key, so whoever stole that key can
-- sign a linkage to an E-DID of their own. The registry cannot tell which
-- of two validly-signed linkages is the owner's, so it keeps the first and
-- files any different later one in identity_linkage_conflicts for a human,
-- rather than silently following whichever arrived last.
CREATE TABLE IF NOT EXISTS identity_linkages (
  from_did     TEXT    PRIMARY KEY,
  to_did       TEXT    NOT NULL,
  linkage_json TEXT    NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_linkage_to ON identity_linkages (to_did);

CREATE TABLE IF NOT EXISTS identity_linkage_conflicts (
  from_did     TEXT    NOT NULL,
  linkage_json TEXT    NOT NULL,
  recorded_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_identity_linkage_conflict_from ON identity_linkage_conflicts (from_did);
