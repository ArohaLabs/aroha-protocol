-- Copyright (c) 2026 Aroha Labs
-- SPDX-License-Identifier: Apache-2.0
--
-- Spaces — a named place a firm shares work into, and the firms it shares with.
--
-- WHY, GIVEN access_grants ALREADY EXISTS
--
-- A grant answers "may this grantee reach this resource". It is the right
-- primitive and nothing here replaces it. What it cannot do is scale to how
-- people actually work: sharing eight agents with five partner firms is forty
-- grants to create and forty to remember when somebody leaves. A space is the
-- grouping over that — share into it once, invite a firm once.
--
-- SPACES MATERIALISE GRANTS RATHER THAN BECOMING A SECOND KIND OF PERMISSION
--
-- Adding a resource to a space, or a member to it, writes ordinary rows into
-- access_grants tagged with `via_space_id`. Everything downstream — discovery
-- filtering, /v1/grants/check, the agent-side allowedCallers check — keeps
-- working unchanged and keeps agreeing, because there is still exactly one
-- table that answers "may this caller reach this resource".
--
-- The alternative was joining spaces at query time. It stores less and it
-- creates a second path to the same answer, which is precisely where access
-- control goes wrong: two checks that must agree, and one of them forgotten
-- on the call-time path where an agent decides whether to answer a stranger.
--
-- The cost is fan-out: N resources by M members. Bounded by both being small
-- in the case this exists for, and every row carries via_space_id so removing
-- a member revokes exactly what that membership created and nothing a person
-- granted by hand.

CREATE TABLE IF NOT EXISTS spaces (
  id              TEXT    PRIMARY KEY,   -- opaque; generated server-side
  name            TEXT    NOT NULL,
  -- The org that owns it, by API key hash. Only this key may invite, add
  -- resources, or archive.
  owner_key_hash  TEXT    NOT NULL,
  owner_org       TEXT    NOT NULL,      -- denormalised for display
  description     TEXT,
  created_at      INTEGER NOT NULL,
  archived_at     INTEGER                -- soft delete, so grants can be traced
);

CREATE INDEX IF NOT EXISTS idx_space_owner ON spaces (owner_key_hash, archived_at);

-- Who is in it. One row per member org.
CREATE TABLE IF NOT EXISTS space_members (
  space_id        TEXT    NOT NULL,
  member_key_hash TEXT    NOT NULL,
  member_org      TEXT    NOT NULL,      -- denormalised for display
  invited_by      TEXT    NOT NULL,      -- key hash of whoever invited them
  created_at      INTEGER NOT NULL,
  removed_at      INTEGER,               -- soft delete
  PRIMARY KEY (space_id, member_key_hash)
);

CREATE INDEX IF NOT EXISTS idx_space_member ON space_members (member_key_hash, removed_at);

-- What has been shared into it.
CREATE TABLE IF NOT EXISTS space_resources (
  space_id          TEXT    NOT NULL,
  resource_did_hash TEXT    NOT NULL,
  resource_type     TEXT    NOT NULL,    -- 'agent' | 'mcp' | 'skill'
  added_by          TEXT    NOT NULL,
  created_at        INTEGER NOT NULL,
  removed_at        INTEGER,
  PRIMARY KEY (space_id, resource_did_hash)
);

CREATE INDEX IF NOT EXISTS idx_space_resource ON space_resources (space_id, removed_at);

-- HOW A FIRM INVITES A FIRM IT CANNOT NAME
--
-- Membership is keyed by API key hash, and one org has no way to learn
-- another's — it is a secret's digest, not an address. So an invitation is a
-- one-time CODE: the owner creates one, sends it however they already talk,
-- and the other firm redeems it with their own key. The redeeming key becomes
-- the member, which means nobody ever has to hold or transmit anything
-- identifying about the other side's credentials.
--
-- Only the code's hash is stored. A registry that can read back its own
-- invitation codes is a registry whose database leak grants space access.
CREATE TABLE IF NOT EXISTS space_invites (
  id              TEXT    PRIMARY KEY,
  space_id        TEXT    NOT NULL,
  code_hash       TEXT    NOT NULL UNIQUE,
  created_by      TEXT    NOT NULL,
  note            TEXT,                  -- e.g. "for Meridian's CFO"
  expires_at      INTEGER,               -- Unix ms; NULL = no expiry
  created_at      INTEGER NOT NULL,
  redeemed_by     TEXT,                  -- member key hash, once used
  redeemed_at     INTEGER,
  revoked_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_space_invite_space ON space_invites (space_id, revoked_at);

-- Which membership produced a grant, so removing one revokes exactly the
-- grants it created and leaves anything granted by hand alone.
ALTER TABLE access_grants ADD COLUMN via_space_id TEXT;

CREATE INDEX IF NOT EXISTS idx_grant_space ON access_grants (via_space_id, revoked_at);
