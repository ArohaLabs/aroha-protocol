-- Aroha Registry — D1 (SQLite) schema
--
-- Migration path to Postgres is a straight copy: every statement here is
-- valid ANSI SQL. The only SQLite-isms are:
--   • INTEGER PRIMARY KEY AUTOINCREMENT  →  SERIAL PRIMARY KEY  (only in api_keys)
--   • active INTEGER (0/1 booleans)      →  active BOOLEAN       (rename the type)
--   • staked_wei TEXT                    →  staked_wei NUMERIC   (optional, currently always '0')
--
-- To export for migration: wrangler d1 export aroha-registry --output=dump.sql
-- To import to Postgres:   pgloader dump.sql postgres://...

-- ─── Agents ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS agent_records (
  -- keccak256(did) — matches what ArohaHttpRegistry client sends in URL paths
  did_hash         TEXT    PRIMARY KEY,
  did              TEXT    NOT NULL UNIQUE,
  -- SHA-256 of the API key used to register — enforces ownership on writes
  owner_key_hash   TEXT    NOT NULL,
  -- Display name of the publishing org (from api_keys.org_name at registration time)
  org_name         TEXT    NOT NULL DEFAULT '',
  manifest_cid     TEXT    NOT NULL,
  public_key_b64   TEXT    NOT NULL,
  -- Stored as text: bigint doesn't exist in SQLite; always '0' until staking is wired
  staked_wei       TEXT    NOT NULL DEFAULT '0',
  -- 0–10000 scale matching BayesianReputationEngine output
  reputation_score INTEGER NOT NULL DEFAULT 5000,
  -- SQLite boolean (0/1); Postgres migration: change to BOOLEAN
  active           INTEGER NOT NULL DEFAULT 1,
  registered_at    INTEGER NOT NULL,  -- Unix ms
  last_updated_at  INTEGER NOT NULL,  -- Unix ms
  endpoint_url     TEXT,
  -- Increments on every key rotation; allows mandate verifiers to detect stale
  -- cached public keys without a full registry round-trip.
  key_version      INTEGER NOT NULL DEFAULT 1,
  -- Unix ms of the most recent rotation. Mandate tokens whose issuedAt precedes
  -- this value were signed with a revoked key and must be rejected.
  key_rotated_at   INTEGER,            -- NULL = never rotated
  -- ── migration 001: verification tiers and discovery cooldown ──
  -- 'community' (default) | 'domain' (.well-known check) | 'org-signed'
  verification_tier     TEXT    NOT NULL DEFAULT 'community',
  domain                TEXT,   -- verified via /.well-known/aroha-did.json
  domain_verified       INTEGER NOT NULL DEFAULT 0,
  -- Withheld from public discovery until this Unix ms. NULL = eligible now.
  discovery_eligible_at INTEGER,
  -- ── migration 002: org signing ──
  -- Base64 Ed25519 signature by the org over the canonical registration payload.
  org_signature         TEXT,
  -- ── migration 003: visibility ──
  -- 'public' (discoverable) | 'unlisted' (resolvable by didHash only)
  -- | 'private' (owner + explicit grants only). See access_grants.
  visibility       TEXT    NOT NULL DEFAULT 'public',
  -- ── migration 015: controller cascade ──
  -- E-DID agents only: the person DID the agent's verified inception names as
  -- controller (copied from the hash-committed log, never from a request).
  -- Revoking that person deactivates every row carrying it.
  controller_did   TEXT,
  -- Why the KEL path deactivated this row: 'kel-revoked' | 'controller-revoked'
  -- (permanent) | 'controller-sealed-ahead' (lifted if the sealed event turns
  -- out to be a recovery). NULL for active rows and owner/admin deactivation.
  deactivated_reason TEXT,
  -- ── migration 019: operator-recorded independent audit ──
  -- Set only by POST /v1/agents/:didHash/audited (admin secret). Feeds the
  -- 'audited' certification tier (agent-tier.ts). NULL = no audit recorded.
  audited_at       INTEGER,
  audit_reference  TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_controller   ON agent_records (controller_did);
CREATE INDEX IF NOT EXISTS idx_agent_active       ON agent_records (active);
CREATE INDEX IF NOT EXISTS idx_agent_registered   ON agent_records (registered_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_owner        ON agent_records (owner_key_hash);
CREATE INDEX IF NOT EXISTS idx_agent_discovery_eligible ON agent_records (discovery_eligible_at);
CREATE INDEX IF NOT EXISTS idx_agent_verification_tier  ON agent_records (verification_tier);
-- migration 003 — was in the migration but missing here, so a database
-- bootstrapped from this file lacked it (schema-drift.test.ts now compares
-- indexes as well as columns).
CREATE INDEX IF NOT EXISTS idx_agent_visibility ON agent_records (visibility);

-- ─── Capability index ─────────────────────────────────────────────────────────
-- Extracted from the IPFS manifest at registration time.
-- Enables GET /v1/agents?capabilities=a,b,c without fetching IPFS on every query.

CREATE TABLE IF NOT EXISTS capability_index (
  capability_id  TEXT NOT NULL,
  did_hash       TEXT NOT NULL,
  PRIMARY KEY (capability_id, did_hash),
  FOREIGN KEY (did_hash) REFERENCES agent_records (did_hash) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cap_id ON capability_index (capability_id);

-- ─── MCP servers ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mcp_records (
  did_hash        TEXT    PRIMARY KEY,
  did             TEXT    NOT NULL UNIQUE,
  owner_key_hash  TEXT    NOT NULL,
  org_name        TEXT    NOT NULL DEFAULT '',
  name            TEXT    NOT NULL,
  description     TEXT    NOT NULL DEFAULT '',
  endpoint_url    TEXT    NOT NULL,
  tool_ids        TEXT    NOT NULL DEFAULT '',   -- JSON array string
  manifest_cid    TEXT    NOT NULL DEFAULT '',
  active          INTEGER NOT NULL DEFAULT 1,
  registered_at   INTEGER NOT NULL,
  last_updated_at INTEGER NOT NULL,
  visibility      TEXT    NOT NULL DEFAULT 'public'
);
CREATE INDEX IF NOT EXISTS idx_mcp_active ON mcp_records (active);
CREATE INDEX IF NOT EXISTS idx_mcp_visibility ON mcp_records (visibility);
CREATE INDEX IF NOT EXISTS idx_mcp_owner  ON mcp_records (owner_key_hash);

-- ─── Skills ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS skill_records (
  did_hash        TEXT    PRIMARY KEY,
  did             TEXT    NOT NULL UNIQUE,
  owner_key_hash  TEXT    NOT NULL,
  org_name        TEXT    NOT NULL DEFAULT '',
  name            TEXT    NOT NULL,
  description     TEXT    NOT NULL DEFAULT '',
  skill_type      TEXT    NOT NULL DEFAULT 'custom',
  endpoint_url    TEXT    NOT NULL DEFAULT '',
  manifest_cid    TEXT    NOT NULL DEFAULT '',
  active          INTEGER NOT NULL DEFAULT 1,
  registered_at   INTEGER NOT NULL,
  last_updated_at INTEGER NOT NULL,
  visibility      TEXT    NOT NULL DEFAULT 'public'
);
CREATE INDEX IF NOT EXISTS idx_skill_active ON skill_records (active);
CREATE INDEX IF NOT EXISTS idx_skill_visibility ON skill_records (visibility);
CREATE INDEX IF NOT EXISTS idx_skill_type   ON skill_records (skill_type);
CREATE INDEX IF NOT EXISTS idx_skill_owner  ON skill_records (owner_key_hash);

-- ─── API keys ─────────────────────────────────────────────────────────────────
-- One key per org. SHA-256 of the raw key is stored — never the raw key itself.
-- Raw key is shown once at creation and never stored.

CREATE TABLE IF NOT EXISTS api_keys (
  key_hash    TEXT    PRIMARY KEY,  -- SHA-256(raw_key) hex
  org_name    TEXT    NOT NULL,     -- display name shown on agents (publishedBy)
  -- Stable provider identity: "github:12345678" or "google:109876543210"
  -- Used for key list/revoke scoping — never the mutable display name
  owner_id    TEXT    NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1,
  -- ── migration 001: org email-domain verification ──
  verified            INTEGER NOT NULL DEFAULT 0,
  verified_domain     TEXT,
  -- ── migration 002: org signing keypair ──
  -- Ed25519 public key (base64) the org signs agent registrations with,
  -- proven by hosting /.well-known/aroha-org.json at org_key_domain.
  org_public_key_b64  TEXT,
  org_key_domain      TEXT,
  org_key_verified_at INTEGER,
  -- ── migration 013: what this key is for ──
  -- Display only, supplied by whoever asked for the key (the desktop app
  -- sends its computer's name). Never used for scoping: owner_id alone
  -- decides whose key this is, so a label set to a lie is cosmetic.
  label               TEXT
);

-- ─── Key versioning ──────────────────────────────────────────────────────────
-- key_version and key_rotated_at are part of the CREATE TABLE above, and
-- migrations/004_baseline_reconcile.sql brings older databases forward.
--
-- This block used to say those ALTERs were "intentionally NOT in this file" and
-- had to be run by hand. Nobody ran them, so production lacked the columns and
-- six tables for months — invisibly, because no hot path touched them. Every
-- change now goes in a numbered migration and is applied by
-- scripts/migrate.mjs, which records what it has run in schema_migrations.

-- Audit log of every superseded public key. Never deleted — forensic record.
CREATE TABLE IF NOT EXISTS revoked_keys (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  did_hash       TEXT    NOT NULL,
  public_key_b64 TEXT    NOT NULL,  -- the key that was rotated OUT
  key_version    INTEGER NOT NULL,  -- which version this was before rotation
  rotated_at     INTEGER NOT NULL,  -- Unix ms
  FOREIGN KEY (did_hash) REFERENCES agent_records (did_hash) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_revoked_did ON revoked_keys (did_hash);

-- ─── Key-rotation nonce dedup ─────────────────────────────────────────────────
-- Every rotate-key request carries a UUID nonce. The server consumes the nonce
-- atomically (INSERT OR IGNORE) before committing the key swap. If a nonce is
-- replayed within its validity window, INSERT is a no-op (changes === 0) and
-- the server returns 409. This closes the replay window that the issuedAt
-- 5-minute guard alone cannot close.
--
-- Rows are pruned lazily: any rotate-key call deletes a batch of expired rows
-- as a fire-and-forget step so the table stays bounded without a cron job.

CREATE TABLE IF NOT EXISTS rotation_nonces (
  nonce      TEXT    PRIMARY KEY,
  did_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL  -- Unix ms; same as the request's issuedAt + 5 min
);
CREATE INDEX IF NOT EXISTS idx_nonce_expires ON rotation_nonces (expires_at);

-- ─── Spending ledger ──────────────────────────────────────────────────────────
-- Closes the double-allocation gap: an orchestrator holding a $500 mandate
-- cannot issue N children each claiming $500. Every attenuateToCart /
-- attenuateToPayment call deducts from the parent mandate's pool here.
--
-- Atomicity strategy (SQLite / D1):
--   UPDATE spending_budgets SET allocated_usd = allocated_usd + ?
--   WHERE mandate_id = ? AND allocated_usd + ? <= limit_usd
--
-- A single UPDATE is atomic in SQLite's serialised write model. meta.changes
-- tells us whether the budget had room (1) or was exhausted (0). No row lock
-- or transaction needed — the conditional WHERE is the guard.

CREATE TABLE IF NOT EXISTS spending_budgets (
  mandate_id      TEXT PRIMARY KEY,
  limit_usd       REAL NOT NULL CHECK (limit_usd > 0),
  -- Invariant: allocated_usd <= limit_usd, enforced by the conditional UPDATE.
  allocated_usd   REAL NOT NULL DEFAULT 0 CHECK (allocated_usd >= 0),
  -- SHA-256 of the API key that called POST /v1/spending/budgets.
  -- All allocate/release/status calls must present the same key — prevents
  -- any other API key holder from exhausting or reading a budget they don't own.
  owner_key_hash  TEXT NOT NULL DEFAULT '',
  -- Unix ms when this mandate expires. allocate() rejects after this timestamp.
  -- NULL = no expiry (for programmatic use without a known TTL).
  -- Set this to the mandate token's own expiresAt for automatic enforcement.
  expires_at      INTEGER,
  created_at      INTEGER NOT NULL,
  -- Migration 018. 'mandate': limit_usd / expires_at were derived from a
  -- verified mandate token and mandate_id holds `<grantor>#<mandateId>`.
  -- 'caller': a pre-018 row whose limit came from the request body — never
  -- served by the routes (routes/spending.ts).
  limit_source    TEXT NOT NULL DEFAULT 'caller',
  -- Migration 018. JSON array of `<grantor>#<mandateId>` for every link of
  -- the verified chain; allocate refuses once any of them is revoked here.
  chain_keys      TEXT
);
CREATE INDEX IF NOT EXISTS idx_budget_owner   ON spending_budgets (owner_key_hash);
CREATE INDEX IF NOT EXISTS idx_budget_expires ON spending_budgets (expires_at);

-- One row per issued child mandate. Released during saga compensation.
CREATE TABLE IF NOT EXISTS spending_allocations (
  allocation_id TEXT    PRIMARY KEY,   -- UUID returned to caller
  mandate_id    TEXT    NOT NULL,      -- FK to spending_budgets.mandate_id
  amount_usd    REAL    NOT NULL CHECK (amount_usd > 0),
  allocated_at  INTEGER NOT NULL,      -- Unix ms
  released_at   INTEGER,               -- NULL while active; set on release
  FOREIGN KEY (mandate_id) REFERENCES spending_budgets (mandate_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alloc_mandate ON spending_allocations (mandate_id);
-- Partial-style index for finding unreleased allocations efficiently
CREATE INDEX IF NOT EXISTS idx_alloc_active ON spending_allocations (mandate_id, released_at);

-- ─── Access grants ───────────────────────────────────────────────────────────
-- One row = "the owner of <resource> grants <grantee> access".
--
-- Two grantee forms, serving different layers:
--   grantee_did      — an agent DID. Used at CALL time (agent-side allow-list)
--                      and for DID-scoped discovery.
--   grantee_key_hash — an org API key hash. Used at DISCOVERY time, since
--                      registry callers authenticate with an API key.
-- At least one must be non-NULL (CHECK below).
--
-- capabilities: JSON array of capability IDs the grant covers; NULL = all.
-- Revocation is a soft delete so the audit trail survives.

CREATE TABLE IF NOT EXISTS access_grants (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  resource_did_hash   TEXT    NOT NULL,
  resource_type       TEXT    NOT NULL,  -- 'agent' | 'mcp' | 'skill'
  grantee_did         TEXT,
  grantee_key_hash    TEXT,
  capabilities        TEXT,              -- JSON array; NULL = all
  granted_by_key_hash TEXT    NOT NULL,  -- must equal the resource's owner_key_hash
  note                TEXT,              -- free-form label, e.g. "CI pipeline"
  expires_at          INTEGER,           -- Unix ms; NULL = no expiry
  created_at          INTEGER NOT NULL,
  revoked_at          INTEGER,
  -- Which space membership produced this grant, when one did. Lets a
  -- member's removal revoke exactly what the space gave them and leave a
  -- hand-written grant for the same pair alone. See migration 012.
  via_space_id        TEXT,
  CHECK (grantee_did IS NOT NULL OR grantee_key_hash IS NOT NULL)
);

-- One live grant per (resource, grantee); partial indexes exclude revoked rows
-- so a resource can be re-granted after revocation.
CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_unique_did
  ON access_grants (resource_did_hash, grantee_did)
  WHERE grantee_did IS NOT NULL AND revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_grant_unique_key
  ON access_grants (resource_did_hash, grantee_key_hash)
  WHERE grantee_key_hash IS NOT NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_grant_resource ON access_grants (resource_did_hash, revoked_at);
CREATE INDEX IF NOT EXISTS idx_grant_key      ON access_grants (grantee_key_hash, revoked_at);
CREATE INDEX IF NOT EXISTS idx_grant_did      ON access_grants (grantee_did, revoked_at);

-- ─── Analytics ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS analytics_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT    NOT NULL,
  did_hash   TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analytics_did_hash   ON analytics_events (did_hash);
CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_events (created_at);

-- ─── Model routing ────────────────────────────────────────────────────────────
-- Catalogue of models the router can select from, plus observed quality signals
-- fed back by callers. Quality dimensions are per task type so the router can
-- prefer a cheap model for extraction and an expensive one for reasoning.

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

-- Caps how many reputation signals one API key can file against one agent
-- per window — stops a single caller from manufacturing a reputation.
CREATE TABLE IF NOT EXISTS signal_rate_limits (
  key_hash     TEXT    NOT NULL,
  did_hash     TEXT    NOT NULL,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key_hash, did_hash, window_start)
);

-- ─── Admin audit ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  action     TEXT    NOT NULL,
  actor      TEXT    NOT NULL,
  target     TEXT,
  ip         TEXT,
  created_at INTEGER NOT NULL
);

-- ─── Migration bookkeeping ────────────────────────────────────────────────────
-- Records which files in migrations/ have been applied to THIS database.
--
-- This file is the complete current schema, so a database bootstrapped from it
-- already contains every migration's effect. `scripts/migrate.mjs` therefore
-- stamps all known migrations as applied immediately after a fresh bootstrap,
-- and only replays files against databases created before they existed.
--
-- Without this table there is no way to ask a live database which migrations it
-- has seen — which is exactly how production silently ran two migrations behind
-- until a deploy that read the new columns took the registry down.

CREATE TABLE IF NOT EXISTS schema_migrations (
  filename   TEXT    PRIMARY KEY,  -- e.g. '003_visibility_and_grants.sql'
  applied_at INTEGER NOT NULL      -- Unix ms
);

-- ─── Caller uniqueness (Sybil-resistant reputation) ───────────────────────────
-- See migrations/005_caller_uniqueness.sql for the full design rationale.

CREATE TABLE IF NOT EXISTS kyc_issuers (
  issuer_did      TEXT    PRIMARY KEY,
  public_key_b64  TEXT    NOT NULL,
  domain          TEXT    NOT NULL,
  registered_at   INTEGER NOT NULL,
  revoked_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_kyc_issuers_domain ON kyc_issuers (domain);

CREATE TABLE IF NOT EXISTS verified_caller_nullifiers (
  nullifier       TEXT    PRIMARY KEY,
  scope           TEXT    NOT NULL,
  commitment      TEXT    NOT NULL,
  issuer_did      TEXT    NOT NULL,
  caller_did      TEXT    NOT NULL,
  verified_at     INTEGER NOT NULL,
  revoked_at      INTEGER,
  FOREIGN KEY (issuer_did) REFERENCES kyc_issuers (issuer_did)
);
CREATE INDEX IF NOT EXISTS idx_nullifier_caller ON verified_caller_nullifiers (caller_did, revoked_at);

CREATE TABLE IF NOT EXISTS caller_attestations (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  saga_id         TEXT    NOT NULL,
  agent_did_hash  TEXT    NOT NULL,
  caller_did      TEXT    NOT NULL,
  success         INTEGER NOT NULL,
  domain          TEXT    NOT NULL DEFAULT 'general',
  caller_weight   REAL    NOT NULL,
  submitted_at    INTEGER NOT NULL,
  UNIQUE (saga_id, caller_did)
);
CREATE INDEX IF NOT EXISTS idx_attestations_agent ON caller_attestations (agent_did_hash, domain);

-- ─── Vanity subdomain provisioning ─────────────────────────────────────────────
-- See migrations/006_vanity_subdomains.sql for the full design rationale.

CREATE TABLE IF NOT EXISTS firm_licenses (
  firm_did        TEXT    PRIMARY KEY,
  public_key_hex  TEXT    NOT NULL,
  name            TEXT    NOT NULL DEFAULT '',
  licensed_at     INTEGER NOT NULL,
  revoked_at      INTEGER
);

CREATE TABLE IF NOT EXISTS subdomain_claims (
  subdomain      TEXT    PRIMARY KEY,
  firm_did       TEXT    NOT NULL,
  target         TEXT    NOT NULL,
  hostname       TEXT    NOT NULL,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  -- design spec §9.6 dispute path: a brand-domain owner who proves control
  -- of the matching real domain (.well-known/aroha-firm-claim.json) can
  -- flag an already-provisioned subdomain as disputed. Set by
  -- POST /v1/provision-subdomain/dispute, never cleared automatically —
  -- resolution (re-allocate, or confirm no conflict) is an operator
  -- decision, not something this endpoint unilaterally acts on.
  disputed_at    INTEGER,
  dispute_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_subdomain_claims_firm ON subdomain_claims (firm_did);

-- ─── Signed Agent Record index (M5 — federated discovery) ───────────────────
-- This registry is deliberately "one index among many, not the index"
-- (design spec §7.4): any Aroha implementation can run one of these, and a
-- client is expected to query several. One row per DID — a republish
-- replaces the prior record, matching a real index's job of holding the
-- latest self-attested state, not a history. Signature verification happens
-- in the route (@aroha-sdk/registry/sar) before a row is ever written; this table
-- only stores what already passed that check.

CREATE TABLE IF NOT EXISTS sar_records (
  did              TEXT    PRIMARY KEY,
  capabilities     TEXT    NOT NULL,  -- JSON array
  transports       TEXT    NOT NULL,  -- JSON array
  settlement_rails TEXT    NOT NULL,  -- JSON array
  terms            TEXT    NOT NULL,  -- JSON object
  issued_at        INTEGER NOT NULL,
  ttl              INTEGER NOT NULL,
  signature        TEXT    NOT NULL,
  stored_at        INTEGER NOT NULL
);

-- ─── Registration ownership challenges (M6 — publish & claim) ───────────────
-- Proves a registrant actually holds the private key for the DID they are
-- registering, closing a real gap: without this, holding a valid API key
-- was sufficient to register ANY did+publicKeyB64 pair, including one you
-- don't control the key for. A challenge is single-use (deleted on
-- successful verification) and short-lived — issued by POST
-- /v1/agents/challenge, consumed by POST /v1/agents' optional
-- challengeNonce/challengeSignature fields. Tying key_hash into the row (not
-- just did) means a challenge issued to one API key cannot be redeemed by a
-- different one that happens to intercept the nonce.

CREATE TABLE IF NOT EXISTS registration_challenges (
  nonce      TEXT    PRIMARY KEY,
  did        TEXT    NOT NULL,
  key_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reg_challenge_expires ON registration_challenges (expires_at);

-- ─── Personal agent names (M7 — key-derived naming, spec §7.10) ─────────────
-- A label (6 hyphen-separated wordlist tokens, e.g.
-- "otter-brass-canyon-vivid-ledger-amber") derived purely from an agent's
-- own Ed25519 public key — see @aroha-sdk/registry/personal-name. This table is a lookup
-- cache for the Worker's Host-header router, NOT a trust boundary: any
-- client can independently recompute derivePersonalLabel(publicKey) from
-- the DID and confirm the label unassisted, so a compromised or stale row
-- here can misroute a request but can never forge a false identity claim.
-- did_hash is UNIQUE because the derivation is a pure function of the
-- key — a given DID has exactly one valid label, ever.

CREATE TABLE IF NOT EXISTS personal_names (
  label          TEXT    PRIMARY KEY,
  did_hash       TEXT    NOT NULL UNIQUE,
  did            TEXT    NOT NULL,
  owner_key_hash TEXT    NOT NULL,
  minted_at      INTEGER NOT NULL
);

-- ─── Relay connect tokens (M10 — relay broker, spec §6.3) ───────────────────
-- Proves the caller opening a WebSocket to an agent's Durable Object relay
-- actually holds that agent's private key — otherwise anyone could claim to
-- BE any agent simply by connecting to its relay endpoint. Single-use,
-- short-lived, same pattern as registration_challenges.

CREATE TABLE IF NOT EXISTS relay_connect_tokens (
  token      TEXT    PRIMARY KEY,
  did_hash   TEXT    NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relay_connect_expires ON relay_connect_tokens (expires_at);

-- Migration 017: each accepted relay-connect proof, by SHA-256 of its
-- signature, until its timestamp leaves the ±5 min window — so one signed
-- proof mints one token, not one per replay. Pruned by the scheduled job.
CREATE TABLE IF NOT EXISTS relay_connect_proofs (
  signature_hash TEXT    PRIMARY KEY,
  did_hash       TEXT    NOT NULL,
  expires_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_relay_connect_proofs_expires ON relay_connect_proofs (expires_at);

-- Spaces (migration 012). A named place a firm shares work into; every
-- membership materialises ordinary access_grants rows tagged via_space_id.
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

CREATE INDEX IF NOT EXISTS idx_grant_space ON access_grants (via_space_id, revoked_at);

-- ─── Key Event Logs for rotatable did:aroha:E… identities (migration 014) ───
-- The registry is one durable "longest verified log seen" memory per DID —
-- it can withhold events but never forge one, because every log is replayed
-- through @aroha-sdk/core's verifyKel/acceptKel before it is stored. See
-- migrations/014_kel_identity.sql for the full rationale.

CREATE TABLE IF NOT EXISTS kel_logs (
  did         TEXT    PRIMARY KEY,
  events_json TEXT    NOT NULL,
  sequence    INTEGER NOT NULL,
  last_digest TEXT    NOT NULL,
  updated_at  INTEGER NOT NULL
);

-- First evidence of a forked log wins; the DID is refused from then on.
CREATE TABLE IF NOT EXISTS kel_duplicity (
  did           TEXT    PRIMARY KEY,
  evidence_json TEXT    NOT NULL,
  recorded_at   INTEGER NOT NULL
);

-- Legacy DID → E-DID successor. First linkage per from_did wins and is never
-- overwritten; a different later one goes to identity_linkage_conflicts.
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

-- ─── Spending-mandate revocations and shared redemption (migration 016) ───
-- See migrations/016_mandate_revocations_redemptions.sql and routes/mandates.ts.

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

-- Migration 017: keyed by (mandate_id, redemption_id). redemption_id is the
-- caller's idempotency handle; as the whole key it let one caller occupy an
-- id another mandate's payee later chose (a 500 after a verified chain).
CREATE TABLE IF NOT EXISTS mandate_redemptions (
  redemption_id TEXT    NOT NULL,
  mandate_id    TEXT    NOT NULL,
  amount_micros INTEGER NOT NULL CHECK (amount_micros > 0),
  merchant      TEXT    NOT NULL,
  redeemed_at   INTEGER NOT NULL,
  actor         TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (mandate_id, redemption_id)
);
CREATE INDEX IF NOT EXISTS idx_mandate_redemptions_mandate ON mandate_redemptions (mandate_id);

-- ─── Audit anchors (migration 018) ──────────────────────────────────────────
-- An external witness for runtime audit heads — see routes/audit-anchors.ts
-- and migrations/018_audit_anchors_and_verified_budgets.sql.
--
-- PERMANENT: not in the retention prune (src/retention.ts). An anchor is only
-- useful if it is still there when a log is checked, possibly years later;
-- pruning would recreate the undetectable-truncation gap anchors close.
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

-- ─── Shared Signals transmitter (migration 019) ─────────────────────────────
-- SSF streams and the durable SET outbox — see routes/ssf.ts, src/ssf.ts and
-- migrations/019_ssf_and_agent_audit.sql. Outbox rows are pruned 30 days
-- after creation (src/retention.ts).
CREATE TABLE IF NOT EXISTS ssf_streams (
  stream_id            TEXT    PRIMARY KEY,
  owner_key_hash       TEXT    NOT NULL,
  iss                  TEXT    NOT NULL,
  aud                  TEXT    NOT NULL,
  delivery_method      TEXT    NOT NULL,
  endpoint_url         TEXT    NOT NULL,
  authorization_header TEXT,
  events_requested     TEXT    NOT NULL DEFAULT '[]',
  events_delivered     TEXT    NOT NULL DEFAULT '[]',
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
  set_jwt         TEXT    NOT NULL,
  subject_dids    TEXT    NOT NULL DEFAULT '[]',
  created_at      INTEGER NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  delivered_at    INTEGER,
  failed_at       INTEGER,
  last_error      TEXT,
  PRIMARY KEY (stream_id, jti)
);
CREATE INDEX IF NOT EXISTS idx_ssf_outbox_pending ON ssf_outbox (delivered_at, failed_at, next_attempt_at);
