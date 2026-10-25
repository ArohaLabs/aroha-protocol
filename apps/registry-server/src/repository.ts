// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * RegistryRepository — the adapter contract that enables zero-downtime migration.
 *
 * Today: D1Repository (Cloudflare D1 / SQLite) — free tier, zero ops.
 * Future: PostgresRepository (Neon / Supabase / Railway) — swap when you need
 *         full-text search, advanced analytics, or higher write throughput.
 *
 * Migration checklist (zero downtime):
 *   1. Implement PostgresRepository satisfying this interface
 *   2. Export D1: `wrangler d1 export aroha-registry --output=dump.sql`
 *   3. Import to Postgres: `pgloader dump.sql postgres://...`
 *   4. Serve the registry from a custom domain you control (today it is the
 *      workers.dev host, which has no DNS to flip) and set its TTL to 60 s
 *      (do this 24 h early)
 *   5. Deploy new server pointing at Postgres
 *   6. Flip CNAME — clients reconnect within 60 s, no data loss
 *
 * Nothing outside this file should import D1 types.
 */

export interface AgentRow {
  didHash: string;
  did: string;
  ownerKeyHash: string;
  /** Display name of the org that registered this agent (from api_keys.org_name) */
  orgName: string;
  manifestCID: string;
  publicKeyB64: string;
  /** Stored as string — SQLite has no native bigint; always "0" until staking ships */
  stakedWei: string;
  reputationScore: number;
  active: boolean;
  registeredAt: number;   // Unix ms
  lastUpdatedAt: number;  // Unix ms
  /** Where the agent is hosted — callers POST {message,sessionId} to {endpointUrl}/v1/run */
  endpointUrl?: string;
  /** Populated by queries that JOIN capability_index; undefined when not fetched */
  capabilityIds?: string[];
  /** Increments on every key rotation. Receivers can detect stale cached public keys. */
  keyVersion: number;
  /** Unix ms of the most recent key rotation; null if the key has never been rotated. */
  keyRotatedAt: number | null;
  /** Trust tier: 'community' → 'domain' → 'org-signed' in ascending strength. */
  verificationTier: 'community' | 'domain' | 'org-signed';
  /** Domain proven via /.well-known/aroha-did.json, or null. */
  domain: string | null;
  /** True once .well-known check passed. */
  domainVerified: boolean;
  /** Unix ms before which this agent is invisible in public discovery. null = immediately eligible. */
  discoveryEligibleAt: number | null;
  /** Base64 Ed25519 org signature over the canonical registration payload, or null. */
  orgSignature: string | null;
  /**
   * Discovery visibility:
   *   'public'   — listed in discovery (default)
   *   'unlisted' — never listed; resolvable by didHash if you know it
   *   'private'  — owner + explicit access grants only
   */
  visibility: Visibility;
  /**
   * E-DID agents with a controller: the person DID their verified inception
   * names (migration 015). Null/absent for every other agent. Revoking that
   * person deactivates this row — see RegistryRepository.deactivateAgentsControlledBy.
   */
  controllerDid?: string | null;
  /**
   * Why the row was taken down, when it was by the registry rather than its
   * owner ('controller-revoked', 'controller-sealed-ahead'); null otherwise.
   * Read-only here — insertAgent never writes it.
   */
  deactivatedReason?: string | null;
}

/**
 * Why the KEL path deactivated an agent row (agent_records.deactivated_reason).
 *
 *   kel-revoked              the agent's own log ends in a revoke — permanent
 *   controller-revoked       the controlling person revoked ITSELF — permanent
 *   controller-sealed-ahead  the controller sealed an agent event the registry
 *                            has not seen; the stored key is superseded whatever
 *                            that event is. Lifted when the agent's log arrives
 *                            and is not revoked (it was a recovery or rotation).
 */
export type KelDeactivationReason = "kel-revoked" | "controller-revoked" | "controller-sealed-ahead";

export type Visibility = "public" | "unlisted" | "private";
export type ResourceType = "agent" | "mcp" | "skill";

/** One access grant: the owner of a resource permitting a specific grantee. */
export interface AccessGrantRow {
  id: number;
  resourceDidHash: string;
  resourceType: ResourceType;
  /** Agent DID the grant is for — used at call time and DID-scoped discovery. */
  granteeDid: string | null;
  /** API key hash the grant is for — used at discovery time. */
  granteeKeyHash: string | null;
  /** Capability IDs covered; null = all of the resource's capabilities. */
  capabilities: string[] | null;
  grantedByKeyHash: string;
  note: string | null;
  expiresAt: number | null;
  createdAt: number;
  revokedAt: number | null;
}

export interface CreateGrantInput {
  resourceDidHash: string;
  resourceType: ResourceType;
  granteeDid?: string | null;
  granteeKeyHash?: string | null;
  capabilities?: string[] | null;
  note?: string | null;
  expiresAt?: number | null;
}

export interface RevokedKeyRow {
  publicKeyB64: string;
  keyVersion: number;
  rotatedAt: number;
}

export interface McpRow {
  didHash: string;
  did: string;
  ownerKeyHash: string;
  orgName: string;
  name: string;
  description: string;
  endpointUrl: string;
  toolIds: string[];
  manifestCID: string;
  active: boolean;
  registeredAt: number;
  lastUpdatedAt: number;
  visibility: Visibility;
}

export interface SkillRow {
  didHash: string;
  did: string;
  ownerKeyHash: string;
  orgName: string;
  name: string;
  description: string;
  skillType: string;
  endpointUrl: string;
  manifestCID: string;
  active: boolean;
  registeredAt: number;
  lastUpdatedAt: number;
  visibility: Visibility;
}

export interface DiscoveryStats {
  /** Total discovery events recorded for this agent (all time). */
  total: number;
  /** Discovery events in the last 7 days. */
  last7d: number;
  /** Discovery events in the last 30 days. */
  last30d: number;
}

export interface AnalyticsSummary {
  activeAgents: number;
  /** Agents with reputation ≥ 7000 and registered ≥ 7 days ago. */
  verifiedAgents: number;
  /** All analytics events in the last 7 days. */
  totalEvents7d: number;
  /** Agent registrations in the last 7 days. */
  registrations7d: number;
}

export interface RoutingSignalRow {
  modelId:          string;
  taskType:         string;
  complexityBucket: number;   // 0–9
  quality:          number;   // 0–1
  tokenCount:       number;
  apiKeyHash:       string;
}

export interface RoutingPriorRow {
  modelId:          string;
  taskType:         string;
  complexityBucket: number;
  alpha:            number;   // sum of quality observations + prior
  beta:             number;   // sum of (1-quality) observations + prior
  observations:     number;
}

export interface KycIssuerRow {
  issuerDid:    string;
  publicKeyB64: string;
  domain:       string;
  registeredAt: number;
  revokedAt:    number | null;
}

export interface VerifiedCallerRow {
  nullifier:  string;
  scope:      string;
  commitment: string;
  issuerDid:  string;
  callerDid:  string;
  verifiedAt: number;
  revokedAt:  number | null;
}

export interface CallerAttestationRow {
  id:            number;
  sagaId:        string;
  agentDidHash:  string;
  callerDid:     string;
  success:       boolean;
  domain:        string;
  callerWeight:  number;
  submittedAt:   number;
}

export interface FirmLicenseRow {
  firmDid:       string;
  publicKeyHex:  string;
  name:          string;
  licensedAt:    number;
  revokedAt:     number | null;
}

export interface SubdomainClaimRow {
  subdomain:      string;
  firmDid:        string;
  target:         string;
  hostname:       string;
  createdAt:      number;
  updatedAt:      number;
  /** design spec §9.6 dispute path — set by putSubdomainDispute, never cleared automatically. */
  disputedAt:     number | null;
  disputeReason:  string | null;
}

export interface SarRow {
  did: string;
  capabilities: string[];
  transports: string[];
  settlementRails: string[];
  terms: Record<string, unknown>;
  issuedAt: number;
  ttl: number;
  signature: string;
  storedAt: number;
}

export interface AuditLogRow {
  id:        number;
  action:    string;
  actor:     string;
  target:    string | null;
  ip:        string | null;
  createdAt: number;
}

export interface ModelCatalogRow {
  modelId:              string;
  provider:             string;   // "anthropic" | "openai" | "google"
  tier:                 number;   // 1=nano … 5=frontier
  inputPricePerMtok:    number;   // USD per million input tokens
  outputPricePerMtok:   number;   // USD per million output tokens
  contextWindow:        number;   // max tokens
  avgLatencyMs:         number;
  qualityReasoning:     number;
  qualityCode:          number;
  qualityExtraction:    number;
  qualityCreative:      number;
  qualityClassification: number;
  qualitySummarization: number;
  active:               boolean;
  updatedAt:            number;   // Unix ms
}


// ─── Spaces ───────────────────────────────────────────────────────────────
//
// A named place a firm shares work into. Everything a space grants is written
// as an ordinary row in access_grants tagged `via_space_id`, so there remains
// exactly one table answering "may this caller reach this resource" — see
// migrations/012_spaces.sql for why that matters more than the storage it costs.

export interface SpaceRow {
  id: string;
  name: string;
  description: string | null;
  ownerKeyHash: string;
  ownerOrg: string;
  createdAt: number;
  archivedAt: number | null;
}

export interface SpaceMemberRow {
  spaceId: string;
  memberKeyHash: string;
  memberOrg: string;
  invitedBy: string;
  createdAt: number;
  removedAt: number | null;
}

export interface SpaceResourceRow {
  spaceId: string;
  resourceDidHash: string;
  resourceType: ResourceType;
  addedBy: string;
  createdAt: number;
  removedAt: number | null;
}

export interface SpaceInviteRow {
  id: string;
  spaceId: string;
  createdBy: string;
  note: string | null;
  expiresAt: number | null;
  createdAt: number;
  redeemedBy: string | null;
  redeemedAt: number | null;
  revokedAt: number | null;
}

export interface RegistryRepository {
  // ── Agents ──────────────────────────────────────────────────────────────────

  /** Insert a new agent and index its capabilities atomically. */
  insertAgent(row: AgentRow, capabilityIds: string[]): Promise<void>;

  /** Look up an active agent by its keccak256(did) hash. Returns null if not found or inactive. */
  getAgent(didHash: string): Promise<AgentRow | null>;

  /** Look up an agent by its keccak256(did) hash, including deactivated records. */
  getAgentAny(didHash: string): Promise<AgentRow | null>;

  /**
   * Deactivate an agent.
   * Only succeeds when ownerKeyHash matches the key used at registration.
   * Returns true if a row was updated, false if not found / wrong owner.
   */
  deactivateAgent(didHash: string, ownerKeyHash: string): Promise<boolean>;

  /**
   * Admin-delegated deactivation — checks org_name instead of ownerKeyHash.
   * Only called by the Next.js server (using ADMIN_SECRET) on behalf of authenticated users.
   */
  deactivateAgentByOrgName(didHash: string, orgName: string): Promise<boolean>;

  /**
   * Replace the manifest CID and re-index capabilities.
   * Only succeeds when ownerKeyHash matches.
   * Returns true if updated, false if not found / wrong owner.
   */
  updateManifest(
    didHash: string,
    manifestCID: string,
    capabilityIds: string[],
    ownerKeyHash: string,
  ): Promise<boolean>;

  /**
   * Admin-delegated manifest update — checks org_name instead of ownerKeyHash.
   * Only called by the Next.js server (using ADMIN_SECRET) on behalf of authenticated users.
   */
  updateManifestByOrgName(
    didHash: string,
    manifestCID: string,
    capabilityIds: string[],
    orgName: string,
  ): Promise<boolean>;

  /**
   * Return all active agents that expose ALL of the requested capability IDs.
   * Empty array if capabilityIds is empty.
   */
  /**
   * Discover by capability.
   * @param viewerKeyHash SHA-256 of the caller's API key, or null when
   *   unauthenticated. Public records are always returned; the viewer
   *   additionally sees records they own or hold a live grant for.
   */
  queryByCapability(capabilityIds: string[], viewerKeyHash?: string | null): Promise<AgentRow[]>;

  /** Paginated list of all active agents, newest first. */
  listAgents(limit: number, offset: number, viewerKeyHash?: string | null): Promise<AgentRow[]>;

  /**
   * Merge an external quality signal into an agent's reputationScore using an
   * exponential moving average: score = α * newScore + (1−α) * existingScore.
   * α defaults to 0.1 (10% weight per signal batch).
   * Returns the updated score, or null if the agent was not found.
   */
  updateReputationScore(didHash: string, signalScore: number, alpha?: number): Promise<number | null>;

  // ── MCPs ────────────────────────────────────────────────────────────────────
  insertMcp(row: McpRow): Promise<void>;
  getMcp(didHash: string): Promise<McpRow | null>;
  listMcps(limit: number, offset: number, viewerKeyHash?: string | null): Promise<McpRow[]>;
  deactivateMcpByOrgName(didHash: string, orgName: string): Promise<boolean>;

  // ── Skills ───────────────────────────────────────────────────────────────────
  insertSkill(row: SkillRow): Promise<void>;
  getSkill(didHash: string): Promise<SkillRow | null>;
  listSkills(limit: number, offset: number, skillType?: string, viewerKeyHash?: string | null): Promise<SkillRow[]>;
  deactivateSkillByOrgName(didHash: string, orgName: string): Promise<boolean>;

  // ── Key rotation ─────────────────────────────────────────────────────────────

  /**
   * Rotate the agent's Ed25519 public key.
   *
   * Caller is responsible for verifying the Ed25519 signature of the rotation
   * message BEFORE calling this method. The repository only updates DB state.
   *
   * Steps performed atomically (D1 batch):
   *   1. Archive the current public key into revoked_keys
   *   2. Update agent_records: new public key, bumped key_version, key_rotated_at
   *
   * Returns the new key_version on success, or null if the agent was not found
   * or is inactive.
   */
  /**
   * Archive the current key and install `newPublicKeyB64`, but only if the
   * row is still at `expectedVersion` — the version the caller verified the
   * rotation signature against. Returns "conflict" when a concurrent
   * rotation got there first, null when the agent is missing or inactive.
   */
  rotateKey(
    didHash: string,
    newPublicKeyB64: string,
    expectedVersion: number,
  ): Promise<{ keyVersion: number } | "conflict" | null>;

  /** List all previously revoked public keys for forensic / auditing purposes. */
  getRevokedKeys(didHash: string): Promise<RevokedKeyRow[]>;

  /**
   * Atomically consume a rotation nonce (INSERT OR IGNORE).
   *
   * Returns true  — nonce was unused; proceed with the key rotation.
   * Returns false — nonce already exists; reject as a replay attack.
   *
   * expiresAt is the Unix ms timestamp at which the nonce becomes irrelevant
   * (issuedAt + 5 minutes). Rows past this timestamp are pruned by
   * pruneExpiredRotationNonces().
   */
  consumeRotationNonce(nonce: string, didHash: string, expiresAt: number): Promise<boolean>;

  /** Delete expired rotation nonces. Call fire-and-forget after each rotation. */
  pruneExpiredRotationNonces(): Promise<void>;

  /**
   * Upgrade an agent's verification tier to 'domain' after a successful .well-known check.
   * Only the ownerKeyHash can promote their own agent.
   * Returns true if a row was updated.
   */
  setVerificationTier(
    didHash: string,
    ownerKeyHash: string,
    tier: 'community' | 'domain' | 'org-signed',
    domain: string,
  ): Promise<boolean>;

  // ── API keys ─────────────────────────────────────────────────────────────────

  /** Persist SHA-256(rawKey) with display name and stable provider owner ID. */
  // ─── Visibility & access grants ────────────────────────────────────────────

  /**
   * Set a resource's discovery visibility. Scoped to the owner: returns false
   * if the resource doesn't exist or ownerKeyHash isn't its owner.
   */
  setVisibility(
    didHash: string,
    resourceType: ResourceType,
    visibility: Visibility,
    ownerKeyHash: string,
  ): Promise<boolean>;

  /**
   * Create an access grant. Returns null when the caller doesn't own the
   * resource. Re-granting a previously revoked (resource, grantee) pair works
   * because the uniqueness indexes exclude revoked rows.
   */
  createGrant(input: CreateGrantInput, ownerKeyHash: string): Promise<AccessGrantRow | null>;

  /** Revoke a grant (soft delete). Owner-scoped; false if not found or not owner. */
  revokeGrant(id: number, ownerKeyHash: string): Promise<boolean>;

  /** List live grants on a resource. Owner-scoped; empty array if not the owner. */
  listGrants(resourceDidHash: string, ownerKeyHash: string): Promise<AccessGrantRow[]>;

  /**
   * Resolve a resource's owner key hash *if* it belongs to `orgName`.
   *
   * Studio-created resources are registered with a short-lived org key the web
   * app doesn't retain, so admin-delegated routes prove ownership by org name
   * instead. This maps that proof back onto the normal owner-scoped methods
   * rather than duplicating each one. Returns null when the org doesn't match.
   */
  getOwnerKeyHashForOrg(
    didHash: string,
    resourceType: ResourceType,
    orgName: string,
  ): Promise<string | null>;

  /**
   * Is there a live (unrevoked, unexpired) grant on this resource for the
   * given grantee? Used for private resolve-by-didHash and agent-side checks.
   */
  hasGrant(
    resourceDidHash: string,
    grantee: { did?: string | null; keyHash?: string | null },
  ): Promise<boolean>;

  insertKey(keyHash: string, orgName: string, ownerId: string, label?: string | null): Promise<void>;

  /** Look up a key by its hash. Returns null if not found or inactive. */
  getKey(keyHash: string): Promise<{ orgName: string; active: boolean; orgPublicKeyB64: string | null } | null>;

  /**
   * Register (or replace) the org's Ed25519 signing public key.
   * Only succeeds when keyHash matches an active key.
   * Returns true if the row was updated.
   */
  setOrgKey(keyHash: string, orgPublicKeyB64: string, domain: string): Promise<boolean>;

  /** List all active keys belonging to a stable provider owner ID. */
  listKeysByOwner(ownerId: string): Promise<{ keyHash: string; createdAt: number; label: string | null }[]>;

  /**
   * Deactivate a key by hash.
   * Only succeeds when the key's owner_id matches — prevents cross-user revocation.
   */
  revokeKey(targetHash: string, ownerId: string): Promise<boolean>;

  // ── Analytics ─────────────────────────────────────────────────────────────────

  /** Fire-and-forget event recording. Callers should not await. */
  recordEvent(eventType: string, didHash: string | null): Promise<void>;

  /** Per-agent discovery counts for the analytics dashboard. */
  getAgentDiscoveryStats(didHash: string): Promise<DiscoveryStats>;

  /** Admin-level platform-wide summary. */
  getAnalyticsSummary(): Promise<AnalyticsSummary>;

  // ── Model catalog ──────────────────────────────────────────────────────────

  /** Return all active models, optionally filtered by provider. */
  getModelCatalog(provider?: string): Promise<ModelCatalogRow[]>;

  /** Admin: upsert a model profile (creates or updates by model_id). */
  upsertModel(row: ModelCatalogRow): Promise<void>;

  // ── Routing signals ────────────────────────────────────────────────────────

  /** Record a batch of quality signals from the routing SDK. */
  recordRoutingSignals(signals: RoutingSignalRow[]): Promise<void>;

  /**
   * Return aggregated Beta(α,β) parameters per (model_id, task_type, complexity_bucket).
   * α = sum(quality) + 1 (Jeffreys prior), β = sum(1-quality) + 1.
   */
  getRoutingPriors(modelId?: string): Promise<RoutingPriorRow[]>;

  /**
   * Check + increment rate limit for signal submissions.
   * Returns true if the caller is within the limit (max `limit` per 24h window).
   */
  checkAndIncrementSignalRate(keyHash: string, didHash: string, limit: number): Promise<boolean>;

  // ── Admin audit log ────────────────────────────────────────────────────────

  /** Append an audit entry. Call fire-and-forget. */
  recordAuditAction(action: string, actor: string, target?: string, ip?: string): Promise<void>;

  /** List recent audit entries, newest first. */
  listAuditLog(limit: number, offset: number): Promise<AuditLogRow[]>;

  // ── Caller uniqueness (Sybil-resistant reputation) ────────────────────────

  /** Register a KYC issuer's signing key. Fails if issuerDid is already registered. */
  insertKycIssuer(issuerDid: string, publicKeyB64: string, domain: string): Promise<boolean>;

  /** Look up an issuer by DID. Returns null if unknown or revoked. */
  getKycIssuer(issuerDid: string): Promise<KycIssuerRow | null>;

  /**
   * Record a verified-caller nullifier, binding it to a caller DID.
   * Returns false if this exact nullifier already has a live row — the
   * actual Sybil-resistance enforcement: the same certified secret cannot
   * be registered twice for the same scope.
   */
  insertVerifiedCallerNullifier(row: Omit<VerifiedCallerRow, "revokedAt">): Promise<boolean>;

  /** True if callerDid has a live (non-revoked) verified-caller nullifier. */
  isCallerVerified(callerDid: string): Promise<boolean>;

  /**
   * Record a caller-signed attestation about a specific interaction.
   * Returns false if this (sagaId, callerDid) pair was already submitted.
   */
  insertCallerAttestation(row: Omit<CallerAttestationRow, "id">): Promise<boolean>;

  /** List attestations for an agent, most recent first — for feeding a reputation engine. */
  listCallerAttestations(agentDidHash: string, domain: string, limit: number): Promise<CallerAttestationRow[]>;

  // ── Vanity subdomain provisioning ──────────────────────────────────────────

  /**
   * License (or re-license) a firm to provision a vanity subdomain. Admin-only
   * — this is the actual access control the provisioning route enforces; a
   * valid signature alone proves key possession, not that the DID is a paying
   * customer. Un-revokes the firm if it was previously revoked.
   */
  upsertFirmLicense(firmDid: string, publicKeyHex: string, name?: string): Promise<void>;

  /** Revoke a firm's license. Returns true if a live license was found and revoked. */
  revokeFirmLicense(firmDid: string): Promise<boolean>;

  /** Look up a firm's live (non-revoked) license. Returns null if unlicensed or revoked. */
  getFirmLicense(firmDid: string): Promise<FirmLicenseRow | null>;

  /** Look up a claim by subdomain — whoever holds this row is the current owner of it. */
  getSubdomainClaim(subdomain: string): Promise<SubdomainClaimRow | null>;

  /** Look up the (at most one) subdomain a firm currently holds. */
  getSubdomainClaimByFirm(firmDid: string): Promise<SubdomainClaimRow | null>;

  /**
   * Create a claim, or update its target if the same firm re-provisions the
   * same subdomain (e.g. after a laptop reinstall picks a new tunnel id).
   * Caller is responsible for the collision/ownership checks beforehand —
   * this only persists the outcome.
   */
  putSubdomainClaim(row: Omit<SubdomainClaimRow, "createdAt" | "updatedAt" | "disputedAt" | "disputeReason">): Promise<void>;

  /**
   * Flag an existing subdomain claim as disputed (design spec §9.6). Caller
   * has already verified the disputing party's domain-ownership proof — this
   * only persists the outcome. A no-op (returns false) if the subdomain has
   * no claim to dispute.
   */
  putSubdomainDispute(subdomain: string, reason: string): Promise<boolean>;

  // ── Signed Agent Record index (M5 — federated discovery) ───────────────────

  /** Store (or replace) the latest SAR for a DID. Caller has already verified the signature. */
  upsertSar(row: SarRow): Promise<void>;

  /** All non-expired SARs, optionally filtered to those declaring a given capability. */
  /** Live records, oldest-stored first; `limit` / `offset` page through them when given. */
  /**
   * Record a relay-connect proof (by SHA-256 of its signature) as used until
   * `expiresAt`. True the first time; false if the same proof was already
   * accepted — a replay inside the freshness window (migration 017).
   */
  consumeRelayConnectProof(signatureHash: string, didHash: string, expiresAt: number): Promise<boolean>;

  querySar(opts: { capability?: string; did?: string; now: number; limit?: number; offset?: number }): Promise<SarRow[]>;

  // ── Registration ownership challenges (M6 — publish & claim) ───────────────

  /** Issue a challenge nonce, tied to the requesting key so it can't be redeemed by another. */
  createRegistrationChallenge(nonce: string, did: string, keyHash: string, expiresAt: number): Promise<void>;

  /**
   * Atomically consume a challenge: returns it if it existed, matched
   * (did, keyHash), and had not expired — deleting it in the same operation
   * so it can never be redeemed twice. Returns null otherwise (no
   * distinction made between "never existed", "wrong owner", and "expired"
   * — the caller treats all three as "proof rejected").
   */
  consumeRegistrationChallenge(nonce: string, did: string, keyHash: string, now: number): Promise<boolean>;

  // ── Personal agent names (M7 — key-derived naming, spec §7.10) ─────────────

  /**
   * Mint a personal-name index entry. The label's validity was already
   * proven by the caller recomputing it from the DID's own committed public
   * key (see @aroha-sdk/registry/personal-name) — this table is a lookup cache for routing,
   * not a source of trust, so re-minting the same (label, didHash) pair is
   * idempotent. Returns false only when the label is already bound to a
   * *different* DID (a scrypt collision, astronomically unlikely, but the
   * contract must still say what happens).
   */
  mintPersonalName(row: { label: string; didHash: string; did: string; ownerKeyHash: string; mintedAt: number }): Promise<boolean>;

  /**
   * Resolve a personal label to its DID for routing — the label was already
   * format-checked by the caller. Null while the agent's row is inactive
   * (deactivated by its owner, or by its KEL / its controller's revocation).
   */
  lookupPersonalName(label: string): Promise<{ did: string } | null>;

  // ── Relay connect tokens (M10 — relay broker, spec §6.3) ────────────────────

  /** Issue a one-time token proving the caller signed a fresh relay-connect challenge for didHash. */
  createRelayConnectToken(token: string, didHash: string, expiresAt: number): Promise<void>;

  /** Atomically consume a relay connect token — same single-use/TTL semantics as consumeRegistrationChallenge. */
  consumeRelayConnectToken(token: string, didHash: string, now: number): Promise<boolean>;

  // ─── Spaces ─────────────────────────────────────────────────────────────

  createSpace(input: {
    id: string; name: string; description: string | null;
    ownerKeyHash: string; ownerOrg: string;
  }): Promise<SpaceRow>;
  getSpace(id: string): Promise<SpaceRow | null>;
  listSpacesOwnedBy(keyHash: string): Promise<SpaceRow[]>;
  listSpacesJoinedBy(keyHash: string): Promise<SpaceRow[]>;
  isSpaceMember(spaceId: string, keyHash: string): Promise<boolean>;
  listSpaceMembers(spaceId: string): Promise<SpaceMemberRow[]>;
  listSpaceResources(spaceId: string): Promise<SpaceResourceRow[]>;

  createSpaceInvite(input: {
    id: string; spaceId: string; codeHash: string;
    createdBy: string; note: string | null; expiresAt: number | null;
  }): Promise<SpaceInviteRow>;
  /** By hash only — the raw code is never stored, so it cannot be looked up. */
  findSpaceInviteByCodeHash(codeHash: string): Promise<(SpaceInviteRow & { spaceId: string }) | null>;

  /**
   * Redeem an invitation: add the member and grant it everything already
   * shared into the space. Returns how many grants that produced, which is
   * what makes the effect of joining visible rather than implied.
   */
  joinSpace(input: {
    spaceId: string; inviteId: string; memberKeyHash: string;
    memberOrg: string; invitedBy: string;
  }): Promise<{ grantsCreated: number } | null>;

  /** Share a resource in, granting it to every current member. */
  addSpaceResource(input: {
    spaceId: string; resourceDidHash: string; resourceType: ResourceType; addedBy: string;
  }): Promise<{ grantsCreated: number }>;

  removeSpaceResource(spaceId: string, resourceDidHash: string): Promise<{ removed: boolean; grantsRevoked: number }>;
  removeSpaceMember(spaceId: string, memberKeyHash: string): Promise<{ removed: boolean; grantsRevoked: number }>;
  archiveSpace(spaceId: string): Promise<{ grantsRevoked: number }>;

  /** Does this key own this resource? Already used by the grants route. */
  ownsResource(didHash: string, type: ResourceType, keyHash: string): Promise<boolean>;

  // ── Key Event Logs for rotatable did:aroha:E… identities (migration 014) ───
  //
  // The repository stores logs and evidence as opaque JSON. It never decides
  // whether a log is valid — that is @aroha-sdk/core's verifyKel/acceptKel,
  // called through kel-store.ts BEFORE anything reaches these methods. Keeping
  // the protocol types out of this interface keeps a future Postgres adapter
  // a pure storage exercise.

  /** The longest verified log stored for `did`, or null. */
  getKelLog(did: string): Promise<KelLogRow | null>;

  /**
   * Store `events` for `did` only if it is LONGER than what is stored (or
   * nothing is). Returns false when a log of equal or greater length was
   * already there — the caller (kel-store.ts) then re-reads and compares, so
   * two concurrent submissions of different same-length logs surface as
   * duplicity instead of a silent last-writer-wins.
   */
  putKelLogIfLonger(row: KelLogRow): Promise<boolean>;

  /** Record duplicity evidence. The FIRST record per DID is kept (later ones are ignored). */
  recordKelDuplicity(did: string, evidence: unknown, recordedAt: number): Promise<void>;

  getKelDuplicity(did: string): Promise<unknown | null>;

  /**
   * First-wins insert of a verified linkage. Returns the row that is stored
   * after the call — the caller's own when it was the first, otherwise the
   * earlier one, which is never overwritten.
   */
  insertIdentityLinkage(row: IdentityLinkageRow): Promise<{ inserted: boolean; stored: IdentityLinkageRow }>;

  /** File a verified linkage whose `to` differs from the stored one, for a human to resolve. */
  recordIdentityLinkageConflict(fromDid: string, linkage: unknown, recordedAt: number): Promise<void>;

  getIdentityLinkage(fromDid: string): Promise<(IdentityLinkageRow & { conflictCount: number }) | null>;

  /**
   * Make a registered E-DID agent's row follow its KEL: current key, key
   * version (= number of key-establishing events), controller (filled in when
   * the row lacks it), and deactivation once the log is revoked — by itself
   * (`revoked`) or because its controller revoked itself
   * (`controllerRevoked`). The superseded key is archived in revoked_keys
   * exactly as a registry rotation archives one.
   *
   * A row the KEL path took down as 'controller-sealed-ahead' is brought back
   * when the log is NOT revoked: the sealed event was a recovery or rotation,
   * the row now carries the key it installed. No other inactive row is ever
   * reactivated here. Returns false if no row exists or nothing changed.
   */
  applyKelKeyState(
    didHash: string,
    state: {
      publicKeyB64: string | null;
      keyVersion: number;
      revoked: boolean;
      controllerRevoked: boolean;
      controllerDid: string | null;
    },
  ): Promise<boolean>;

  /**
   * The controller-revocation cascade: deactivate every ACTIVE agent row whose
   * controller is `controllerDid` ('controller-revoked', final key archived).
   * Matches on controller_did, and — for rows the migration-015 backfill
   * missed — on the controller named by the row's stored, verified KEL
   * inception (filling controller_did in as it goes). Returns the didHashes
   * deactivated.
   */
  deactivateAgentsControlledBy(controllerDid: string): Promise<string[]>;

  /**
   * Take an ACTIVE agent row down as 'controller-sealed-ahead' (current key
   * archived): its controller has sealed an event of the agent's log beyond
   * what the registry holds, so the row's key is no longer the agent's current
   * key. The caller (kel-store.ts) has already checked that the seal comes
   * from the controller the agent's own inception names. Returns true if a
   * row was deactivated.
   */
  suspendAgentPendingControllerEvent(didHash: string): Promise<boolean>;
}

export interface KelLogRow {
  did: string;
  /** The verified events, in sequence order. Opaque to the repository. */
  events: unknown[];
  /** Sequence number of the last event (events.length - 1). */
  sequence: number;
  lastDigest: string;
  updatedAt: number;
}

export interface IdentityLinkageRow {
  fromDid: string;
  toDid: string;
  /** The signed IdentityLinkage, verbatim. */
  linkage: unknown;
  createdAt: number;
}
