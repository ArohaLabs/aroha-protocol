// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Manifest builders for the common entity kinds — agent, mcp, skill.
 *
 * generateDID() (see identity/did.ts) returns identity material and stops
 * there: DID, keys, DID document. Everything past that — what a manifest for
 * an agent/mcp/skill looks like, what "capability" and "trustLevel" mean —
 * previously had to be invented from scratch by every implementer, even
 * though arohaManifest/arohaProtocolVersion versioning implies the shape is
 * meant to be somewhat standard across implementations. These builders are
 * that shared shape, optional to use: nothing elsewhere in this package
 * requires a manifest built this way, and `validateManifest` accepts any
 * object satisfying the shape regardless of how it was constructed.
 */

export type ManifestKind = "agent" | "mcp" | "skill";
export type CapabilityTrustLevel = "low" | "medium" | "high";
export type Visibility = "public" | "unlisted" | "private";
export type DeployTarget = "local" | "hosted";

export interface Capability {
  id: string;
  name: string;
  description?: string;
  trustLevel?: CapabilityTrustLevel;
}

export interface ManifestBase {
  did: string;
  arohaProtocolVersion: string;
  version: string;
  kind: ManifestKind;
  name: string;
  description: string;
  visibility: Visibility;
  published: boolean;
  deployTarget: DeployTarget;
  createdAt: string;
}

export interface AgentManifest extends ManifestBase {
  kind: "agent";
  capabilities: Capability[];
  model?: string;
  trigger?: string;
  /**
   * Settlement rail identifiers this agent accepts (design spec §8.1) —
   * e.g. "stripe", "usdc-base", "ap2", "quota", "api-key". Mirrors
   * SignedCapabilityManifest.settlementRails (messages/types.ts) for
   * consumers that only have the simpler AgentManifest, and SAR's
   * settlementRails for federated discovery. Absent or empty means "not
   * yet advertised", not "accepts nothing" — see matchSettlementRail in
   * @aroha-sdk/orchestrator for how that's treated during negotiation.
   */
  settlementRails?: string[];
  extra?: Record<string, unknown>;
}

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpManifest extends ManifestBase {
  kind: "mcp";
  endpoint: string | null;
  auth: { type: string };
  tools: McpTool[];
  extra?: Record<string, unknown>;
}

export interface SkillManifest extends ManifestBase {
  kind: "skill";
  skillType: string;
  instructions: string;
  endpoint: string | null;
  extra?: Record<string, unknown>;
}

export interface BuildManifestOptions {
  name: string;
  description?: string;
  /** Defaults to "private" — deliberately not "public", so publishing is opt-in per manifest, not the default. */
  visibility?: Visibility;
  /** Defaults to false. */
  published?: boolean;
  /** Defaults to "local". */
  deployTarget?: DeployTarget;
  arohaProtocolVersion?: string;
  version?: string;
  createdAt?: string;
}

function buildBase(did: string, kind: ManifestKind, opts: BuildManifestOptions): ManifestBase {
  return {
    did,
    arohaProtocolVersion: opts.arohaProtocolVersion ?? "1.0",
    version: opts.version ?? "1.0",
    kind,
    name: opts.name,
    description: opts.description ?? "",
    visibility: opts.visibility ?? "private",
    published: opts.published ?? false,
    deployTarget: opts.deployTarget ?? "local",
    createdAt: opts.createdAt ?? new Date().toISOString(),
  };
}

export function buildAgentManifest(
  did: string,
  opts: BuildManifestOptions & { capabilities?: Capability[]; model?: string; trigger?: string; settlementRails?: string[]; extra?: Record<string, unknown> },
): AgentManifest {
  return {
    ...buildBase(did, "agent", opts),
    kind: "agent",
    capabilities: opts.capabilities ?? [],
    model: opts.model,
    trigger: opts.trigger,
    settlementRails: opts.settlementRails,
    extra: opts.extra,
  };
}

export function buildMcpManifest(
  did: string,
  opts: BuildManifestOptions & { endpoint?: string | null; tools?: McpTool[]; authType?: string; extra?: Record<string, unknown> },
): McpManifest {
  return {
    ...buildBase(did, "mcp", opts),
    kind: "mcp",
    endpoint: opts.endpoint ?? null,
    auth: { type: opts.authType ?? "none" },
    tools: opts.tools ?? [],
    extra: opts.extra,
  };
}

export function buildSkillManifest(
  did: string,
  opts: BuildManifestOptions & { skillType?: string; instructions?: string; endpoint?: string | null; extra?: Record<string, unknown> },
): SkillManifest {
  return {
    ...buildBase(did, "skill", opts),
    kind: "skill",
    skillType: opts.skillType ?? "custom",
    instructions: opts.instructions ?? "",
    endpoint: opts.endpoint ?? null,
    extra: opts.extra,
  };
}

export interface ManifestValidationResult {
  ok: boolean;
  /** Empty when ok is true. */
  errors: string[];
}

/**
 * Structural check against ManifestBase plus each kind's required fields —
 * not a full JSON-Schema validator, just enough to catch the mistakes that
 * are easy to make hand-building a manifest without this module (missing
 * `did`, a `kind` that isn't one of the three, `published: true` with
 * `visibility: "private"` — a combination that's almost always a bug, not
 * an intentional choice).
 */
export function validateManifest(manifest: unknown): ManifestValidationResult {
  const errors: string[] = [];
  if (typeof manifest !== "object" || manifest === null) {
    return { ok: false, errors: ["manifest must be an object"] };
  }
  const m = manifest as Record<string, unknown>;

  if (typeof m.did !== "string" || !m.did.startsWith("did:aroha:")) {
    errors.push("did must be a string starting with 'did:aroha:'");
  }
  if (m.kind !== "agent" && m.kind !== "mcp" && m.kind !== "skill") {
    errors.push('kind must be "agent", "mcp", or "skill"');
  }
  if (typeof m.name !== "string" || m.name.length === 0) {
    errors.push("name must be a non-empty string");
  }
  if (m.visibility !== "public" && m.visibility !== "unlisted" && m.visibility !== "private") {
    errors.push('visibility must be "public", "unlisted", or "private"');
  }
  if (typeof m.published !== "boolean") {
    errors.push("published must be a boolean");
  }
  if (m.published === true && m.visibility === "private") {
    errors.push('published:true with visibility:"private" is contradictory — a private manifest should not be published');
  }
  if (m.deployTarget !== "local" && m.deployTarget !== "hosted") {
    errors.push('deployTarget must be "local" or "hosted"');
  }

  if (m.kind === "agent" && !Array.isArray(m.capabilities)) {
    errors.push("agent manifest must have a capabilities array");
  }
  if (m.kind === "mcp" && !Array.isArray(m.tools)) {
    errors.push("mcp manifest must have a tools array");
  }
  if (m.kind === "skill" && typeof m.skillType !== "string") {
    errors.push("skill manifest must have a skillType string");
  }

  return { ok: errors.length === 0, errors };
}
