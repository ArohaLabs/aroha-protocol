// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Server configuration: a JSON file (AROHA_MCP_CONFIG) overlaid by
 * environment variables. Every field is documented in README.md; the file
 * shape is `ArohaMcpConfigFile` below.
 *
 * Fail-closed rules enforced here (not at first request):
 *   - HTTP mode needs an authorization server (`auth.issuer`) unless it is
 *     explicitly put in unauthenticated development mode AND bound to a
 *     loopback interface.
 *   - The governed verification profile needs a registry (KEL + revocation)
 *     and a pinned root.
 *   - A configured requestState key must be at least 32 bytes.
 *   - Enterprise-Managed Authorization needs an authorization server, and
 *     "required" mode needs at least one trusted identity provider.
 *   - Task limits must be positive and bounded.
 */

import { readFileSync } from "node:fs";
import { resolveRegistryUrl } from "@aroha-sdk/core/endpoints";
import type { RegistryStatusKey } from "@aroha-sdk/credentials/mandates";
import { defaultIdentityDir } from "./identity.js";
import { DEFAULT_ENTERPRISE_CLAIM, type TrustedIdp } from "./enterprise.js";

export type TransportMode = "stdio" | "http";

/** Tool names an approval policy can gate. */
export const GATEABLE_TOOLS = [
  "aroha_call",
  "aroha_issue_task_mandate",
  "aroha_issue_spending_mandate",
  "revoke_mandate",
] as const;

export interface ArohaMcpConfigFile {
  transport?: TransportMode;
  http?: {
    host?: string;
    port?: number;
    /** Canonical public URL of the MCP endpoint, e.g. https://mcp.example.com/mcp. */
    publicUrl?: string;
    /** Extra Host header names accepted (DNS-rebinding protection). */
    allowedHosts?: string[];
    /** Browser Origin host names accepted. */
    allowedOrigins?: string[];
    /** DEVELOPMENT ONLY: serve without OAuth. Refused unless bound to loopback. */
    allowUnauthenticated?: boolean;
    /** Request-body cap in bytes. Default 1 MiB. */
    maxBodyBytes?: number;
  };
  auth?: {
    /** Authorization server issuer identifier (exact string from its metadata). */
    issuer?: string;
    /** JWKS URL. Default: `jwks_uri` from the issuer's RFC 8414 / OIDC metadata. */
    jwksUrl?: string;
    /** Required `aud` value. Default: the canonical public URL. */
    audience?: string;
    /** Scopes every request needs. */
    requiredScopes?: string[];
    /** Scopes advertised in the protected-resource metadata. */
    scopesSupported?: string[];
    /** Accepted JWS algorithms. Default RS256, ES256, EdDSA. */
    algorithms?: string[];
    /** When set, only these OAuth client ids (CIMD URLs) are accepted. */
    allowedClientIds?: string[];
    /** Refuse client ids that are not Client ID Metadata Document URLs. */
    requireClientIdMetadataDocument?: boolean;
    /** Enterprise-Managed Authorization (ID-JAG). See enterprise.ts. */
    enterprise?: {
      /** Identity providers (ID-JAG `iss`, exact) whose users are accepted; optionally pinned to tenants. */
      trustedIdps?: Array<string | TrustedIdp>;
      /** Refuse access tokens that were not issued from an ID-JAG. */
      required?: boolean;
      /** Access-token claim carrying the ID-JAG provenance. Default "id_jag". */
      claim?: string;
    };
  };
  keys?: { dir?: string };
  approvals?: {
    /** Tools that need a human approval (MRTR input_required), or "none". */
    tools?: string[] | "none";
    /** HMAC key for requestState (≥ 32 bytes; hex, base64url or raw). */
    stateKey?: string;
    /** requestState lifetime in seconds. Default 600. */
    stateTtlSeconds?: number;
  };
  registry?: {
    url?: string;
    /** Registry signing keys for signed revocation status (pinned out of band). */
    keys?: RegistryStatusKey[];
  };
  governed?: {
    enabled?: boolean;
    expectedRoot?: string;
    trustedRoots?: string[];
  };
  /** Verify every agent response envelope in aroha_call. Default true. */
  verifyResponses?: boolean;
  /** DEVELOPMENT ONLY: let aroha_call reach private, loopback and link-local agent endpoints. */
  allowPrivateEndpoints?: boolean;
  /** MCP Tasks extension (io.modelcontextprotocol/tasks) for aroha_call. */
  tasks?: {
    /** Offer tasks to clients that declare the extension. Default true. */
    enabled?: boolean;
    /** Task lifetime from creation, seconds. Default 900. */
    ttlSeconds?: number;
    /** Tasks one user (and client) may hold at once. Default 32. */
    maxPerUser?: number;
    /** Tasks the process holds at once. Default 1000. */
    maxTotal?: number;
    /** Suggested polling interval, ms. Default 1000. */
    pollIntervalMs?: number;
  };
}

export interface ResolvedConfig {
  transport: TransportMode;
  http: {
    host: string;
    port: number;
    publicUrl: URL;
    path: string;
    allowedHosts: string[];
    allowedOrigins: string[];
    allowUnauthenticated: boolean;
    maxBodyBytes: number;
  };
  auth?: {
    issuer: string;
    jwksUrl?: string;
    audience: string;
    requiredScopes: string[];
    scopesSupported: string[];
    algorithms: string[];
    allowedClientIds?: string[];
    requireClientIdMetadataDocument: boolean;
    enterprise?: {
      trustedIdps: TrustedIdp[];
      required: boolean;
      claim: string;
    };
  };
  keysDir: string;
  approvals: {
    tools: Set<string>;
    stateKey?: Uint8Array;
    stateTtlSeconds: number;
  };
  registry: {
    url: string;
    apiKey: string;
    allowInsecureHttp: boolean;
    keys?: RegistryStatusKey[];
  };
  governed?: {
    expectedRoot?: string;
    trustedRoots?: string[];
  };
  verifyResponses: boolean;
  allowPrivateEndpoints: boolean;
  tasks?: {
    ttlMs: number;
    maxPerUser: number;
    maxTotal: number;
    pollIntervalMs: number;
  };
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK.has(host.replace(/^\[|\]$/g, "").toLowerCase());
}

function list(v: string | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  return v.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
}

function bool(v: string | undefined): boolean | undefined {
  if (v === undefined) return undefined;
  return v === "1" || v.toLowerCase() === "true";
}

/** Decode a secret given as hex, base64url or plain text. */
export function decodeSecret(s: string): Uint8Array {
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return new Uint8Array(Buffer.from(s, "hex"));
  if (/^[A-Za-z0-9_-]+={0,2}$/.test(s)) {
    const b = Buffer.from(s, "base64url");
    if (b.length >= 32) return new Uint8Array(b);
  }
  return new TextEncoder().encode(s);
}

function boundedInt(name: string, v: string | number | undefined, dflt: number, min: number, max: number): number {
  if (v === undefined) return dflt;
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer from ${min} to ${max}, got ${String(v)}`);
  return n;
}

function trustedIdps(env: string | undefined, file: Array<string | TrustedIdp> | undefined): TrustedIdp[] {
  const raw: Array<string | TrustedIdp> = list(env) ?? file ?? [];
  return raw.map((e) => {
    const idp = typeof e === "string" ? { issuer: e } : e;
    if (typeof idp?.issuer !== "string" || idp.issuer.length === 0) throw new Error("auth.enterprise.trustedIdps: every entry needs an issuer");
    if (idp.tenants !== undefined && (!Array.isArray(idp.tenants) || idp.tenants.length === 0 || idp.tenants.some((t) => typeof t !== "string" || t.length === 0))) {
      throw new Error(`auth.enterprise.trustedIdps: tenants for ${idp.issuer} must be a non-empty list of strings`);
    }
    return { issuer: idp.issuer, ...(idp.tenants ? { tenants: [...idp.tenants] } : {}) };
  });
}

function readConfigFile(path: string | undefined): ArohaMcpConfigFile {
  if (!path) return {};
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    throw new Error(`AROHA_MCP_CONFIG: cannot read ${path}: ${(err as Error).message}`);
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("not an object");
    return parsed as ArohaMcpConfigFile;
  } catch (err) {
    throw new Error(`AROHA_MCP_CONFIG: ${path} is not a JSON object: ${(err as Error).message}`);
  }
}

function parseRegistryKeys(v: string | undefined): RegistryStatusKey[] | undefined {
  if (v === undefined || v.trim() === "") return undefined;
  const text = v.trim().startsWith("[") || v.trim().startsWith("{") ? v : readFileSync(v, "utf8");
  const parsed = JSON.parse(text) as unknown;
  const keys = Array.isArray(parsed) ? parsed : (parsed as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) throw new Error("AROHA_MCP_REGISTRY_KEYS: expected a JSON array of keys or { keys: [...] }");
  return keys as RegistryStatusKey[];
}

/**
 * Resolve the configuration from a file (`AROHA_MCP_CONFIG` or `file`) and
 * the environment. Environment variables win over the file.
 */
export function loadConfig(
  env: NodeJS.ProcessEnv = process.env,
  overrides: { transport?: TransportMode; file?: ArohaMcpConfigFile } = {},
): ResolvedConfig {
  const file = overrides.file ?? readConfigFile(env.AROHA_MCP_CONFIG);
  const transport: TransportMode = overrides.transport
    ?? ((env.AROHA_MCP_TRANSPORT as TransportMode | undefined) ?? file.transport ?? "stdio");
  if (transport !== "stdio" && transport !== "http") {
    throw new Error(`AROHA_MCP_TRANSPORT must be "stdio" or "http", got "${String(transport)}"`);
  }

  const host = env.AROHA_MCP_HOST ?? file.http?.host ?? "127.0.0.1";
  const portRaw = env.AROHA_MCP_PORT ?? (file.http?.port !== undefined ? String(file.http.port) : undefined) ?? "8787";
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error(`AROHA_MCP_PORT: invalid port ${portRaw}`);
  const publicUrl = new URL(env.AROHA_MCP_PUBLIC_URL ?? file.http?.publicUrl ?? `http://${host.includes(":") ? `[${host}]` : host}:${port}/mcp`);
  if (publicUrl.hash) throw new Error("AROHA_MCP_PUBLIC_URL must not contain a fragment");
  const path = publicUrl.pathname.replace(/\/+$/, "") || "/";
  const allowUnauthenticated = bool(env.AROHA_MCP_ALLOW_UNAUTHENTICATED) ?? file.http?.allowUnauthenticated ?? false;

  const issuer = env.AROHA_MCP_AUTH_ISSUER ?? file.auth?.issuer;
  let auth: ResolvedConfig["auth"];
  if (issuer) {
    auth = {
      issuer,
      jwksUrl: env.AROHA_MCP_AUTH_JWKS_URL ?? file.auth?.jwksUrl,
      audience: env.AROHA_MCP_AUTH_AUDIENCE ?? file.auth?.audience ?? publicUrl.href.replace(/\/$/, ""),
      requiredScopes: list(env.AROHA_MCP_AUTH_SCOPES) ?? file.auth?.requiredScopes ?? [],
      scopesSupported: list(env.AROHA_MCP_AUTH_SCOPES_SUPPORTED) ?? file.auth?.scopesSupported
        ?? list(env.AROHA_MCP_AUTH_SCOPES) ?? file.auth?.requiredScopes ?? [],
      algorithms: list(env.AROHA_MCP_AUTH_ALGS) ?? file.auth?.algorithms ?? ["RS256", "ES256", "EdDSA"],
      allowedClientIds: list(env.AROHA_MCP_AUTH_ALLOWED_CLIENTS) ?? file.auth?.allowedClientIds,
      requireClientIdMetadataDocument: bool(env.AROHA_MCP_AUTH_REQUIRE_CIMD) ?? file.auth?.requireClientIdMetadataDocument ?? false,
    };
  }

  // Enterprise-Managed Authorization rides on the OAuth resource server: an
  // operator who turns it on without an authorization server gets an error,
  // not a server that silently accepts ordinary tokens.
  const idps = trustedIdps(env.AROHA_MCP_ENTERPRISE_IDPS, file.auth?.enterprise?.trustedIdps);
  const enterpriseRequired = bool(env.AROHA_MCP_ENTERPRISE_REQUIRED) ?? file.auth?.enterprise?.required ?? false;
  if (idps.length > 0 || enterpriseRequired) {
    if (!auth) throw new Error("Enterprise-Managed Authorization needs an authorization server: set AROHA_MCP_AUTH_ISSUER");
    if (enterpriseRequired && idps.length === 0) {
      throw new Error("AROHA_MCP_ENTERPRISE_REQUIRED needs at least one trusted identity provider (AROHA_MCP_ENTERPRISE_IDPS)");
    }
    const claim = env.AROHA_MCP_ENTERPRISE_CLAIM ?? file.auth?.enterprise?.claim ?? DEFAULT_ENTERPRISE_CLAIM;
    if (!/^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$/.test(claim) || ["iss", "sub", "aud", "exp", "nbf", "iat", "jti", "client_id", "azp", "scope"].includes(claim)) {
      throw new Error(`AROHA_MCP_ENTERPRISE_CLAIM: "${claim}" is not a usable claim name`);
    }
    auth.enterprise = { trustedIdps: idps, required: enterpriseRequired, claim };
  }

  if (transport === "http" && !auth) {
    if (!allowUnauthenticated) {
      throw new Error(
        "HTTP transport needs an authorization server: set AROHA_MCP_AUTH_ISSUER (and optionally " +
        "AROHA_MCP_AUTH_JWKS_URL). For local development only, AROHA_MCP_ALLOW_UNAUTHENTICATED=1 on a loopback host.",
      );
    }
    if (!isLoopbackHost(host)) {
      throw new Error("AROHA_MCP_ALLOW_UNAUTHENTICATED is refused on a non-loopback host; configure AROHA_MCP_AUTH_ISSUER");
    }
  }

  const toolsSetting = env.AROHA_MCP_APPROVAL_TOOLS !== undefined
    ? (env.AROHA_MCP_APPROVAL_TOOLS.trim() === "none" ? "none" : list(env.AROHA_MCP_APPROVAL_TOOLS))
    : file.approvals?.tools;
  // HTTP defaults to gating mandate issuance and spending calls; stdio keeps
  // its pre-existing behaviour (no prompts) unless configured.
  const defaultGated = transport === "http"
    ? ["aroha_call", "aroha_issue_task_mandate", "aroha_issue_spending_mandate"]
    : [];
  const gatedTools = toolsSetting === "none" ? [] : (toolsSetting ?? defaultGated);
  for (const t of gatedTools) {
    if (!(GATEABLE_TOOLS as readonly string[]).includes(t)) {
      throw new Error(`approvals.tools: "${t}" is not a gateable tool (${GATEABLE_TOOLS.join(", ")})`);
    }
  }
  const stateKeyRaw = env.AROHA_MCP_STATE_KEY ?? file.approvals?.stateKey;
  const stateKey = stateKeyRaw ? decodeSecret(stateKeyRaw) : undefined;
  if (stateKey && stateKey.length < 32) throw new Error("AROHA_MCP_STATE_KEY must be at least 32 bytes");

  const allowInsecureHttp = env.AROHA_ALLOW_INSECURE_HTTP === "1";
  const registryUrl = resolveRegistryUrl(env.AROHA_REGISTRY_URL ?? file.registry?.url);
  const registryKeys = parseRegistryKeys(env.AROHA_MCP_REGISTRY_KEYS) ?? file.registry?.keys;

  const governedOn = bool(env.AROHA_MCP_GOVERNED) ?? file.governed?.enabled ?? false;
  let governed: ResolvedConfig["governed"];
  if (governedOn) {
    const trustedRoots = list(env.AROHA_MCP_TRUSTED_ROOTS) ?? file.governed?.trustedRoots;
    const expectedRoot = env.AROHA_MCP_EXPECTED_ROOT ?? file.governed?.expectedRoot;
    if (!expectedRoot && !(trustedRoots && trustedRoots.length > 0)) {
      throw new Error("Governed profile needs a pinned root: AROHA_MCP_EXPECTED_ROOT or AROHA_MCP_TRUSTED_ROOTS");
    }
    governed = { expectedRoot, trustedRoots };
  }

  const tasksOn = bool(env.AROHA_MCP_TASKS) ?? file.tasks?.enabled ?? true;
  let tasks: ResolvedConfig["tasks"];
  if (tasksOn) {
    const maxPerUser = boundedInt("AROHA_MCP_TASKS_PER_USER", env.AROHA_MCP_TASKS_PER_USER ?? file.tasks?.maxPerUser, 32, 1, 1000);
    tasks = {
      ttlMs: boundedInt("AROHA_MCP_TASK_TTL_SECONDS", env.AROHA_MCP_TASK_TTL_SECONDS ?? file.tasks?.ttlSeconds, 900, 1, 86_400) * 1000,
      maxPerUser,
      maxTotal: boundedInt("AROHA_MCP_TASKS_MAX", env.AROHA_MCP_TASKS_MAX ?? file.tasks?.maxTotal, 1000, maxPerUser, 100_000),
      pollIntervalMs: boundedInt("tasks.pollIntervalMs", file.tasks?.pollIntervalMs, 1000, 100, 60_000),
    };
  }

  const hostnames = new Set<string>(["localhost", "127.0.0.1", "[::1]"]);
  hostnames.add(publicUrl.hostname);
  for (const h of list(env.AROHA_MCP_ALLOWED_HOSTS) ?? file.http?.allowedHosts ?? []) hostnames.add(h);

  return {
    transport,
    http: {
      host,
      port,
      publicUrl,
      path,
      allowedHosts: [...hostnames],
      allowedOrigins: list(env.AROHA_MCP_ALLOWED_ORIGINS) ?? file.http?.allowedOrigins ?? [],
      allowUnauthenticated,
      maxBodyBytes: file.http?.maxBodyBytes ?? 1_048_576,
    },
    auth,
    keysDir: env.AROHA_MCP_KEY_DIR ?? env.AROHA_MCP_IDENTITY_DIR ?? file.keys?.dir ?? defaultIdentityDir(),
    approvals: {
      tools: new Set(gatedTools),
      stateKey,
      stateTtlSeconds: file.approvals?.stateTtlSeconds ?? 600,
    },
    registry: {
      url: registryUrl,
      apiKey: env.AROHA_API_KEY ?? "",
      allowInsecureHttp,
      keys: registryKeys,
    },
    governed,
    verifyResponses: bool(env.AROHA_MCP_VERIFY_RESPONSES) ?? file.verifyResponses ?? true,
    allowPrivateEndpoints: bool(env.AROHA_ALLOW_PRIVATE_ENDPOINTS) ?? file.allowPrivateEndpoints ?? false,
    tasks,
  };
}
