// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `@aroha-sdk/core/endpoints` — the one place the SDK names Aroha-operated
 * hosts, and the one place it decides whether an outbound endpoint is safe to
 * talk to.
 *
 * WHY A SEPARATE SUBPATH. Like ./identity, this module has no Node-only
 * imports, so Worker-bundled code (the registry's mandate endpoints, which
 * import @aroha-sdk/credentials/mandates) can use it without pulling in the
 * Node transport.
 *
 * WHY ONE CONSTANT. The registry URL used to be hard-coded in half a dozen
 * packages, and they disagreed: some named a custom domain that does not
 * resolve, others the workers.dev host that is actually deployed. A client
 * pointed at a dead host fails; a client pointed at the wrong-but-live host
 * trusts records it should not. Every package now reads these constants (or
 * the environment overrides) instead of carrying its own copy.
 */

/**
 * The Aroha-managed registry. This is the workers.dev host the registry
 * Worker (apps/registry-server, no custom route configured) is deployed to.
 * The `registry.aroha-labs.com` alias does not resolve at the time of
 * writing; switch this constant only once it does.
 *
 * Override per process with the AROHA_REGISTRY_URL environment variable, or
 * per call site with each client's own `registryUrl` option.
 */
export const AROHA_MANAGED_REGISTRY_URL = "https://aroha-registry.aroha-labs.workers.dev";

/**
 * The Aroha-operated IPFS gateway (apps/ipfs-gateway), including the `/ipfs`
 * path prefix — append `/<cid>`. Override with AROHA_IPFS_GATEWAY.
 */
export const AROHA_DEFAULT_IPFS_GATEWAY = "https://aroha-ipfs-gateway.aroha-labs.workers.dev/ipfs";

function readEnv(name: string): string | undefined {
  // `process` does not exist in a Worker or a browser; reading it must not throw.
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const v = env?.[name];
  return v && v.trim().length > 0 ? v.trim() : undefined;
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

/** `override` → AROHA_REGISTRY_URL → AROHA_MANAGED_REGISTRY_URL. No trailing slash. */
export function resolveRegistryUrl(override?: string): string {
  return stripTrailingSlash(override ?? readEnv("AROHA_REGISTRY_URL") ?? AROHA_MANAGED_REGISTRY_URL);
}

/** `override` → AROHA_IPFS_GATEWAY → AROHA_DEFAULT_IPFS_GATEWAY. No trailing slash. */
export function resolveIpfsGateway(override?: string): string {
  return stripTrailingSlash(override ?? readEnv("AROHA_IPFS_GATEWAY") ?? AROHA_DEFAULT_IPFS_GATEWAY);
}

// ── Endpoint transport policy ────────────────────────────────────────────────

export interface SecureEndpointOptions {
  /**
   * Permit plain http:// (or ws://) to a NON-loopback host. Development and
   * closed test networks only: signed envelopes protect integrity, but
   * cleartext still exposes bodies, bearer tokens and mandate tokens to every
   * hop on the path. Loopback is always permitted without this flag.
   */
  allowInsecureHttp?: boolean;
  /** Names the setting in the error message, e.g. "registryUrl". */
  label?: string;
}

export class InsecureEndpointError extends Error {
  readonly code = "INSECURE_ENDPOINT";
  constructor(message: string) {
    super(message);
    this.name = "InsecureEndpointError";
  }
}

/**
 * True for hosts that can only be reached from this machine: `localhost`
 * (and `*.localhost`, RFC 6761), 127.0.0.0/8 and ::1. Accepts a bare
 * hostname or a bracketed IPv6 literal as URL.hostname returns it.
 */
export function isLoopbackHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  return m !== null && m.slice(1).every((o) => Number(o) <= 255);
}

/**
 * Refuse an outbound endpoint that would carry Aroha traffic in cleartext.
 *
 * Accepts https:// and wss:// anywhere; http:// and ws:// only to a loopback
 * host or when `allowInsecureHttp` is set. Anything else (file:, data:,
 * unparseable input) is refused. Returns the parsed URL so callers do not
 * parse twice.
 *
 * Applied to every client that sends signed envelopes, mandate tokens or
 * registry lookups: a registry-supplied endpoint URL is attacker-influenced
 * data, and "it was in the registry" is not a reason to send credentials over
 * plain HTTP.
 */
export function assertSecureEndpoint(url: string | URL, options: SecureEndpointOptions = {}): URL {
  const label = options.label ?? "endpoint";
  let parsed: URL;
  try {
    parsed = typeof url === "string" ? new URL(url) : url;
  } catch {
    throw new InsecureEndpointError(`${label} is not a valid URL: ${String(url)}`);
  }
  const scheme = parsed.protocol;
  if (scheme === "https:" || scheme === "wss:") return parsed;
  if (scheme === "http:" || scheme === "ws:") {
    if (isLoopbackHost(parsed.hostname) || options.allowInsecureHttp === true) return parsed;
    throw new InsecureEndpointError(
      `${label} ${parsed.origin} uses ${scheme.slice(0, -1)}:// to a non-loopback host; ` +
        `use https:// (or pass allowInsecureHttp: true for development only)`
    );
  }
  throw new InsecureEndpointError(`${label} has unsupported scheme ${scheme}`);
}
