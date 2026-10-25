// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Startup configuration checks — shared by the agents under agents/ (each
 * carries an identical copy; see errors.ts for why).
 *
 * Three things used to fail late or silently:
 *
 *   - Missing credentials: the agent started, advertised itself, and then
 *     failed every call with an upstream 401. It now refuses to start.
 *   - Advertised endpoint: defaulted to http://localhost:<port>, which went
 *     into the DID document peers resolve — wrong for any real deployment.
 *     AGENT_ENDPOINT is now required outside development.
 *   - Identity: a fresh keypair on every start meant no peer could pin this
 *     agent's key across restarts. A persistent key can now be supplied;
 *     generate-on-start stays as the development fallback, with a warning.
 *
 * "Development" means NODE_ENV=development, the single switch for all three.
 */

import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { generateDID, toMultibase, type AgentKeyPair } from "@aroha-sdk/core";

type Env = Record<string, string | undefined>;

export function isDevMode(env: Env = process.env): boolean {
  return env.NODE_ENV === "development";
}

/**
 * Throw if any of `names` is unset/empty, unless in development mode, where
 * a warning is printed instead so local demos still boot without credentials.
 */
export function requireEnv(names: readonly string[], logPrefix: string, env: Env = process.env): void {
  const missing = names.filter((n) => !env[n]?.trim());
  if (missing.length === 0) return;
  const msg = `missing required environment variable(s): ${missing.join(", ")}`;
  if (isDevMode(env)) {
    console.warn(`${logPrefix} ${msg} — continuing because NODE_ENV=development; upstream calls will fail`);
    return;
  }
  throw new Error(`${logPrefix} ${msg}. Set them, or set NODE_ENV=development for a local run without credentials.`);
}

/**
 * The endpoint advertised in this agent's DID document. `names` are checked
 * in order (AGENT_ENDPOINT first; some agents also honour a legacy name).
 */
export function resolveEndpoint(names: readonly string[], devDefault: string, logPrefix: string, env: Env = process.env): string {
  for (const n of names) {
    const v = env[n]?.trim();
    if (v) {
      if (!/^https?:\/\/\S+$/.test(v)) throw new Error(`${logPrefix} ${n} must be an http(s) URL`);
      return v;
    }
  }
  if (isDevMode(env)) return devDefault;
  throw new Error(
    `${logPrefix} AGENT_ENDPOINT is not set. It is published in this agent's DID document, so it must be the ` +
    `URL peers actually reach (e.g. https://agent.example.com/aroha/v1). Set NODE_ENV=development to default to ${devDefault}.`,
  );
}

// RFC 8410 PKCS#8 prefix for a raw 32-byte Ed25519 seed, so node:crypto can
// derive the public key without adding @noble/ed25519 as a direct dependency.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Derive the raw Ed25519 public key for a 32-byte private seed. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  const key = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
  const jwk = createPublicKey(key).export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new Error("could not derive Ed25519 public key");
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

function parseSeedHex(hex: string, source: string): Uint8Array {
  const clean = hex.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) throw new Error(`${source} must be 64 hex characters (a 32-byte Ed25519 seed)`);
  return new Uint8Array(Buffer.from(clean, "hex"));
}

function readKeyFile(path: string): string {
  // A world/group-readable key file defeats the point of a persistent key.
  // POSIX permission bits are not meaningful on Windows, so the check is
  // skipped there; restrict the file with an ACL instead.
  if (process.platform !== "win32") {
    const mode = statSync(path).mode & 0o777;
    if (mode & 0o077) {
      throw new Error(`AGENT_PRIVATE_KEY_FILE ${path} has mode ${mode.toString(8)}; restrict it to 0600 (chmod 600)`);
    }
  }
  return readFileSync(path, "utf8");
}

/**
 * Load this agent's identity.
 *
 *   AGENT_PRIVATE_KEY_HEX   64-hex-char Ed25519 seed, or
 *   AGENT_PRIVATE_KEY_FILE  path to a file holding that hex (mode 0600)
 *
 * With neither set, a new keypair is generated (the previous behaviour) and
 * a warning explains that the key changes on every restart.
 */
export async function loadIdentity(agentId: string, endpoint: string, logPrefix: string, env: Env = process.env): Promise<AgentKeyPair> {
  const identity = await generateDID(agentId, endpoint);
  let seed: Uint8Array | undefined;
  if (env.AGENT_PRIVATE_KEY_HEX?.trim()) {
    seed = parseSeedHex(env.AGENT_PRIVATE_KEY_HEX, "AGENT_PRIVATE_KEY_HEX");
  } else if (env.AGENT_PRIVATE_KEY_FILE?.trim()) {
    seed = parseSeedHex(readKeyFile(env.AGENT_PRIVATE_KEY_FILE.trim()), "AGENT_PRIVATE_KEY_FILE");
  }
  if (!seed) {
    console.warn(
      `${logPrefix} no AGENT_PRIVATE_KEY_HEX / AGENT_PRIVATE_KEY_FILE — generated an ephemeral key; ` +
      `peers cannot pin it across restarts`,
    );
    return identity;
  }
  const publicKey = publicKeyFromSeed(seed);
  // generateDID builds the document around its own random key; swap ours in.
  const document = {
    ...identity.document,
    verificationMethod: identity.document.verificationMethod.map((vm) => ({ ...vm, publicKeyMultibase: toMultibase(publicKey) })),
  };
  return { did: identity.did, privateKey: seed, publicKey, document };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

/** True when `host` only accepts connections from this machine. */
export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return LOOPBACK_HOSTS.has(h) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * Interface the agent's listener binds: AGENT_HOST, default 127.0.0.1.
 *
 * Loopback by default so an agent is not reachable from the LAN (or, on a VM
 * with a public IP, the internet) as a side effect of starting it. To serve
 * other machines — a container behind a load balancer, a LAN peer — set
 * AGENT_HOST=0.0.0.0 (or a specific interface) explicitly; a warning is
 * printed so the exposure is visible in the logs.
 */
export function resolveListenHost(logPrefix: string, env: Env = process.env): string {
  const host = env.AGENT_HOST?.trim() || "127.0.0.1";
  if (!isLoopbackHost(host)) {
    console.warn(
      `${logPrefix} AGENT_HOST=${host} — listener is reachable from other machines; ` +
      `keep it behind a firewall or reverse proxy and make sure peer authentication is configured`,
    );
  }
  return host;
}
