// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Per-install signing identity for the MCP server.
 *
 * WHY: the server used to send every request as the fixed, unsigned DID
 * `did:aroha:mcp-personal-agent`. Every install was the same "agent", nothing
 * it sent could be attributed or verified, and a conformant agent (which
 * rejects unsigned envelopes) could not be called at all. Each install now
 * mints its own Ed25519 key on first run and signs with it; the DID is the
 * content-addressed form, so a verifier derives the key from the DID itself.
 *
 * The key file holds the 32-byte private seed. It is created with mode 0600
 * inside a 0700 directory. (On Windows those modes are advisory; the file
 * lives under the user's profile directory.)
 */

import { mkdirSync, readFileSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { randomBytes } from "node:crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { generateDid } from "@aroha-sdk/core/identity";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

export interface McpIdentity {
  did: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  /** Where the key lives (for the user's information). */
  keyPath: string;
}

/** `AROHA_MCP_IDENTITY_DIR`, else `~/.aroha/mcp-server`. */
export function defaultIdentityDir(): string {
  const fromEnv = process.env.AROHA_MCP_IDENTITY_DIR?.trim();
  return fromEnv && fromEnv.length > 0 ? fromEnv : join(homedir(), ".aroha", "mcp-server");
}

interface KeyFile {
  v: 1;
  /** Hex Ed25519 private seed (32 bytes). */
  privateKeyHex: string;
}

/**
 * Load the identity from `dir/identity.key`, creating it on first run.
 * Throws on a corrupt key file rather than silently replacing it — a new key
 * is a new identity, and that should never happen behind the user's back.
 */
export async function loadOrCreateIdentity(dir: string = defaultIdentityDir()): Promise<McpIdentity> {
  const keyPath = join(dir, "identity.key");
  let privateKey: Uint8Array;
  if (existsSync(keyPath)) {
    let parsed: KeyFile;
    try {
      parsed = JSON.parse(readFileSync(keyPath, "utf8")) as KeyFile;
    } catch {
      throw new Error(`MCP identity key at ${keyPath} is unreadable; move it aside to mint a new identity`);
    }
    if (parsed?.v !== 1 || typeof parsed.privateKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(parsed.privateKeyHex)) {
      throw new Error(`MCP identity key at ${keyPath} is malformed; move it aside to mint a new identity`);
    }
    privateKey = new Uint8Array(Buffer.from(parsed.privateKeyHex, "hex"));
  } else {
    mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
    privateKey = new Uint8Array(randomBytes(32));
    const body: KeyFile = { v: 1, privateKeyHex: Buffer.from(privateKey).toString("hex") };
    try {
      // flag "wx": never overwrite a key another process created in the meantime.
      writeFileSync(keyPath, JSON.stringify(body), { mode: 0o600, flag: "wx" });
    } catch (err) {
      // Lost a creation race: another request (or process) minted the key
      // first. Use theirs — two keys for one principal would be two identities.
      if ((err as NodeJS.ErrnoException).code === "EEXIST") return loadOrCreateIdentity(dir);
      throw err;
    }
    try { chmodSync(keyPath, 0o600); } catch { /* best effort on platforms without POSIX modes */ }
  }
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { did: generateDid(publicKey), publicKey, privateKey, keyPath };
}
