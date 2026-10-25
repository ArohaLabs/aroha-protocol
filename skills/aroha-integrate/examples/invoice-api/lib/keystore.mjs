// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Where a key lives. This example keeps each party's key in its own file,
// readable only by its owner (0600), standing in for the real places:
//
//   customer  → their device's keystore (OS keychain, a passkey-backed
//               wallet) or a key service your product runs for them.
//               NEVER the agent's machine, a prompt, a log or your server.
//   agent     → the agent's own secret store (its host's KMS / vault).
//
// The point the example makes: the customer's private key and the agent's
// private key are never in the same process. Only DIDs (public) and signed
// mandate tokens cross between them.

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { generateKeyPair, generateDid } from "@aroha-sdk/core";

/** Load the key at `path`, creating it on first use. Returns { did, privateKey }. */
export async function loadOrCreateKey(path) {
  if (existsSync(path)) {
    const saved = JSON.parse(readFileSync(path, "utf8"));
    return { did: saved.did, privateKey: Uint8Array.from(Buffer.from(saved.privateKeyHex, "hex")) };
  }
  const { publicKey, privateKey } = await generateKeyPair();
  const did = generateDid(publicKey); // did:aroha:z… — the public key is IN the DID
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify({ did, privateKeyHex: Buffer.from(privateKey).toString("hex") }), { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort on Windows */ }
  return { did, privateKey };
}
