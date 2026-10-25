// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Key-derived personal agent names — design spec §7.10.
 *
 * `label = wordlist(KDF(publicKey))`. The label is self-verifying: anyone
 * holding the public key a content-addressed DID commits to (see
 * `publicKeyFromDid` in sar.ts) can recompute the label and confirm a
 * hostname matches it, with no registry, no allocator, and no trusted
 * mapping — the same principle as onion addresses and IPFS CIDs.
 *
 * Two inputs, one pipeline. A legacy content-addressed DID
 * (`did:aroha:z<pubkey>`) derives its label from its public key, so the label
 * dies with the key: lose or rotate the key and the name is gone with the
 * DID. A rotatable DID (`did:aroha:E<sha256(inception)>`, aroha-core kel.ts)
 * derives its label from the 32-byte INCEPTION DIGEST instead — the part of
 * the identifier that never changes. Same wordlist, same KDF, same
 * parameters; only the input (and the domain-separation salt) differs. That
 * is the payoff of the E form for naming: the label survives key rotation and
 * controller recovery, so a stolen laptop no longer costs a person their
 * agent's name. Use `derivePersonalLabelForDid` / `verifyPersonalLabelForDid`
 * to pick the right derivation from the DID; `derivePersonalLabel(publicKey)`
 * remains the z-form derivation, byte-for-byte unchanged.
 *
 * Migrating a z-DID to an E-DID (aroha-core migration.ts) therefore CHANGES
 * the label once — the new identifier has a new name — and from then on it is
 * stable. Show the old label as a redirecting alias, never as identity (§7.10
 * Layer 3 still applies).
 *
 * KDF substitution, disclosed: the spec's worked example names Argon2id.
 * Argon2 is not available in this environment (no native binary can be
 * built here, and it ships in neither Node's stdlib nor @noble/hashes).
 * `@noble/hashes/scrypt` is used instead — it is memory-hard for the same
 * reason Argon2id is (the point of spec §7.10 Layer 2: a legitimate holder
 * derives once, ever, so the cost is invisible, while an attacker grinding
 * candidate keys pays for it once per attempt) and is pure JS, so it runs
 * identically in Node, Bun, and the Cloudflare Workers runtime with no
 * native dependency. Parameters below (N=2^15, r=8, p=1) cost ~32 MiB and
 * ~100-150 ms per derivation on ordinary hardware, checked empirically
 * against this repo's real @noble/hashes install, not assumed.
 *
 * Worker-safe on purpose. This module is published as the
 * `@aroha-sdk/registry/personal-name` subpath and the Cloudflare registry
 * server (apps/registry-server) imports it directly, so everything it
 * reaches must bundle for the Workers runtime. That is why it imports the
 * `@aroha-sdk/core/identity` SUBPATH and never the `@aroha-sdk/core` barrel:
 * the barrel re-exports the transport module, which pulls in `ws`/`undici`
 * and through them `fs`, `http`, `path` and `string_decoder`. The subpath
 * depends on @noble/* only. worker-safety.test.ts bundles this file for a
 * platform with no Node built-ins and fails if that ever stops being true.
 */

import { scrypt } from "@noble/hashes/scrypt";
import { inceptionDigestFromDid, isContentAddressedDid, fromMultibase } from "@aroha-sdk/core/identity";
import { WORDLIST } from "./wordlist.js";

const TOKEN_COUNT = 6;
const BITS_PER_TOKEN = 11; // 2^11 = 2048 = WORDLIST.length
const TOTAL_BITS = TOKEN_COUNT * BITS_PER_TOKEN; // 66
const DK_LEN = Math.ceil(TOTAL_BITS / 8); // 9 bytes = 72 bits, 6 spare

// Fixed, public domain-separation salt — not a secret. Deterministic on
// purpose: the whole point is that any two parties deriving from the same
// public key get the same label with no coordination. The version suffix
// lets a future algorithm/parameter change mint a distinguishable label
// rather than silently colliding with v1 labels.
const SALT = new TextEncoder().encode("aroha:personal-name:v1");
// Separate salt for inception-digest input. Not load-bearing against any
// known attack (a digest and a key are both 32 opaque bytes and colliding
// them is a 2^256 problem); it is the cheap habit of never feeding two kinds
// of input through one derivation under one label, so a future change to
// either derivation cannot silently alias the other.
const INCEPTION_SALT = new TextEncoder().encode("aroha:personal-name:v1:inception");
const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, dkLen: DK_LEN };

const WORDLIST_INDEX = new Map(WORDLIST.map((word, i) => [word, i]));

function readBits(bytes: Uint8Array, startBit: number, numBits: number): number {
  let value = 0;
  for (let i = 0; i < numBits; i++) {
    const bitPos = startBit + i;
    const byteIdx = bitPos >> 3;
    const bitIdx = 7 - (bitPos & 7);
    value = (value << 1) | ((bytes[byteIdx] >> bitIdx) & 1);
  }
  return value;
}

function hashToTokens(hash: Uint8Array): string[] {
  const tokens: string[] = [];
  for (let i = 0; i < TOKEN_COUNT; i++) {
    tokens.push(WORDLIST[readBits(hash, i * BITS_PER_TOKEN, BITS_PER_TOKEN)]);
  }
  return tokens;
}

/** Derive the key-derived personal label for a raw Ed25519 public key (legacy z-DIDs). */
export function derivePersonalLabel(publicKey: Uint8Array): string {
  const hash = scrypt(publicKey, SALT, SCRYPT_PARAMS);
  return hashToTokens(hash).join("-");
}

/**
 * Derive the personal label for a rotatable E-DID from its 32-byte inception
 * digest (`inceptionDigestFromDid`). Stable for the life of the identifier,
 * across every rotation and recovery.
 */
export function derivePersonalLabelFromInception(inceptionDigest: Uint8Array): string {
  if (inceptionDigest.length !== 32) throw new Error("inception digest must be 32 bytes");
  const hash = scrypt(inceptionDigest, INCEPTION_SALT, SCRYPT_PARAMS);
  return hashToTokens(hash).join("-");
}

/**
 * The personal label for a DID, choosing the derivation from the DID's form:
 * E-DID → inception digest; z-DID → public key; anything else (named DIDs,
 * which have nothing self-certifying to derive from) → null.
 */
export function derivePersonalLabelForDid(did: string): string | null {
  const digest = inceptionDigestFromDid(did);
  if (digest) return derivePersonalLabelFromInception(digest);
  if (isContentAddressedDid(did)) return derivePersonalLabel(fromMultibase(did.slice("did:aroha:".length)));
  return null;
}

/** Recompute the label for `did` (either self-certifying form) and confirm it matches. */
export function verifyPersonalLabelForDid(label: string, did: string): boolean {
  if (!isPersonalLabelFormat(label)) return false;
  return derivePersonalLabelForDid(did) === label;
}

/**
 * Structural check only (design spec §7.10's namespace-disambiguation
 * table): exactly 6 hyphen-separated tokens, every one present in the
 * wordlist. This is what lets a router tell a personal label from a firm
 * name without looking anything up — it does NOT confirm the label matches
 * any particular key; use `verifyPersonalLabel` for that.
 */
export function isPersonalLabelFormat(label: string): boolean {
  const tokens = label.split("-");
  if (tokens.length !== TOKEN_COUNT) return false;
  return tokens.every((t) => WORDLIST_INDEX.has(t));
}

/** Recompute the label from `publicKey` and confirm it matches `label`. */
export function verifyPersonalLabel(label: string, publicKey: Uint8Array): boolean {
  if (!isPersonalLabelFormat(label)) return false;
  return derivePersonalLabel(publicKey) === label;
}
