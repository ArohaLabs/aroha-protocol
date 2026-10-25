// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Migration from a legacy, non-rotatable DID to a rotatable `did:aroha:E…`
 * identity (kel.ts), with a LINKAGE record that lets relationships carry over.
 *
 * WHY a linkage and not "just start using the new DID": everything anyone
 * holds about an agent — access grants, reputation, contacts, pinned keys,
 * mandates that name it — is keyed by its DID. A new DID is a stranger. The
 * linkage is a statement { from: oldDid, to: newDid, at } signed by BOTH:
 *   - the old key (the holder of the old identity consents to the move), and
 *   - the new identity's current key at a stated KEL sequence (the holder of
 *     the new identity accepts the old one's history).
 * Anyone who trusted the old DID verifies the linkage and can transfer that
 * trust to the new DID knowing it is the same holder. A one-sided linkage is
 * worthless — signed only by the old key, it could point anywhere; signed
 * only by the new key, anyone could claim anyone's history — so verification
 * requires both.
 *
 * What does NOT carry over automatically:
 *   - The personal name. Names are derived from the identifier (z: from the
 *     key; E: from the inception digest), so the new DID has a new name. From
 *     then on the name is stable across rotations, which is the point of
 *     migrating; the old name should be shown as an alias that redirects.
 *   - Anything signed BY the old DID (mandates, SARs). Those keep verifying
 *     against the old DID until they expire; re-issue them from the new one.
 *
 * Limitation, stated plainly: a content-addressed DID IS its key, so whoever
 * holds the old key can produce a linkage — including a thief, pointing at an
 * E-DID they control. The linkage cannot tell the two apart. Migrate while
 * the old key is still yours alone, and verifiers SHOULD keep the first
 * linkage they see per `from` DID and treat a second, different `to` as a
 * conflict to surface to a human, never silently follow the newest.
 */

import * as ed from "@noble/ed25519";
import { canonicalizeJcs } from "../crypto/jcs.js";
import { generateDid, isContentAddressedDid, fromMultibase } from "./did.js";
import {
  incept,
  isInceptionDid,
  verifyKel,
  keysAtSequence,
  type InceptOptions,
  type KelEvent,
  type KelIdentity,
  type KelState,
  type KelSource,
} from "./kel.js";

/** The signed body of a linkage. `type` domain-separates it from every other JCS-signed object. */
export interface IdentityLinkageBody {
  v: 1;
  type: "aroha-identity-linkage";
  /** The legacy DID being retired. */
  from: string;
  /** The successor E-DID. */
  to: string;
  /** Sequence in `to`'s KEL whose current key made `sigs.to`. */
  toSeq: number;
  /** ISO 8601. */
  at: string;
}

export interface IdentityLinkage extends IdentityLinkageBody {
  sigs: {
    /** base64url Ed25519 by the old DID's key over JCS(body). */
    from: string;
    /** base64url Ed25519 by `to`'s key at `toSeq` over JCS(body). */
    to: string;
  };
}

const bodyBytes = (b: IdentityLinkageBody) => new TextEncoder().encode(canonicalizeJcs(b as unknown as Record<string, unknown>));

/**
 * Create an E-DID for the holder of a legacy content-addressed DID and link
 * the two. Pass `newInceptionOpts.privateKey = oldPrivateKey` to keep the
 * device's existing signing key as the new current key (it then gains a
 * pre-rotation commitment it never had); omit it to start with a fresh key.
 *
 * @param oldDid         `did:aroha:z…` being retired
 * @param oldPrivateKey  its Ed25519 private key (proves the holder consents)
 */
export async function migrateLegacyIdentity(
  oldDid: string,
  oldPrivateKey: Uint8Array,
  newInceptionOpts: InceptOptions
): Promise<{ identity: KelIdentity; linkage: IdentityLinkage }> {
  if (!isContentAddressedDid(oldDid)) {
    throw new Error(`${oldDid} is not a content-addressed did:aroha:z… DID — use signIdentityLinkage for registry-backed DIDs`);
  }
  const oldPublicKey = await ed.getPublicKeyAsync(oldPrivateKey);
  if (generateDid(oldPublicKey) !== oldDid) throw new Error("oldPrivateKey does not belong to oldDid");

  const identity = await incept(newInceptionOpts);
  const linkage = await signIdentityLinkage(oldDid, oldPrivateKey, identity, newInceptionOpts.now);
  return { identity, linkage };
}

/**
 * Sign a linkage from any DID whose private key you hold (z or named) to an
 * E-DID identity, using that identity's CURRENT key (its last log position).
 */
export async function signIdentityLinkage(
  fromDid: string,
  fromPrivateKey: Uint8Array,
  to: KelIdentity,
  now: Date = new Date()
): Promise<IdentityLinkage> {
  if (!isInceptionDid(to.did)) throw new Error("linkage target must be an E-DID");
  if (fromDid === to.did) throw new Error("cannot link a DID to itself");
  const body: IdentityLinkageBody = {
    v: 1,
    type: "aroha-identity-linkage",
    from: fromDid,
    to: to.did,
    toSeq: to.kel.length - 1,
    at: now.toISOString(),
  };
  const bytes = bodyBytes(body);
  const [fromSig, toSig] = await Promise.all([ed.signAsync(bytes, fromPrivateKey), ed.signAsync(bytes, to.privateKey)]);
  return {
    ...body,
    sigs: { from: Buffer.from(fromSig).toString("base64url"), to: Buffer.from(toSig).toString("base64url") },
  };
}

export type LinkageVerifyResult =
  | { valid: true; from: string; to: string; toState: KelState }
  | { valid: false; reason: string };

export interface VerifyLinkageOptions {
  /**
   * Key for a `from` DID that is NOT content-addressed (named, registry
   * trusted). Not consulted for `did:aroha:z…`, whose key is the DID.
   */
  resolveFromKey?: (did: string) => Promise<Uint8Array | null>;
  /** Controller KEL source, if `to` is an agent whose log has controller events. */
  resolveControllerKel?: KelSource;
}

async function sigOk(sigB64: unknown, bytes: Uint8Array, key: Uint8Array): Promise<boolean> {
  if (typeof sigB64 !== "string") return false;
  try {
    return await ed.verifyAsync(Buffer.from(sigB64, "base64url"), bytes, key);
  } catch {
    return false;
  }
}

/**
 * Verify a linkage against the successor's KEL. Requires BOTH signatures:
 * the old DID's key and the key `to`'s verified log had at `toSeq`. Rejects a
 * revoked successor — a retired identity cannot inherit anything.
 */
export async function verifyLinkage(
  linkage: IdentityLinkage,
  toKel: KelEvent[],
  options: VerifyLinkageOptions = {}
): Promise<LinkageVerifyResult> {
  if (
    typeof linkage !== "object" || linkage === null || linkage.v !== 1 ||
    linkage.type !== "aroha-identity-linkage" || typeof linkage.from !== "string" ||
    typeof linkage.to !== "string" || !Number.isInteger(linkage.toSeq) ||
    typeof linkage.at !== "string" || typeof linkage.sigs !== "object" || linkage.sigs === null
  ) {
    return { valid: false, reason: "malformed linkage" };
  }
  if (!isInceptionDid(linkage.to)) return { valid: false, reason: "linkage target is not an E-DID" };
  if (linkage.from === linkage.to) return { valid: false, reason: "linkage links a DID to itself" };

  let fromKey: Uint8Array | null = null;
  if (isContentAddressedDid(linkage.from)) {
    fromKey = fromMultibase(linkage.from.slice("did:aroha:".length));
  } else if (options.resolveFromKey) {
    fromKey = await options.resolveFromKey(linkage.from).catch(() => null);
  }
  if (!fromKey) return { valid: false, reason: `cannot resolve a key for ${linkage.from}` };

  let toState: KelState;
  let toKey: Uint8Array;
  try {
    toState = await verifyKel(linkage.to, toKel, { resolveControllerKel: options.resolveControllerKel });
    toKey = fromMultibase(keysAtSequence(toState, linkage.toSeq)[0]);
  } catch (e) {
    return { valid: false, reason: `successor KEL: ${(e as Error).message}` };
  }
  if (toState.revoked) return { valid: false, reason: "successor identity is revoked" };

  const body: IdentityLinkageBody = {
    v: 1,
    type: "aroha-identity-linkage",
    from: linkage.from,
    to: linkage.to,
    toSeq: linkage.toSeq,
    at: linkage.at,
  };
  const bytes = bodyBytes(body);
  if (!(await sigOk(linkage.sigs.from, bytes, fromKey))) {
    return { valid: false, reason: "linkage is not signed by the old DID's key" };
  }
  if (!(await sigOk(linkage.sigs.to, bytes, toKey))) {
    return { valid: false, reason: "linkage is not signed by the successor's key" };
  }
  return { valid: true, from: linkage.from, to: linkage.to, toState };
}
