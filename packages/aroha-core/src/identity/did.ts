// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha DID (Decentralized Identifier) implementation.
 *
 * DID format:  did:aroha:<unique-id>
 * Spec:        W3C DID Core 1.0 (https://www.w3.org/TR/did-core/)
 *
 * Three forms share the method, told apart by syntax alone:
 *   did:aroha:E<base58btc(sha256(inception))>  rotatable + self-certifying;
 *                                              the key lives in a Key Event
 *                                              Log (kel.ts). Preferred.
 *   did:aroha:z<base58btc(pubkey)>             legacy content-addressed: the
 *                                              DID IS the key, so it can never
 *                                              rotate (see migration.ts).
 *   did:aroha:<name>                           named: the key is whatever a
 *                                              registry says — registry-trusted.
 *
 * A DID Document contains:
 *   - Verification methods (public keys)
 *   - Authentication references
 *   - Service endpoints (Aroha agent endpoint)
 */

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { bytesToHex, randomBytes } from "@noble/hashes/utils";
import { canonicalizeJcs } from "../crypto/jcs.js";

// noble/ed25519 v2 requires sha512 sync
ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

// ─── Types ────────────────────────────────────────────────────────────────────

export interface VerificationMethod {
  id: string;
  type: "Ed25519VerificationKey2020";
  controller: string;
  /** Base58-encoded public key with multibase prefix 'z' */
  publicKeyMultibase: string;
}

export interface ServiceEndpoint {
  id: string;
  type: "ArohaEndpoint";
  serviceEndpoint: string;
}

export interface KeyRotationRecord {
  /** ISO8601 — when the rotation was announced. */
  rotatedAt: string;
  /** ISO8601 — earliest time the new key becomes trusted (rotatedAt + coolDownHours). */
  trustAfter: string;
  /** Multibase pubkey of the replaced (predecessor) key. */
  predecessorKey: string;
  /** SHA-256 hex of the new key. */
  newKeyHash: string;
  /**
   * Ed25519 signature by the predecessor key over
   * `rotationSigningPayload(record)`. Proves voluntary key rotation.
   */
  predecessorSignature: string;
  /**
   * Record format version. `2` = the signature covers RFC 8785 JCS of
   * `{ did, newKeyHash, predecessorKey, rotatedAt, trustAfter, v: 2 }`.
   * Absent = legacy v1: the signature covers only the concatenation
   * `predecessorKey + newKeyHash + rotatedAt`.
   *
   * WHY v2: the v1 bytes name neither the DID nor `trustAfter`. Without the
   * DID, a rotation record signed for one identity verifies inside ANY
   * document that reuses the same key (one operator, several agent paths) —
   * so it can be lifted from one DID into another. Without `trustAfter`,
   * whoever serves the document can shorten the cool-down of a genuine
   * rotation by editing an unsigned field. v1 records still verify (old
   * documents keep resolving) but are reported as deprecated, and their
   * unsigned `trustAfter` is never allowed to shorten the default cool-down.
   */
  v?: 2;
  /** The DID this rotation belongs to. Required (and signed) when `v` is 2. */
  did?: string;
}

/**
 * The exact bytes a KeyRotationRecord's `predecessorSignature` covers.
 * v2 (`record.v === 2`): JCS of { did, newKeyHash, predecessorKey, rotatedAt,
 * trustAfter, v: 2 }. Legacy v1: `predecessorKey + newKeyHash + rotatedAt`.
 * Exported so other SDKs' conformance tests can pin it byte for byte.
 */
export function rotationSigningPayload(record: KeyRotationRecord): Uint8Array {
  if (record.v === 2) {
    if (typeof record.did !== "string" || record.did.length === 0) {
      throw new Error("v2 key rotation record is missing its did");
    }
    return new TextEncoder().encode(
      canonicalizeJcs({
        did: record.did,
        newKeyHash: record.newKeyHash,
        predecessorKey: record.predecessorKey,
        rotatedAt: record.rotatedAt,
        trustAfter: record.trustAfter,
        v: 2,
      })
    );
  }
  return new TextEncoder().encode(record.predecessorKey + record.newKeyHash + record.rotatedAt);
}

export interface RevokedKeyRecord {
  /** Multibase public key that was revoked. */
  keyMultibase: string;
  /** ISO8601 — when revocation was announced. */
  revokedAt: string;
  /** Human-readable reason (e.g. "Compromised — see incident #42"). */
  reason: string;
  /**
   * Ed25519 signature over `keyMultibase || revokedAt || reason`
   * signed by the key being revoked. Proves intentional revocation.
   */
  selfSignature?: string;
}

/**
 * Record of an IMMEDIATE key replacement authorised by the DID's controller
 * (see `controllerRecoverKey`). This is the only way a new key becomes
 * trusted without waiting out a rotation cool-down.
 */
export interface ControllerRecoveryRecord {
  /** DID of the controller that authorised the change (must equal the document's `controller`). */
  controller: string;
  /** Multibase key that was replaced (and is now listed in `revokedKeys`). */
  previousKeyMultibase: string;
  /** Multibase key installed by the recovery. */
  newKeyMultibase: string;
  /** ISO8601 — when the controller signed the recovery. */
  recoveredAt: string;
  /** Human-readable reason. */
  reason: string;
  /**
   * base64url Ed25519 signature by the CONTROLLER's key over
   * `controllerRecoveryPayload(...)`. Verify with `verifyControllerRecovery`.
   */
  controllerSignature: string;
}

export interface DIDDocument {
  "@context": string[];
  id: string;
  /**
   * Optional controller DID (W3C DID Core `controller`) — a person/organisation
   * identity that is DISTINCT from the agent itself and whose key is held
   * somewhere other than the agent's runtime (e.g. a founder's hardware key).
   *
   * WHY it exists: an agent's own key is the thing most likely to be stolen
   * (it sits in a running process). If the only party that can authorise a
   * key change is the holder of that same key, a thief and the owner are
   * indistinguishable. A controller is the independent second factor: the
   * ONLY signer allowed to install an immediately-trusted replacement key
   * (`controllerRecoverKey` / `verifyDIDKeyChange`). Must not equal `id`.
   */
  controller?: string;
  /** Controller-authorised immediate key replacements (newest-first). */
  controllerRecoveries?: ControllerRecoveryRecord[];
  verificationMethod: VerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  keyAgreement: string[];
  service: ServiceEndpoint[];
  created: string;
  updated: string;
  /** Rotation history (newest-first). Present only after at least one rotation. */
  keyHistory?: KeyRotationRecord[];
  /** Keys that have been explicitly revoked and must never be trusted. */
  revokedKeys?: RevokedKeyRecord[];
}

export interface AgentKeyPair {
  did: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  document: DIDDocument;
}

// ─── Base58 encoding (multibase 'z' prefix) ───────────────────────────────────

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function encodeBase58(bytes: Uint8Array): string {
  let num = BigInt("0x" + bytesToHex(bytes));
  const digits: number[] = [];
  while (num > 0n) {
    digits.push(Number(num % 58n));
    num /= 58n;
  }
  // leading zeros
  for (const b of bytes) {
    if (b !== 0) break;
    digits.push(0);
  }
  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join("");
}

/**
 * General base58btc decode: each leading '1' is one leading zero byte, the
 * rest is a big-endian base-58 number emitted in exactly as many bytes as
 * it needs.
 *
 * WHY this replaced the old version: the previous decoder padded every
 * result to a fixed 32 bytes (`padStart(64, "0")`). That happened to
 * round-trip Ed25519 public keys, but it was wrong for everything else and
 * — worse — it made SHORT inputs look like keys: `fromMultibase("zebra")`
 * came back as 32 bytes (mostly zeros), so a caller doing
 * `fromMultibase(didSuffix).length === 32` to decide "is this DID
 * content-addressed?" (aroha-registry's sar.ts `publicKeyFromDid`,
 * aroha-runtime's lan-server `resolveContentAddressedPublicKey`) would treat
 * a NAMED DID such as `did:aroha:zebra` as if its suffix were a public key.
 * Inputs longer than 32 bytes (e.g. multicodec-prefixed keys) also lost
 * their leading zero bytes. This version is the textbook algorithm and
 * round-trips any byte string `encodeBase58` produces.
 */
function decodeBase58(s: string): Uint8Array {
  let leadingZeros = 0;
  while (leadingZeros < s.length && s[leadingZeros] === "1") leadingZeros++;

  let num = 0n;
  for (const c of s) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`Invalid base58 character: ${c}`);
    num = num * 58n + BigInt(idx);
  }

  const body: number[] = [];
  while (num > 0n) {
    body.push(Number(num & 0xffn));
    num >>= 8n;
  }
  body.reverse();

  const out = new Uint8Array(leadingZeros + body.length);
  out.set(body, leadingZeros);
  return out;
}

export function toMultibase(bytes: Uint8Array): string {
  return "z" + encodeBase58(bytes);
}

export function fromMultibase(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new Error("Only base58btc multibase (prefix 'z') is supported");
  }
  return decodeBase58(multibase.slice(1));
}

// ─── Key Generation ───────────────────────────────────────────────────────────

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a raw Ed25519 keypair without creating a DID. */
export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Derive a did:aroha: DID string from an existing Ed25519 public key.
 * The DID is content-addressed: did:aroha:<base58btc(publicKey)>
 * Use generateDID() when you also need a DID Document and service endpoint.
 */
export function generateDid(publicKey: Uint8Array): string {
  return "did:aroha:" + toMultibase(publicKey);
}

/**
 * True when `did` is the self-certifying, content-addressed form
 * `did:aroha:z<base58btc(32-byte Ed25519 public key)>` — i.e. the public key
 * can be recovered from the DID string itself with no resolver.
 *
 * WHY this helper exists: `did:aroha:` covers TWO very different shapes.
 *   - Content-addressed (`generateDid` / `generateContentAddressedDID`): the
 *     DID commits to its key. Nobody — not a registry, not a cache — can
 *     substitute a different key without changing the DID.
 *   - Named (`generateDID("my-agent")`, `did:aroha:<ns>.<agentId>`): the
 *     suffix is just a label. The key comes from whatever DID Document a
 *     resolver hands back, so the binding is ONLY AS TRUSTWORTHY AS THE
 *     REGISTRY/RESOLVER that serves it.
 * Code that wants to skip resolution, cache a key forever, or accept a
 * self-signed record must check this first rather than guess from the
 * prefix. Named DIDs that happen to start with "z" (e.g. `did:aroha:zebra`)
 * are rejected because they do not decode to exactly 32 bytes.
 */
export function isContentAddressedDid(did: string): boolean {
  const prefix = "did:aroha:";
  if (!did.startsWith(prefix)) return false;
  const suffix = did.slice(prefix.length);
  if (!suffix.startsWith("z") || suffix.includes(".") || suffix.includes(":")) return false;
  try {
    return fromMultibase(suffix).length === 32;
  } catch {
    return false;
  }
}

/**
 * Reject a NAME that would parse as one of the two self-certifying forms.
 *
 * WHY: `did:aroha:` carries three shapes that verifiers treat very
 * differently — `z<base58btc(pubkey)>` (key derived from the DID, no lookup),
 * `E<base58btc(sha256(inception))>` (key from a verified Key Event Log, see
 * kel.ts), and anything else (a registry-trusted name). The forms are told
 * apart purely by syntax, so a named DID must never be minted in a shape a
 * verifier would read as self-certifying: the best case is a confusing
 * verification failure, the worst is a name squatting on the exact string
 * of somebody's real identifier. The method spec already restricts names to
 * lowercase (`[a-z0-9-]`), which excludes "E…" outright; this guard enforces
 * the collision rule for callers that never validated against the spec.
 */
function assertNotSelfCertifyingShape(suffix: string): void {
  for (const prefix of ["z", "E"]) {
    if (!suffix.startsWith(prefix)) continue;
    try {
      const bytes = fromMultibase("z" + suffix.slice(1));
      if (bytes.length === 32) {
        throw new Error(
          `"${suffix}" has the shape of a self-certifying did:aroha identifier (${prefix}-form) and cannot be used as a name`
        );
      }
    } catch (e) {
      if ((e as Error).message.includes("cannot be used as a name")) throw e;
      // Not base58 → cannot collide.
    }
  }
}

// ─── DID Generation ───────────────────────────────────────────────────────────

export interface GenerateDIDOptions {
  /**
   * Optional tenant namespace — produces did:aroha:<namespace>.<agentId>.
   * Must match /^[a-z0-9-]+$/.
   */
  namespace?: string;
  /**
   * Optional controller DID written to `document.controller` — the distinct
   * identity allowed to authorise an immediate key replacement via
   * `controllerRecoverKey`. Must differ from the generated DID.
   */
  controller?: string;
}

/**
 * Generate a new Aroha DID with a fresh Ed25519 keypair.
 *
 * NOTE — named form: this produces `did:aroha:<agentId>` (or
 * `did:aroha:<namespace>.<agentId>`), which is NOT self-certifying. The DID
 * string says nothing about the key; a verifier learns the key from a DID
 * Document served by some registry/resolver, so the key is only as
 * trustworthy as that registry. Prefer `generateContentAddressedDID` when no
 * human-readable name is needed, and use `isContentAddressedDid` to tell the
 * two forms apart. The named form is kept for compatibility.
 *
 * @param agentId  Human-readable identifier (e.g. "expedia-flights-v2")
 * @param endpoint Aroha endpoint URL for the agent
 * @param options  Optional generation options (e.g. namespace for multi-tenancy)
 */
export async function generateDID(
  agentId: string,
  endpoint: string,
  options: GenerateDIDOptions = {}
): Promise<AgentKeyPair> {
  const { namespace } = options;
  if (namespace && !/^[a-z0-9-]+$/.test(namespace)) {
    throw new Error(`Invalid namespace "${namespace}" — must match /^[a-z0-9-]+$/`);
  }
  const qualifiedId = namespace ? `${namespace}.${agentId}` : agentId;
  assertNotSelfCertifyingShape(qualifiedId);

  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const did = `did:aroha:${qualifiedId}`;
  const now = new Date().toISOString();
  const keyId = `${did}#key-1`;

  const document: DIDDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: toMultibase(publicKey),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    keyAgreement: [keyId],
    service: [
      {
        id: `${did}#aroha`,
        type: "ArohaEndpoint",
        serviceEndpoint: endpoint,
      },
    ],
    created: now,
    updated: now,
  };
  if (options.controller) {
    if (options.controller === did) throw new Error("controller must be a DID distinct from the agent's own");
    document.controller = options.controller;
  }

  return { did, privateKey, publicKey, document };
}

/**
 * Generate a new Aroha DID that is content-addressed: did:aroha:<base58btc(publicKey)>.
 *
 * Unlike generateDID() (which produces a human-readable did:aroha:<agentId>,
 * not self-certifying), this DID commits to its own signing key — any party
 * can derive the public key straight from the DID string with no lookup, no
 * trusted resolver, and no network call (the same mechanism `generateDid()`
 * exposes as a standalone function for keys minted elsewhere). That property
 * is what makes a DID eligible for the self-signed SAR path (aroha-registry's
 * sar.ts `verifySar`) and for key-derived personal agent names (design spec
 * §7.10, aroha-registry's personal-name.ts) — both require recovering the
 * public key from the DID alone, which a namespaced `did:aroha:<agentId>`
 * cannot do.
 *
 * @param endpoint Aroha endpoint URL for the agent
 */
export async function generateContentAddressedDID(endpoint: string): Promise<AgentKeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);

  const did = generateDid(publicKey);
  const now = new Date().toISOString();
  const keyId = `${did}#key-1`;

  const document: DIDDocument = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: toMultibase(publicKey),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    keyAgreement: [keyId],
    service: [
      {
        id: `${did}#aroha`,
        type: "ArohaEndpoint",
        serviceEndpoint: endpoint,
      },
    ],
    created: now,
    updated: now,
  };

  return { did, privateKey, publicKey, document };
}

/**
 * Reconstruct a DID Document from an existing keypair.
 * Used when loading a saved agent identity from storage.
 */
export function buildDIDDocument(
  agentId: string,
  publicKey: Uint8Array,
  endpoint: string,
  created: string
): DIDDocument {
  const did = `did:aroha:${agentId}`;
  const keyId = `${did}#key-1`;
  const now = new Date().toISOString();

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyMultibase: toMultibase(publicKey),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    keyAgreement: [keyId],
    service: [
      {
        id: `${did}#aroha`,
        type: "ArohaEndpoint",
        serviceEndpoint: endpoint,
      },
    ],
    created,
    updated: now,
  };
}

/**
 * Pick the verification method a signature claims to have been made with.
 *
 * WHY: key selection used to be hard-wired to `verificationMethod[0]`, so a
 * DID could only ever have one usable key — no per-device keys, no staged
 * key alongside the current one. An envelope proof already carries a
 * `verificationMethod` id; honouring it is what lets one DID hold several
 * device keys.
 *
 * Rules:
 *   - No id given → the first method (historic behaviour).
 *   - Id given (absolute `did#frag` or relative `#frag`) → that exact method.
 *   - Id given but absent → throw, EXCEPT for the legacy default
 *     `${doc.id}#key-1`, which every pre-multi-key signer stamped regardless
 *     of what the document called its key; that one falls back to the first
 *     method so old envelopes keep verifying. Falling back for an arbitrary
 *     unknown id would let a signer name a key the document never listed.
 */
export function selectVerificationMethod(
  doc: DIDDocument,
  verificationMethodId?: string
): VerificationMethod {
  const first = doc.verificationMethod[0];
  if (!first) throw new Error(`DID ${doc.id} has no verification methods`);
  if (!verificationMethodId) return first;

  const absolute = verificationMethodId.startsWith("#")
    ? `${doc.id}${verificationMethodId}`
    : verificationMethodId;
  const match = doc.verificationMethod.find(
    (vm) => vm.id === absolute || (vm.id.startsWith("#") && `${doc.id}${vm.id}` === absolute)
  );
  if (match) return match;
  if (absolute === `${doc.id}#key-1`) return first;
  throw new Error(`DID ${doc.id} has no verification method ${verificationMethodId}`);
}

function assertNotRevoked(doc: DIDDocument, keyMultibase: string): void {
  const revoked = doc.revokedKeys?.find((r) => r.keyMultibase === keyMultibase);
  if (revoked) {
    throw new Error(
      `DID ${doc.id} key ${keyMultibase.slice(0, 12)}... was revoked at ${revoked.revokedAt}: ${revoked.reason}`
    );
  }
}

/**
 * True when the latest controller recovery installed exactly `keyMultibase`
 * and is at least as recent as the latest rotation record — i.e. this key
 * was put in place by the controller, so rotation cool-downs that predate
 * it no longer apply.
 */
function isControllerInstalled(doc: DIDDocument, keyMultibase: string): boolean {
  const rec = doc.controllerRecoveries?.[0];
  if (!rec || rec.newKeyMultibase !== keyMultibase) return false;
  const latestRotation = doc.keyHistory?.[0];
  if (!latestRotation) return true;
  return new Date(rec.recoveredAt).getTime() >= new Date(latestRotation.rotatedAt).getTime();
}

/**
 * Extract the public key that should verify signatures from this DID right
 * now.
 *
 * @param doc                   The DID Document.
 * @param verificationMethodId  Optional — the `verificationMethod` id named
 *                              by the signature's proof. See
 *                              `selectVerificationMethod` for the rules.
 * @param now                   Clock override (tests).
 *
 * Rotation cool-down (CHANGED): the primary key (`verificationMethod[0]`)
 * is the one `rotateDIDKey`/`revokeKey` replace. While the newest rotation
 * is still inside its cool-down (`now < trustAfter`) the function now
 * returns the PREDECESSOR key from `keyHistory` instead of throwing. It used
 * to throw, which made the agent completely unverifiable for the whole
 * cool-down (24h by default) after every routine rotation — an availability
 * outage for a safety mechanism whose only job is to delay trust in the NEW
 * key. The predecessor signed the rotation record itself, so continuing to
 * trust it until trustAfter is exactly what the cool-down intends. Chained
 * rotations inside overlapping cool-downs walk back to the newest key whose
 * own cool-down has finished.
 *
 * If that predecessor has been REVOKED (the `revokeKey` path — the old key
 * is compromised) the function still throws: there is no trustworthy key
 * until either the cool-down ends or the controller installs one with
 * `controllerRecoverKey`. Being briefly unverifiable is the correct outcome
 * when the only alternative is trusting a stolen key.
 *
 * NOTE: this function interprets the document it is given; it does not
 * verify signatures on rotation/recovery records (it is synchronous and has
 * no way to resolve a controller's key). A registry or resolver accepting a
 * document UPDATE must check it with `verifyDIDKeyChange` first.
 */
export function extractPublicKey(
  doc: DIDDocument,
  verificationMethodId?: string,
  now: Date = new Date()
): Uint8Array {
  const vm = selectVerificationMethod(doc, verificationMethodId);
  const isPrimary = vm === doc.verificationMethod[0];

  // Non-primary (device) keys are not touched by rotation records — those
  // always describe the primary slot — so only revocation applies.
  if (!isPrimary || !doc.keyHistory?.length || isControllerInstalled(doc, vm.publicKeyMultibase)) {
    assertNotRevoked(doc, vm.publicKeyMultibase);
    return fromMultibase(vm.publicKeyMultibase);
  }

  // Walk back through rotations still inside their cool-down.
  let candidate = vm.publicKeyMultibase;
  for (const rotation of doc.keyHistory) {
    if (now.getTime() >= new Date(rotation.trustAfter).getTime()) break;
    candidate = rotation.predecessorKey;
  }

  if (candidate !== vm.publicKeyMultibase) {
    const revoked = doc.revokedKeys?.find((r) => r.keyMultibase === candidate);
    if (revoked) {
      throw new Error(
        `DID ${doc.id} key rotation cool-down active until ${doc.keyHistory[0].trustAfter} ` +
        `and the predecessor key was revoked at ${revoked.revokedAt} (${revoked.reason}) — ` +
        `no key is trusted until the cool-down ends or the controller recovers the DID`
      );
    }
  }
  assertNotRevoked(doc, candidate);
  return fromMultibase(candidate);
}

/**
 * Extract the Aroha service endpoint URL from a DID Document.
 */
export function extractEndpoint(doc: DIDDocument): string {
  const svc = doc.service.find((s) => s.type === "ArohaEndpoint");
  if (!svc) throw new Error(`DID ${doc.id} has no ArohaEndpoint service`);
  return svc.serviceEndpoint;
}

// ─── Key rotation ─────────────────────────────────────────────────────────────

function keyCommitmentHash(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey));
}

/**
 * Signed (v2) rotation record from `oldPrivateKey` to `newPublicKey` for
 * `did`. Shared by did:aroha (rotateDIDKey / revokeKey) and did:aroha-web
 * (rotateKey) so both methods sign the same, DID-bound bytes — see
 * KeyRotationRecord.v for why v1 bytes were not enough.
 */
export async function buildRotationRecord(
  did: string,
  oldPrivateKey: Uint8Array,
  oldPubMultibase: string,
  newPublicKey: Uint8Array,
  now: Date,
  coolDownHours: number
): Promise<KeyRotationRecord> {
  const trustAfter = new Date(now.getTime() + coolDownHours * 3_600_000);
  const unsigned: KeyRotationRecord = {
    v: 2,
    did,
    rotatedAt: now.toISOString(),
    trustAfter: trustAfter.toISOString(),
    predecessorKey: oldPubMultibase,
    newKeyHash: keyCommitmentHash(newPublicKey),
    predecessorSignature: "",
  };
  const sig = await ed.signAsync(rotationSigningPayload(unsigned), oldPrivateKey);
  return { ...unsigned, predecessorSignature: Buffer.from(sig).toString("base64url") };
}

/**
 * Replace the PRIMARY verification method (index 0) and keep any additional
 * (device) methods untouched. Rotation/recovery records always describe the
 * primary slot.
 */
function withNewPrimaryKey(doc: DIDDocument, newPublicKey: Uint8Array): VerificationMethod[] {
  const [primary, ...rest] = doc.verificationMethod;
  return [
    {
      id: primary?.id ?? `${doc.id}#key-1`,
      type: "Ed25519VerificationKey2020",
      controller: primary?.controller ?? doc.id,
      publicKeyMultibase: toMultibase(newPublicKey),
    },
    ...rest,
  ];
}

/**
 * Rotate to a new keypair for a did:aroha: identity.
 * The predecessor key signs the rotation record.
 * The new key is not trusted until coolDownHours have elapsed; until then
 * `extractPublicKey` keeps returning the predecessor key.
 */
export async function rotateDIDKey(
  current: AgentKeyPair,
  coolDownHours = 24
): Promise<AgentKeyPair> {
  const newPrivateKey = ed.utils.randomPrivateKey();
  const newPublicKey = await ed.getPublicKeyAsync(newPrivateKey);
  const now = new Date();

  const rotation = await buildRotationRecord(
    current.did, current.privateKey, toMultibase(current.publicKey), newPublicKey, now, coolDownHours
  );

  const newDoc: DIDDocument = {
    ...current.document,
    verificationMethod: withNewPrimaryKey(current.document, newPublicKey),
    updated: now.toISOString(),
    keyHistory: [rotation, ...(current.document.keyHistory ?? [])],
  };

  return { did: current.did, privateKey: newPrivateKey, publicKey: newPublicKey, document: newDoc };
}

/** Self-signed revocation record for `current`'s key. */
async function buildRevocationRecord(
  current: AgentKeyPair,
  reason: string,
  revokedAt: string
): Promise<RevokedKeyRecord> {
  const keyMultibase = toMultibase(current.publicKey);
  // Sign revocation with the key being revoked (proves the holder intended
  // it). Anyone holding the key — owner or thief — may revoke it; that is
  // safe because revoking only ever REMOVES trust.
  const payload = new TextEncoder().encode(keyMultibase + revokedAt + reason);
  const sig = await ed.signAsync(payload, current.privateKey);
  return {
    keyMultibase,
    revokedAt,
    reason,
    selfSignature: Buffer.from(sig).toString("base64url"),
  };
}

/**
 * Revocation ONLY — mark the current primary key as revoked and install
 * nothing in its place.
 *
 * After publishing the returned document the DID's primary key is
 * unverifiable until a new key is installed, either by `revokeKey`-style
 * recovery that waits out a cool-down, or immediately by the DID's
 * controller via `controllerRecoverKey`. That is deliberate: revocation is
 * the one key-management act a compromised key may safely authorise,
 * because it can only take trust away.
 */
export async function revokeCurrentKey(
  current: AgentKeyPair,
  reason: string
): Promise<DIDDocument> {
  const now = new Date().toISOString();
  const record = await buildRevocationRecord(current, reason, now);
  return {
    ...current.document,
    updated: now,
    revokedKeys: [record, ...(current.document.revokedKeys ?? [])],
  };
}

/**
 * Revoke the current key AND stage a replacement under the normal rotation
 * cool-down.
 *
 * ⚠️ BEHAVIOUR CHANGE (security fix): this used to install the new key with
 * NO cool-down and immediate trust, authorised only by a signature from the
 * key being revoked. Anyone who stole that key could therefore call
 * `revokeKey` themselves and take the DID over permanently, with the real
 * owner locked out and no window to react. Now:
 *   - the old key is revoked (immediately untrusted — same as before);
 *   - the new key is recorded in `keyHistory` with `trustAfter =
 *     now + coolDownHours`, exactly like `rotateDIDKey`;
 *   - during that window `extractPublicKey` THROWS for the primary key
 *     (the predecessor is revoked, the successor not yet trusted).
 * An owner who needs a new key trusted immediately must have a `controller`
 * on the DID document and use `controllerRecoverKey`. A competing staged
 * key from a thief can likewise be overridden by the controller before its
 * cool-down ends.
 *
 * @param current        The current agent keypair (signs the revocation and rotation records)
 * @param reason         Human-readable reason for revocation
 * @param coolDownHours  Cool-down before the new key is trusted (default 24)
 */
export async function revokeKey(
  current: AgentKeyPair,
  reason: string,
  coolDownHours = 24
): Promise<AgentKeyPair> {
  const newPrivateKey = ed.utils.randomPrivateKey();
  const newPublicKey = await ed.getPublicKeyAsync(newPrivateKey);
  const now = new Date();

  const revokedRecord = await buildRevocationRecord(current, reason, now.toISOString());
  const rotation = await buildRotationRecord(
    current.did, current.privateKey, revokedRecord.keyMultibase, newPublicKey, now, coolDownHours
  );

  const newDoc: DIDDocument = {
    ...current.document,
    verificationMethod: withNewPrimaryKey(current.document, newPublicKey),
    updated: now.toISOString(),
    keyHistory: [rotation, ...(current.document.keyHistory ?? [])],
    revokedKeys: [revokedRecord, ...(current.document.revokedKeys ?? [])],
  };

  return { did: current.did, privateKey: newPrivateKey, publicKey: newPublicKey, document: newDoc };
}

/**
 * Verify a revocation record's self-signature.
 * Returns true if the signature is valid — i.e., the holder of the revoked
 * key intentionally created this record.
 *
 * @param record     The RevokedKeyRecord to verify
 * @param publicKey  The public key that was revoked (to verify against)
 */
export async function verifyRevocation(
  record: RevokedKeyRecord,
  publicKey: Uint8Array
): Promise<boolean> {
  if (!record.selfSignature) return false;
  try {
    const payload = new TextEncoder().encode(
      record.keyMultibase + record.revokedAt + record.reason
    );
    const sig = Buffer.from(record.selfSignature, "base64url");
    return await ed.verifyAsync(sig, payload, publicKey);
  } catch {
    return false;
  }
}

// ─── Controller recovery ──────────────────────────────────────────────────────

/**
 * Exact bytes a controller signs to authorise an immediate key replacement.
 * Domain-separated and bound to the DID, the key being replaced, the new
 * key and the time, so a signature cannot be replayed onto another DID or
 * another key transition.
 */
export function controllerRecoveryPayload(
  did: string,
  record: Omit<ControllerRecoveryRecord, "controllerSignature">
): Uint8Array {
  return new TextEncoder().encode(
    [
      "aroha-controller-recovery:v1",
      did,
      record.controller,
      record.previousKeyMultibase,
      record.newKeyMultibase,
      record.recoveredAt,
      record.reason,
    ].join("\n")
  );
}

/**
 * Immediately replace a DID's primary key, authorised by its CONTROLLER.
 *
 * This is the only supported path to an immediately-trusted new key. It
 * requires `current.controller` to name a DID other than the agent's own,
 * and is signed with that controller's private key (which should live
 * somewhere the agent's key does not — a person's device, an HSM). The
 * replaced key is added to `revokedKeys`; any staged rotation still in its
 * cool-down (e.g. one a key thief created with `revokeKey`) is superseded.
 *
 * Callers publishing the result, and registries accepting it, should run
 * `verifyDIDKeyChange(previousDoc, newDoc, { resolveControllerPublicKey })`.
 *
 * @param current               The DID document as currently published
 * @param newPublicKey          The replacement Ed25519 public key
 * @param controllerPrivateKey  The controller DID's Ed25519 private key
 */
export async function controllerRecoverKey(
  current: DIDDocument,
  newPublicKey: Uint8Array,
  controllerPrivateKey: Uint8Array,
  options: { reason?: string; now?: Date } = {}
): Promise<DIDDocument> {
  if (!current.controller) {
    throw new Error(`DID ${current.id} has no controller — controller recovery is unavailable`);
  }
  if (current.controller === current.id) {
    throw new Error(`DID ${current.id} names itself as controller — a controller must be a distinct DID`);
  }
  const primary = current.verificationMethod[0];
  if (!primary) throw new Error(`DID ${current.id} has no verification methods`);

  const now = options.now ?? new Date();
  const unsigned: Omit<ControllerRecoveryRecord, "controllerSignature"> = {
    controller: current.controller,
    previousKeyMultibase: primary.publicKeyMultibase,
    newKeyMultibase: toMultibase(newPublicKey),
    recoveredAt: now.toISOString(),
    reason: options.reason ?? "Controller recovery",
  };
  const sig = await ed.signAsync(controllerRecoveryPayload(current.id, unsigned), controllerPrivateKey);
  const record: ControllerRecoveryRecord = {
    ...unsigned,
    controllerSignature: Buffer.from(sig).toString("base64url"),
  };

  const alreadyRevoked = current.revokedKeys?.some((r) => r.keyMultibase === primary.publicKeyMultibase);
  const revokedKeys: RevokedKeyRecord[] = alreadyRevoked
    ? (current.revokedKeys ?? [])
    : [
        {
          keyMultibase: primary.publicKeyMultibase,
          revokedAt: record.recoveredAt,
          reason: `Replaced by controller recovery: ${record.reason}`,
        },
        ...(current.revokedKeys ?? []),
      ];

  return {
    ...current,
    verificationMethod: withNewPrimaryKey(current, newPublicKey),
    updated: record.recoveredAt,
    revokedKeys,
    controllerRecoveries: [record, ...(current.controllerRecoveries ?? [])],
  };
}

/** Verify one controller recovery record against the controller's public key. */
export async function verifyControllerRecovery(
  did: string,
  record: ControllerRecoveryRecord,
  controllerPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const { controllerSignature, ...unsigned } = record;
    const sig = Buffer.from(controllerSignature, "base64url");
    return await ed.verifyAsync(sig, controllerRecoveryPayload(did, unsigned), controllerPublicKey);
  } catch {
    return false;
  }
}

export type DIDKeyChangeResult =
  | { accepted: true; kind: "unchanged" | "rotation" | "controller-recovery"; immediate: boolean; trustAfter?: string }
  | { accepted: false; reason: string };

export interface VerifyDIDKeyChangeOptions {
  /** Resolve the controller DID's public key. Required to accept a controller recovery. */
  resolveControllerPublicKey?: (controllerDID: string) => Promise<Uint8Array | null>;
  /**
   * Minimum cool-down a rotation record must declare (hours). Default 24 —
   * the same default `rotateDIDKey`/`revokeKey` use. Lower it only in tests.
   */
  minCoolDownHours?: number;
}

/**
 * Decide whether `next` is an acceptable successor of `previous` as far as
 * the PRIMARY key is concerned. Intended for registries/resolvers that
 * accept DID-document updates — `extractPublicKey` only interprets a
 * document, it cannot tell a forged update from a real one.
 *
 * Accepts:
 *   - no primary key change;
 *   - a new rotation record (`keyHistory[0]`) signed by the previous
 *     primary key, committing to the new key, with a cool-down of at least
 *     `minCoolDownHours` — the new key is NOT trusted immediately
 *     (`immediate: false`);
 *   - a new controller recovery record signed by the controller named in
 *     the PREVIOUS document (so an update cannot swap in its own
 *     controller and sign for it) — `immediate: true`.
 * Rejects everything else, including any change of `controller` (changing
 * who may authorise recovery needs its own out-of-band approval process).
 */
export async function verifyDIDKeyChange(
  previous: DIDDocument,
  next: DIDDocument,
  options: VerifyDIDKeyChangeOptions = {}
): Promise<DIDKeyChangeResult> {
  if (previous.id !== next.id) return { accepted: false, reason: "DID id changed" };
  if ((previous.controller ?? null) !== (next.controller ?? null)) {
    return { accepted: false, reason: "controller changed — requires separate authorisation" };
  }
  const prevKey = previous.verificationMethod[0]?.publicKeyMultibase;
  const nextKey = next.verificationMethod[0]?.publicKeyMultibase;
  if (!prevKey || !nextKey) return { accepted: false, reason: "missing primary verification method" };
  if (prevKey === nextKey) return { accepted: true, kind: "unchanged", immediate: false };

  const prevRecoveries = previous.controllerRecoveries?.length ?? 0;
  const nextRecoveries = next.controllerRecoveries?.length ?? 0;
  if (nextRecoveries > prevRecoveries) {
    const rec = next.controllerRecoveries![0];
    if (!previous.controller || previous.controller === previous.id) {
      return { accepted: false, reason: "controller recovery on a DID without a distinct controller" };
    }
    if (rec.controller !== previous.controller) {
      return { accepted: false, reason: "recovery signed for a controller the previous document did not name" };
    }
    if (rec.previousKeyMultibase !== prevKey || rec.newKeyMultibase !== nextKey) {
      return { accepted: false, reason: "recovery record does not describe this key transition" };
    }
    const controllerKey = await options.resolveControllerPublicKey?.(rec.controller);
    if (!controllerKey) return { accepted: false, reason: "controller public key could not be resolved" };
    if (!(await verifyControllerRecovery(next.id, rec, controllerKey))) {
      return { accepted: false, reason: "invalid controller signature" };
    }
    return { accepted: true, kind: "controller-recovery", immediate: true };
  }

  const prevRotations = previous.keyHistory?.length ?? 0;
  const nextRotations = next.keyHistory?.length ?? 0;
  if (nextRotations > prevRotations) {
    const rot = next.keyHistory![0];
    if (rot.predecessorKey !== prevKey) {
      return { accepted: false, reason: "rotation predecessor is not the current primary key" };
    }
    if (rot.newKeyHash !== keyCommitmentHash(fromMultibase(nextKey))) {
      return { accepted: false, reason: "rotation record does not commit to the new key" };
    }
    const minMs = (options.minCoolDownHours ?? 24) * 3_600_000;
    if (new Date(rot.trustAfter).getTime() - new Date(rot.rotatedAt).getTime() < minMs) {
      return { accepted: false, reason: "rotation cool-down shorter than required" };
    }
    // A v2 record names the DID it was signed for; a record lifted from
    // another identity that happens to share the key must not apply here.
    if (rot.v === 2 && rot.did !== next.id) {
      return { accepted: false, reason: "rotation record was signed for a different DID" };
    }
    try {
      const payload = rotationSigningPayload(rot);
      const ok = await ed.verifyAsync(
        Buffer.from(rot.predecessorSignature, "base64url"), payload, fromMultibase(rot.predecessorKey)
      );
      if (!ok) return { accepted: false, reason: "invalid predecessor signature on rotation" };
    } catch {
      return { accepted: false, reason: "invalid predecessor signature on rotation" };
    }
    return { accepted: true, kind: "rotation", immediate: false, trustAfter: rot.trustAfter };
  }

  return { accepted: false, reason: "primary key changed without a rotation record or controller signature" };
}

/**
 * Extract the namespace from a namespaced DID.
 * Returns null for un-namespaced DIDs.
 *
 * Example:
 *   extractNamespace("did:aroha:acme-corp.invoice-processor") → "acme-corp"
 *   extractNamespace("did:aroha:flight-agent")                → null
 */
export function extractNamespace(did: string): string | null {
  const suffix = did.replace("did:aroha:", "");
  const dotIndex = suffix.indexOf(".");
  return dotIndex >= 0 ? suffix.slice(0, dotIndex) : null;
}
