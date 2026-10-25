<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# DID Method — did:aroha

The `did:aroha` DID method specification.
Full W3C ReSpec HTML version: [`did-aroha-method-1.0.html`](../spec/did-aroha-method-1.0.html).

---

## Syntax

```
did:aroha:<unique-id>

<unique-id> ::= [a-z0-9][a-z0-9\-]{1,62}
```

Examples:
```
did:aroha:flight-booking-agent
did:aroha:personal-agent-alice
did:aroha:hedge-fund-analyst-v2
```

**Constraints:**

- Lowercase alphanumeric and hyphens only
- 2–63 characters
- Must not start or end with a hyphen
- Globally unique — operators are responsible for choosing a unique ID

### Forms

Three forms share the method and are distinguished by syntax alone:

| Form | Suffix | Key comes from | Rotatable | Trust |
|------|--------|----------------|-----------|-------|
| **E-form** (recommended) | `E` + base58btc of a 32-byte SHA-256 digest of the inception event | the identifier's verified Key Event Log | Yes (pre-rotation; controller recovery for agents) | Self-certifying |
| **z-form** (legacy) | `z` + base58btc of a 32-byte Ed25519 public key | the identifier itself | **No** | Self-certifying |
| **Named form** | the grammar above | a registry record / DID Document | Via the registry | Registry-trusted |

The constraints above apply to the named form. A named DID MUST NOT have a
suffix that parses as the E-form or the z-form. See
[Rotatable identifiers (E-form) and Key Event Logs](#rotatable-identifiers-e-form-and-key-event-logs).

---

## DID Document format

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:aroha:my-agent",
  "verificationMethod": [
    {
      "id": "did:aroha:my-agent#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aroha:my-agent",
      "publicKeyMultibase": "z<base58btc-32-bytes>"
    }
  ],
  "authentication": ["did:aroha:my-agent#key-1"],
  "assertionMethod": ["did:aroha:my-agent#key-1"],
  "keyAgreement": ["did:aroha:my-agent#key-1"],
  "service": [
    {
      "id": "did:aroha:my-agent#aroha",
      "type": "ArohaEndpoint",
      "serviceEndpoint": "https://my-agent.example.com/aroha/v1"
    }
  ],
  "created": "2026-04-23T00:00:00Z",
  "updated": "2026-04-23T00:00:00Z"
}
```

### Required fields

| Field | Required | Constraint |
|-------|----------|-----------|
| `id` | ✓ | Must match the DID |
| `verificationMethod` | ✓ | At least one `Ed25519VerificationKey2020` |
| `authentication` | ✓ | Must reference the verification method |
| `service` | ✓ | Must contain one `ArohaEndpoint` service |
| `service[].serviceEndpoint` | ✓ | HTTPS URL of `/aroha/v1` endpoint |

---

## DID Method Operations

This section defines the four operations required by
[DID Core §8.2](https://www.w3.org/TR/did-1.1/#method-operations):
Create, Read (Resolve), Update, and Deactivate. The verifiable data
registry for `did:aroha` is the Aroha Registry — an HTTPS service
(reference deployment: `aroha-registry.aroha-labs.workers.dev`) whose
records bind each DID to an Ed25519 public key and a content-addressed
(IPFS) capability manifest. Any party may operate a registry instance;
the DID's `didHash` (keccak-256 of the DID string) is registry-independent.

### Create

A DID is created by generating an Ed25519 keypair, choosing a unique DID
conforming to the Syntax section, pinning a capability manifest to IPFS,
and registering the binding:

```
POST /v1/agents
Authorization: Bearer <registry API key>
{ "did": "did:aroha:<name>", "manifestCID": "<IPFS CID>",
  "publicKeyB64": "<base64 raw Ed25519 public key>", "endpointUrl": "https://…" }
```

The registry extracts capability identifiers from the content-addressed
manifest server-side — callers cannot claim capabilities that the signed
manifest does not contain. A DID may be registered exactly once
(`409 Conflict` otherwise); newly created DIDs are withheld from public
discovery for a 48-hour cooldown as an anti-squatting and anti-spam measure.

### Read (Resolve)

A `did:aroha:` DID resolves by fetching the DID Document over HTTPS:

```
GET https://<agent-domain>/.well-known/aroha-agent.json
```

The endpoint is extracted from:

1. The Aroha Registry (on-chain or HTTP) — `AgentRecord.manifestCID` → manifest → `endpoint`
2. Or directly, if the agent's domain is known

### Resolution algorithm

```
1. Query registry: resolveByDID(did)
2. Fetch manifest from IPFS: fetchManifest(record.manifestCID)
3. Verify manifest signature against record.publicKeyB64
4. Extract endpoint from manifest.endpoint
5. GET {endpoint}/../.well-known/aroha-agent.json
6. Verify document.id === did
7. Return DID Document
```

### Update

Two attributes of a registration are mutable, both write-scoped to the
API key that created the record (`403` otherwise):

1. **Manifest update** — `PUT /v1/agents/{didHash}/manifest` replaces the
   manifest CID; capability indexes are rebuilt from the new
   content-addressed manifest.
2. **Key rotation** — a signed rotate-key request replaces the bound
   public key. Rotation requests carry a UUID nonce consumed atomically
   by the registry (replayed nonces → `409`), a 5-minute `issuedAt`
   freshness window, and must be self-signed by the *outgoing* key,
   proving voluntary rotation. The registry increments `keyVersion`,
   records `keyRotatedAt`, and archives the superseded key in an
   append-only `revoked_keys` log. Verifiers MUST reject credentials
   signed before `keyRotatedAt` by a superseded key. Operational key
   handling is described under Key management below.

### Deactivate

```
DELETE /v1/agents/{didHash}
Authorization: Bearer <owner API key>
```

Deactivation sets `active = false`. Deactivated DIDs no longer resolve
and are excluded from discovery, but the record and its key history are
retained (never re-assignable to another party) so that historical
signatures remain auditable. Deactivation is idempotent and permanent;
re-activation is not defined by this method.

---

## Key management

### Key generation

```typescript
import { generateDID } from "@aroha-sdk/core";

const identity = await generateDID("my-agent", "https://my-agent.example.com/aroha/v1");
// identity.privateKey  Uint8Array(32) — Ed25519 seed — KEEP SECRET
// identity.publicKey   Uint8Array(32) — Ed25519 public key
// identity.document    DID Document
```

### Key rotation

This procedure applies to the named form. An E-form identifier rotates by
appending a `rotate` event to its Key Event Log (see below). A z-form
identifier cannot rotate; migrate it to the E-form.

1. Generate new keypair
2. Add new `verificationMethod` to DID Document with ID `#key-2`
3. Keep old key in DID Document during a transition window (≥ 5 minutes)
4. Update the manifest signature with the new key
5. Update the registry record with the new public key
6. After transition window, remove old key from DID Document

### Key recovery

Recovery is the operator's responsibility. Best practices:

- Store the private key in a Hardware Security Module (HSM) or secrets manager
- Keep an encrypted backup in a separate geographic region
- Never store the private key in environment variables or source code

---

## Rotatable identifiers (E-form) and Key Event Logs

*Status: added 2026-10-07. Reference implementation: `@aroha-sdk/core`
`identity/kel.ts`, `identity/migration.ts`.*

The key words MUST, MUST NOT, SHOULD and MAY in this section are to be
interpreted as described in RFC 2119.

### Motivation

The content-addressed form (`did:aroha:z…`) derives the key from the DID,
so it can never rotate: a lost or stolen key takes the identity, its
personal name, its reputation and its grants with it. The named form can
rotate, but only because a registry says which key is current. The E-form
is self-certifying like the z-form **and** rotatable: the identifier
commits to a signed *inception event*, and later key changes are events in
an append-only, hash-chained **Key Event Log (KEL)**, each authorised by a
key that the previous state committed to in advance (*pre-rotation*). A
registry or peer that serves a KEL can withhold events or serve an old
prefix; it cannot forge one.

### Encodings

| Item | Encoding |
|------|----------|
| Public key | Multibase base58btc of the raw 32-byte Ed25519 key: `z<base58btc>` |
| Digest | `E` followed by base58btc of a 32-byte SHA-256 output. Decoding MUST yield exactly 32 bytes and re-encoding MUST reproduce the string. |
| Canonical form | RFC 8785 (JCS) of the event with its `sig` member removed |
| Event digest | Digest of the UTF-8 bytes of the canonical form |
| Key digest | Digest of the raw 32-byte public key |
| Signature | Ed25519 over the UTF-8 bytes of the canonical form, base64url without padding |
| Timestamps | ISO 8601 strings. Informational: verifiers MUST NOT use them to order events. |

### Identifier

```
did:aroha:E<base58btc(sha256(JCS(inception without "sig")))>
```

The DID is `did:aroha:` followed by the event digest of the inception
event. A conforming parser MUST classify a `did:aroha:` suffix as the E-form
only if it is `E` followed by base58btc that decodes to exactly 32 bytes and
re-encodes to the same string. Named DIDs MUST NOT take a shape that parses
as the E-form or the z-form (the lowercase named-form grammar already
excludes the E-form).

### Events

Every event has `v: 1`. Events after the inception also have `did` (the
identifier), `seq` (an integer equal to the event's index in the log;
inception is 0), `prior` (the event digest of the event at `seq - 1`) and
`at` (a timestamp).

| `type` | Members | Authorised by |
|--------|---------|---------------|
| `inception` | `kind` (`"person"` \| `"agent"`), `keys` (one public key), `nextKeyDigest`, `controller` (agents only, optional), `createdAt`, `sig` | `keys[0]` |
| `rotate` | `keys` (one public key), `nextKeyDigest`, `sig` | the new `keys[0]`, whose key digest MUST equal the previous `nextKeyDigest` |
| `recover` | `auth: "controller"`, `keys`, `nextKeyDigest` (no `sig`) | a seal in the controller's KEL (agents with a controller only) |
| `revoke` | `auth: "controller"`, optional `reason` (no `sig`) | a seal in the controller's KEL (agents with a controller only) |
| `revoke` | `auth: "next-key"`, `revealedKey`, optional `reason`, `sig` | `revealedKey`, whose key digest MUST equal the current `nextKeyDigest` |
| `anchor` | `seals`: array of `{ did, seq, digest }`, `sig` | the current key (persons only) |

In version 1, `keys` MUST contain exactly one key. A `nextKeyDigest` MUST
NOT equal the key digest of the key installed by the same event.

A **seal** `{ did, seq, digest }` in a person's `anchor` event authorises,
and vouches for the existence of, the event at position `seq` of the KEL of
`did`, whose event digest is `digest`. Controller authority is expressed by
anchoring rather than by a signature on the agent's event because a
signature carries no ordering: after a person rotates, a superseded person
key could still sign, but it can no longer append to the person's
hash-chained log.

### Verification

To verify a KEL `events` for an identifier `did`, a verifier MUST:

1. Check that `did` is an E-form DID and that `events[0]` is a version 1
   `inception` whose event digest equals the suffix of `did`.
2. Check the inception's members and its signature by `keys[0]`. If `kind`
   is `"person"`, `controller` MUST be absent. If `controller` is present, it
   MUST be an E-form DID.
3. For each later event, in order: check that `did`, `seq` and `prior`
   chain as defined above, that no event follows a `revoke`, and that the
   event satisfies its authorisation rule in the table.
4. For an agent with a `controller`: if any event is controller-authorised,
   obtain and verify the controller's KEL (the controller MUST be a
   person). Every controller-authorised event MUST be matched by a seal with
   the same `did`, `seq` and `digest`. For every seal the controller placed
   for `did`, the agent's log MUST contain an event at that `seq` with that
   digest. If the log is too short, the verifier MUST treat it as stale; if
   the digests differ, it MUST treat it as duplicitous.
5. Derive the state: current keys, the outstanding `nextKeyDigest`,
   `revoked` (true after any `revoke`, after which no key of the identity is
   valid), and the last sequence number.

An inception-only KEL MUST verify with no input other than the inception
event. Implementations SHOULD send the inception (or the full KEL) with
first contact, so a peer can verify an E-form DID with no network access.

A signature by an E-form identity MUST be verified against the identity's
**current** key as derived from the newest verified KEL available to the
verifier. An identity that is revoked, or an agent whose controller has
revoked itself, has no valid key.

### Persons and controllers

A **person** is an E-form identity with `kind: "person"` and no controller.
An **agent** MAY name a person as `controller` in its inception, which is
fixed for the life of the identifier. The controller MAY append `recover`
(install a new key and commitment — the lost or stolen device path) or
`revoke` events to the agent's KEL, each authorised by a seal in the
person's own KEL.

A person rotates only by pre-rotation. The person's recovery mechanism is
the pre-committed next key, which SHOULD be held separately from the
current key (for example offline, or in a passkey- or secure-enclave-backed
store on a second device). Loss of both keys of a person cannot be
recovered by this method; see Migration below.

| Holder of… | can… | cannot… |
|------------|------|---------|
| an agent's current key | sign as the agent until it is recovered, revoked or rotated | rotate, recover or revoke the agent |
| an agent's next key | rotate or revoke the agent | — |
| a person's current key | sign as the person; anchor (recover or revoke) the person's agents | rotate the person |
| a person's superseded key | fork the person's log from the point it was current (see Duplicity) | extend the honest log |

### Stale logs and duplicity

Verification proves a KEL is authentic, not that it is complete. A party
serving a KEL can omit recent events, and a holder of a superseded key can
fork the log from the point that key was current.

- A verifier SHOULD retain, per identifier, the longest KEL it has verified.
- A verifier MUST NOT accept a KEL shorter than one it has already verified
  for the same identifier as the identifier's current state. It MAY answer
  from the retained, longer KEL instead.
- If a verified KEL differs from a retained KEL at any sequence number both
  contain, the verifier MUST record a duplicity alarm for the identifier and
  MUST reject the identifier until the alarm is resolved out of band. A
  verifier MUST verify a KEL before comparing it, so that an unauthenticated
  party cannot raise an alarm.
- A first-contact verifier with only one source cannot detect a stale or
  forked KEL. Witness and watcher infrastructure is out of scope for this
  version.

### Delegation roots

A verifier of a delegation (mandate) chain MAY require a **person root**.
When it does, the root grantor MUST be an E-form identity of kind `person`
whose KEL verifies and is not revoked, and the root mandate's signature
MUST verify against that person's current key.

When a verifier has a KEL source, it MUST resolve the KEL of every E-form
grantor and grantee in the chain, MUST verify each grantor's signature
against that identity's current key, and MUST reject the chain if any of
those identities, or any of their controllers, is revoked, or if a required
KEL (including an agent's controller's KEL) cannot be obtained or verified.
Consequence: after a rotation or recovery, mandates signed by the
superseded key no longer verify and must be re-issued.

### Migration from the z-form

A holder of a content-addressed DID migrates by creating an E-form identity
and a **linkage**:

```json
{
  "v": 1,
  "type": "aroha-identity-linkage",
  "from": "did:aroha:z…",
  "to": "did:aroha:E…",
  "toSeq": 0,
  "at": "2026-10-07T00:00:00.000Z",
  "sigs": { "from": "<base64url>", "to": "<base64url>" }
}
```

Both signatures cover the JCS form of the linkage without `sigs`. `sigs.from`
MUST verify against the key of `from`; `sigs.to` MUST verify against the key
that was current at position `toSeq` of the verified KEL of `to`. A verifier
MUST reject a linkage that is missing either signature, and SHOULD reject a
linkage to a revoked identity. A verified linkage allows parties that
trusted `from` (grants, reputation, contacts) to extend that trust to `to`.

Because a z-form DID is its key, anyone holding that key can produce a
linkage. Verifiers SHOULD retain the first linkage seen for each `from` and
SHOULD surface a second linkage with a different `to` for human review
rather than following it.

The personal name changes on migration, because it is derived from the
identifier. From then on it is stable across rotation and recovery.

### Derived data

- **Personal names.** For an E-form DID the personal label is derived from
  the 32-byte inception digest, using the same wordlist and key-derivation
  function as the z-form with the domain-separation salt
  `aroha:personal-name:v1:inception`. For a z-form DID it continues to be
  derived from the public key.
- **Signed Agent Records.** A SAR for an E-form DID MAY carry the agent's
  KEL in a `kel` member that is not covered by the SAR signature. A
  verifier MUST verify the SAR signature against the current key of the
  verified KEL and MUST NOT use any key written in the record.

### Status of the other forms

- **z-form** (`did:aroha:z<base58btc(publicKey)>`): **legacy**. Verifiable
  offline, but **not rotatable**: a verifier deriving the key from the DID
  ignores any rotation record. New identities SHOULD use the E-form.
- **Named form** (`did:aroha:<name>`): **registry-trusted**. The binding of
  name to key is only as trustworthy as the registry or resolver that
  serves it. The Create/Update/Deactivate operations above and the
  registry-based key rotation apply to this form.

---

## Post-quantum migration

The DID Document is designed for a no-flag-day migration to NIST PQ standards
(FIPS 204 ML-DSA / FIPS 205 SLH-DSA).

Add a second `verificationMethod` alongside the existing Ed25519 key:

```json
{
  "verificationMethod": [
    {
      "id": "did:aroha:my-agent#key-1",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z..."
    },
    {
      "id": "did:aroha:my-agent#key-2-pq",
      "type": "Mldsa44VerificationKey2025",
      "publicKeyMultibase": "z..."
    }
  ]
}
```

Legacy agents ignore unknown key types. New agents prefer the PQ key.
See [Post-Quantum Migration](https://github.com/ArohaLabs/aroha-protocol/blob/main/docs/reference/post-quantum.md) and [Aroha 1.0 Appendix C](aroha-1.0.md#appendix-c--post-quantum-cryptography-migration) for the full procedure.

---

## did:aroha-web: — Web-Native Two-Factor Identity

Aroha provides a second DID method for agents that want domain-anchored identity without a custom registry. `did:aroha-web:` requires **two independent verification factors**, unlike `did:web:` (W3C) and `did:wba:` (ANP) which only use HTTPS.

### Format

```
did:aroha-web:{domain}:{path}

Examples:
  did:aroha-web:stripe.com:payments-agent
  did:aroha-web:acme.corp:travel-orchestrator
```

### Two-factor verification

| Factor | Where |
|--------|-------|
| **HTTPS** | `GET https://{domain}/.well-known/aroha/agents/{path}/did.json` |
| **DNS TXT** | `_aroha.{domain} IN TXT "v=aroha1; path={path}; keyhash={sha256hex}"` |

Both must match. A domain hijack alone — or a DNS poisoning alone — is insufficient.

### Key rotation

Keys rotate with a 24-hour cool-down period and a predecessor-signature chain. The old key signs the rotation event, so verifiers can confirm it was authorised by the previous key holder.

For full specification, DNS TXT format, and key rotation procedure, see [did:aroha-web: Specification →](web-did.md)

---

## Security Considerations

This section addresses the requirements of
[DID Core §8.3](https://www.w3.org/TR/did-1.1/#security-requirements).

**Cryptography.** All bindings and credentials use Ed25519 (EdDSA over
Curve25519, ~128-bit security). Signatures are computed over
canonicalised (key-sorted) JSON to prevent semantic-equivalence
malleability. See Post-quantum migration above for the hybrid-signature
transition plan.

**Key compromise and rotation.** An attacker holding a private key can
impersonate the DID until rotation. Mitigations: rotation requests must
be self-signed by the outgoing key with a fresh nonce (atomic,
replay-rejected) inside a 5-minute issuance window; superseded keys are
archived append-only and verifiers reject artefacts signed by a
superseded key after `keyRotatedAt`; mandate credentials issued under
this method are deliberately short-lived (minutes to one hour), bounding
the value of any single compromise. These registry-mediated controls apply
to the named form. For the E-form, a stolen current key cannot rotate the
identifier (rotation requires the pre-committed next key), and a person can
recover or revoke a stolen agent from another device; see Rotatable
identifiers. The z-form has no rotation and no recovery.

**Registry trust model.** The registry is a trusted directory for
*liveness* (endpoint, active flag, current key) but not for *content*:
capability lists derive from content-addressed IPFS manifests whose CIDs
the registry cannot forge, and DID Documents are verified against the
DID itself (`document.id === did`) at resolution. A malicious registry
can deny service or serve stale keys; it cannot mint valid signatures.
Operators requiring stronger guarantees can run their own registry
instance and pin trust anchors out-of-band (see the delegation layer's
`trustAnchors`).

**Eavesdropping and man-in-the-middle.** All method operations and
resolution occur over HTTPS. The `did:aroha-web:` variant additionally
requires an independent DNS TXT proof, so neither a web-server compromise
nor DNS poisoning alone is sufficient to bind a fraudulent key.

**Denial of service.** Discovery endpoints are rate-limited per IP;
registration requires an API key; new registrations are excluded from
discovery for 48 hours, limiting the utility of bulk-registered
squatting or impersonation DIDs.

**Residual risks.** DID strings are user-chosen: nothing prevents
registering a name *similar* to another agent's (typosquatting).
Verifiers MUST treat reputation, verification tier, and mandate chains —
not DID string resemblance — as the basis for trust decisions.

## Privacy Considerations

This section addresses the requirements of
[DID Core §8.4](https://www.w3.org/TR/did-1.1/#privacy-requirements).

**No PII in method data.** DID Documents, registry records, and IPFS
manifests are public and permanent; the method therefore forbids
personal data in all three. In the reference implementation, ownership
is recorded as a one-way hash of an internal account identifier — never
an email address or name. IPFS pinning is immutable, so this exclusion
is enforced at manifest construction time rather than by later deletion.

**Pseudonymity and correlation.** A `did:aroha` identifier is a
persistent pseudonym. As with all long-lived identifiers, use of the
same DID across many counterparties permits activity correlation by
those counterparties and by the registry operator (who observes
resolution queries). Agents with strong unlinkability requirements
SHOULD use distinct DIDs per context; the method imposes no limit on
DIDs per operator.

**Resolution metadata.** Resolving a DID reveals the resolver's interest
in that DID to the registry and to the agent's endpoint (standard HTTPS
metadata). Cached resolution (registry records and manifests are
cache-friendly; manifests are immutable by CID) reduces repeat exposure.

**Deactivation vs. erasure.** Deactivation removes a DID from resolution
and discovery but retains the record and key history for auditability of
past signatures. Because no personal data may enter method records, this
retention holds no PII; operator obligations for off-method data (e.g.
account records) are out of scope and addressed in the platform's
GDPR documentation.
