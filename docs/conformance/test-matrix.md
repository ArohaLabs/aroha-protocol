<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Conformance Test Matrix

**Owner:** @projectmed99  
**Version:** 1.0 — 2026-05-28  
**Protocol:** Aroha 1.0  
**Status:** Initial draft — pending external implementer review

This matrix defines what it means to be "Aroha 1.0 conformant." Every row is a testable requirement. Pass/fail is binary.

---

## How to Read This Matrix

- **MUST** = required for any conformance claim
- **SHOULD** = strongly recommended; non-conformance must be documented
- **MAY** = optional extension
- **Pass criteria** = machine-verifiable condition
- **CI column** = whether this test runs in the reference CI suite
- **Row IDs** are stable test identifiers used by the conformance suite. Their `L0`–`L4` prefixes predate the specification's layer numbering and do not match it; each section heading names the specification layer (Layers 0–3) or extension the rows belong to.
- **Extension rows** apply only to implementations that adopt that extension ([Aroha 1.0 §11](../spec/aroha-1.0.md#11-conformance)).
- **Status codes** follow [Aroha 1.0 Appendix A](../spec/aroha-1.0.md#appendix-a--error-codes); the `code` string is normative and the HTTP status is a recommendation for HTTP transports.

---

## Identity (spec Layer 1)

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L0-01 | Agent generates a valid `did:aroha:` DID backed by Ed25519 keypair | MUST | DID resolves; public key in DID document matches keypair | ✅ |
| L0-02 | DID document conforms to W3C DID Core 1.0 | MUST | JSON-LD validation passes against W3C DID Core context | ✅ |
| L0-03 | Agent can rotate keys without changing DID | MUST | New keypair registered; old messages signed with prior key still verify against version at time of signing | ✅ |
| L0-04 | Agent rejects messages signed with unknown DID | MUST | Reject with 401; log reason | ✅ |
| L0-05 | Agent supports did:web as alternative DID method | MAY | did:web DID document resolves and passes L0-02 | — |

### Rotatable identifiers (`did:aroha:E…`) and Key Event Logs

Normative source: spec `did-method.md`, "Rotatable identifiers (E-form) and Key Event Logs". Tests: `packages/aroha-core/src/conformance/l0-kel-identity.conformance.test.ts` (run by `vitest.conformance.config.ts`).

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L0-KEL-01 | An E-DID is `did:aroha:E` + base58btc(sha256(JCS(inception event without `sig`))); events are signed over the same JCS bytes | MUST | Pinned vector reproduced exactly: from fixed seeds (current key seed `0x01…`, next key seed `0x02…`, `createdAt` 2026-10-07T00:00:00.000Z) the implementation produces the same canonical inception body, Ed25519 signature and DID, and the following rotation (next-next seed `0x03…`) has the same event digest | ✅ |
| L0-KEL-02 | An inception-only log verifies with no other input | MUST | `verifyKel(did, [inception])` succeeds and reports the inception's key as the current key — no registry, network or controller log consulted | ✅ |
| L0-KEL-03 | A rotation is valid only when signed by the pre-committed next key | MUST | The same rotate event body signed by the CURRENT key is rejected; signed by the revealed next key (whose digest the prior state committed to) it verifies | ✅ |
| L0-KEL-04 | Controller-authorised events (agent `recover`, controller `revoke`) are valid only when sealed in the controller person's KEL | MUST | An agent log with a controller revocation verifies (and reports `revoked`) when the controller's anchoring log is supplied; without it, verification fails with `controller-unavailable` | ✅ |
| L0-KEL-05 | A verifier that has accepted a log rejects a fork of it (duplicity) | MUST | After accepting one validly signed rotation into a KEL store, a different validly signed rotation at the same sequence is rejected with `duplicity` | ✅ |
| L0-KEL-06 | A verifier that has accepted a log does not accept a shorter one | SHOULD | After accepting a rotated log, offering the inception-only prefix is rejected with `stale` | ✅ |

---

## Messaging and transport (spec Layers 3 and 0)

Rows L1-01 to L1-05 cover signed envelopes (Layer 3, §6); L1-06 covers TLS (Layer 0, §3.4); L1-07 to L1-11 cover `aroha-sig` caller authentication (Layer 0, §3.5).

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L1-01 | Every outbound message is signed with sender's Ed25519 key | MUST | Signature verifies against sender DID document | ✅ |
| L1-02 | Receiver rejects messages with invalid signatures | MUST | Returns 401 (`Aroha_INVALID_SIGNATURE`); does not process payload | ✅ |
| L1-03 | Receiver rejects replayed messages (timestamp + nonce) | MUST | Second receipt of identical envelope returns 401 (`Aroha_REPLAY_DETECTED`) | ✅ |
| L1-04 | Envelope includes `expires` field set to a future timestamp; receiver rejects envelopes where `expires` is in the past | MUST | Expired envelopes rejected with 401 (`Aroha_EXPIRED_MESSAGE`); accepted nonces retained, keyed per sender, at least until `expires` (§6.3) | ✅ |
| L1-05 | Envelope schema validates against Aroha 1.0 message spec | MUST | JSON Schema validation passes | ✅ |
| L1-06 | Agent enforces TLS 1.3+ for all connections; plaintext HTTP connections are rejected | MUST | TLS 1.3 handshake succeeds; plaintext HTTP returns connection error or 400 | ✅ |
| L1-07 | An agent requiring `aroha-sig` rejects unsigned requests | MUST | Missing signature headers return 401; payload not processed; never downgraded to anonymous | ✅ |
| L1-08 | Signature covers method, path, timestamp, nonce and body hash | MUST | A signature captured from one endpoint fails on another; altering the body fails verification | ✅ |
| L1-09 | Caller DID is checked against the allow-list before key resolution | MUST | A non-allow-listed DID is rejected without a registry lookup — verified by the absence of a resolution call, not by timing alone | ✅ |
| L1-10 | Nonce is consumed only after all other checks pass | MUST | A request with a valid nonce and bad signature is rejected, and the same nonce is still accepted on a subsequent valid request | ✅ |
| L1-11 | Requests outside the clock-skew window are rejected | MUST | Timestamp older or newer than the permitted skew returns 401 | ✅ |

---

## Registry (spec Layer 2)

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L2-01 | Agent publishes capability manifest to registry on startup | MUST | Manifest retrievable via registry query within 30s of start | ✅ |
| L2-02 | Capability manifest includes: DID, capabilities[], endpoint, version | MUST | Schema validation passes | ✅ |
| L2-03 | Registry supports capability discovery by name and tag | MUST | Query returns matching agents within 500ms (p95) | ✅ |
| L2-04 | Agent deregisters from registry on graceful shutdown | SHOULD | Manifest no longer returned in queries within 30s | ✅ |
| L2-05 | Agent handles stale registry entries (TTL-based expiry) | SHOULD | Entries older than configured TTL are not returned | — |
| L2-06 | Registry supports pagination for large result sets | SHOULD | `cursor`-based pagination returns consistent pages | — |
| L2-07 | Records carry a visibility level (`public` \| `unlisted` \| `private`), defaulting to `public` | MUST | Record created without the field is discoverable exactly as before | ✅ |
| L2-08 | `private` records are absent from capability queries by non-entitled viewers | MUST | Anonymous and unrelated-credential queries omit the record; owner's query includes it | ✅ |
| L2-09 | Visibility filtering happens inside the retrieval query, not by post-filtering | MUST | Result counts and pagination boundaries are identical whether or not private records exist | — |
| L2-10 | No-access and does-not-exist are indistinguishable | MUST | Resolving a `private` record without entitlement returns the same status and body as resolving an unregistered `didHash` — never `403` | ✅ |
| L2-11 | An invalid discovery credential degrades to the anonymous view | MUST | Request with a malformed or unknown API key returns the public result set, not an auth error | ✅ |
| L2-12 | A live grant admits its grantee; a revoked or expired one does not | MUST | Grantee sees the record; after revocation or expiry the same request returns not-found | ✅ |
| L2-13 | At most one live grant per (resource, grantee), and re-granting after revocation succeeds | MUST | Duplicate grant rejected; grant → revoke → grant sequence succeeds | ✅ |

---

## Extension: Orchestration (sagas)

Applies only to implementations that adopt the orchestration extension ([extensions document](../spec/extensions.md) §1, §3). Formerly numbered Layer 4 in the specification.

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L3-01 | Saga coordinator sends `Reserve` before `Commit` | MUST | `Reserve` step logged before any `Commit` issued | ✅ |
| L3-02 | On participant failure, coordinator issues `Cancel` to all committed participants | MUST | All prior `Commit` recipients receive `Cancel` within timeout | ✅ |
| L3-03 | `Cancel` is idempotent | MUST | Duplicate `Cancel` for same saga ID returns success without side effects | ✅ |
| L3-04 | Saga ID is globally unique (UUID v4 or equivalent) | MUST | No two concurrent sagas share an ID | ✅ |
| L3-05 | Participant enforces timeout on `Reserve` (releases lock if no `Commit` within TTL) | MUST | Lock released after TTL; subsequent `Reserve` succeeds | ✅ |
| L3-06 | Saga state is persisted durably (survives coordinator restart) | SHOULD | After restart, in-progress sagas resume or cancel cleanly | — |
| L3-07 | Agent reports saga metrics (success rate, rollback count) via telemetry | SHOULD | Metrics endpoint returns current saga KPIs | — |

---

## Extension: Commerce and settlement

Applies only to implementations that adopt the commerce or settlement extensions ([Aroha 1.0 §2](../spec/aroha-1.0.md#2-protocol-layers)).

| ID | Requirement | Level | Pass Criteria | CI |
|----|-------------|-------|---------------|----|
| L4-01 | Payment envelope includes: amount, currency, recipient DID, saga ID | MUST | Schema validation passes | ✅ |
| L4-02 | Payment amount is non-negative | MUST | Negative amounts rejected with 400 | ✅ |
| L4-03 | Payment is refunded on saga rollback | MUST | Refund issued to payer DID after `Cancel` | ✅ |
| L4-04 | Agent rejects duplicate payment for same saga ID | MUST | Second payment attempt returns 409 | ✅ |
| L4-05 | Agent supports USD and at least one additional currency | SHOULD | Currency code in payment envelope is validated | — |
| L4-06 | Agent can emit signed payment receipt | SHOULD | Receipt verifiable against payee DID | — |

---

## Pass/Fail Rubric

**Conformant:** All applicable MUST rows pass (core rows, plus the rows of every extension the implementation adopts). SHOULD failures are documented.  
**Non-conformant:** Any applicable MUST row fails.  
**Provisional:** MUST rows pass but SHOULD rows are untested — must resolve within 90 days.

---

## Scoring

| Grade | Criteria |
|-------|----------|
| Full conformance | All MUST + all SHOULD pass |
| Core conformance | All MUST pass; ≥50% of SHOULD pass |
| Provisional | All MUST pass; SHOULD untested |
| Non-conformant | Any MUST fails |

---

*To validate your implementation: see [implementer-packet.md](implementer-packet.md).*
