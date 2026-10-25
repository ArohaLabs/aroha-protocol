<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# did:aroha-web: — Two-Factor Web Identity

`did:aroha-web:` is Aroha's web-native DID method. It anchors an agent's
public key to a domain through two independent verification channels — HTTPS
**and** DNS — so control of one channel alone (the web server, its TLS
certificate, or the DNS zone) is not enough to substitute a key.

The reference implementation is `@aroha-sdk/core` · `identity/web-did.ts`
(`generateWebAgent`, `rotateKey`, `resolveWebDID`, `selectWebDIDKey`). Where
this document and that code disagree, file an issue — they are meant to be
identical, and the conformance tests in
`identity/web-did-chain.test.ts` pin the rules below.

## Why Two Factors?

| Method | Single-factor surface |
|--------|-----------------------|
| `did:web:` (W3C) | HTTPS only — control of the web origin is enough |
| `did:wba:` (ANP) | HTTPS only — same single-factor weakness |
| **`did:aroha-web:`** | **Requires BOTH the web origin AND the DNS TXT record** |

---

## DID Format

```
did:aroha-web:{domain}[:{path}]
```

| Component | Example |
|-----------|---------|
| `domain`  | `stripe.com` |
| `path`    | `payments-agent` (defaults to `agent` when omitted; further `:` segments map to `/`) |
| **DID**   | `did:aroha-web:stripe.com:payments-agent` |

---

## Factor 1 — HTTPS document

```
GET https://{domain}/.well-known/aroha/agents/{path}/did.json
```

Returns a **WebDIDDocument**: a standard DID Document plus an `arohaWeb` block.
The document's `id` MUST equal the requested DID.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://aroha-labs.com/contexts/aroha-web/v1"
  ],
  "id": "did:aroha-web:stripe.com:payments-agent",
  "verificationMethod": [
    {
      "id": "did:aroha-web:stripe.com:payments-agent#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aroha-web:stripe.com:payments-agent",
      "publicKeyMultibase": "z… (base58btc of the 32-byte Ed25519 public key)"
    }
  ],
  "authentication":  ["did:aroha-web:stripe.com:payments-agent#key-1"],
  "assertionMethod": ["did:aroha-web:stripe.com:payments-agent#key-1"],
  "keyAgreement":    ["did:aroha-web:stripe.com:payments-agent#key-1"],
  "service": [
    { "id": "did:aroha-web:stripe.com:payments-agent#aroha", "type": "ArohaEndpoint",
      "serviceEndpoint": "https://stripe.com/aroha/v1" }
  ],
  "created": "2026-05-01T00:00:00.000Z",
  "updated": "2026-05-01T00:00:00.000Z",
  "arohaWeb": {
    "domain": "stripe.com",
    "path": "payments-agent",
    "keyCommitmentHash": "SHA-256 hex of the PRIMARY key's 32 bytes",
    "keyHistory": []
  }
}
```

- `verificationMethod[0]` is the **primary** key — the one rotations replace.
  Further entries are additional (e.g. device) keys; rotation never touches them.
- `arohaWeb.keyCommitmentHash`, when present, MUST equal the SHA-256 hex of the
  primary key. A mismatch is a resolution error.
- `arohaWeb.keyHistory` is the rotation chain, **newest first** (below).

## Factor 2 — DNS TXT key-commitment

```
_aroha.{domain} IN TXT "v=aroha1; path={path}; keyhash={sha256hex}"
```

| Field | Description |
|-------|-------------|
| `v`   | Protocol version. Must be `aroha1`. |
| `path` | Must equal the DID's path. Records for other paths are ignored. |
| `keyhash` | SHA-256 hex of an Ed25519 public key's 32 raw bytes. |

A domain MAY publish several records (several paths, or several keys for one
path — e.g. an additional device key, or the old and new key during a
rotation).

---

## Rotation records

```json
{
  "v": 2,
  "did": "did:aroha-web:stripe.com:payments-agent",
  "rotatedAt": "2026-06-01T00:00:00.000Z",
  "trustAfter": "2026-06-02T00:00:00.000Z",
  "predecessorKey": "z… multibase of the key being replaced",
  "newKeyHash": "SHA-256 hex of the replacing key",
  "predecessorSignature": "base64url Ed25519 signature by predecessorKey"
}
```

**Signed bytes (v2).** `predecessorSignature` covers the RFC 8785 (JCS)
canonical form of

```json
{ "did": …, "newKeyHash": …, "predecessorKey": …, "rotatedAt": …, "trustAfter": …, "v": 2 }
```

(`rotationSigningPayload` in `identity/did.ts`). Binding `did` stops a record
signed for one identity from being replayed into another identity that reuses
the key; binding `trustAfter` stops whoever serves the document from
shortening a genuine rotation's cool-down.

**Legacy v1 (deprecated).** A record without `v` is v1: its signature covers
only the string concatenation `predecessorKey + newKeyHash + rotatedAt`.
Resolvers MUST still verify v1 records (documents published before v2 keep
resolving) but MUST report them as deprecated, and MUST treat a v1 record's
unsigned `trustAfter` as no earlier than `rotatedAt + 24h`. New records MUST
be v2. The same record format and payload are used by `did:aroha` key
rotation (`rotateDIDKey`, `verifyDIDKeyChange`).

---

## Resolution algorithm

1. **Fetch** the document over HTTPS. `id` MUST equal the DID.
2. **Verify the chain.** With `H = keyHistory` (newest first) and `K` the
   primary key:
   - `H[0].newKeyHash = sha256(K)`;
   - `H[i].newKeyHash = sha256(H[i-1].predecessorKey)` for every `i ≥ 1`;
   - every record's signature verifies under its own `predecessorKey`;
     a v2 record's `did` equals the DID;
   - `rotatedAt` does not increase down the list.

   Any failure is a resolution **error** — a history that does not chain is
   not a rotation, it is unrelated keys.
3. **DNS anchor.** Read `_aroha.{domain}` TXT. The *anchor* is the **newest**
   key in the chain `[H[n-1].predecessorKey, …, H[0].predecessorKey, K]`
   whose hash appears in a record for this path. No anchor → `dnsVerified =
   false` and **no key is accepted** (fail closed).

   This is what makes stripping `keyHistory` useless: a document reduced to
   just the new key no longer chains to the key DNS still names, so nothing
   is accepted.
4. **Accepted keys.**
   - Anchor is `K` (DNS already names the new key): accept `K`. While
     `now < trustAfter` of `H[0]`, ALSO accept `H[0].predecessorKey` —
     graceful cutover; both keys verify during the cool-down.
   - Anchor is an older key: starting at the anchor, step to each newer key
     only once its own rotation's cool-down has passed; accept the key
     reached. A key DNS has not endorsed is **never** accepted early: the
     cool-down is the owner's window to notice a rotation made with a stolen
     key and answer it by publishing a new DNS commitment (which then
     matches nothing in the attacker's chain).
   - Additional (non-primary) methods are accepted only if DNS commits to
     each one's hash.
5. **Key selection.** A signature's proof names a `verificationMethod` id;
   verify against the accepted key(s) for that id (`webDIDPublicKeys` /
   `selectWebDIDKey`). During a cutover the primary id has two accepted keys,
   and a signature by either verifies.

`keyTrusted` in the result means: the **current** primary key is accepted
and past its cool-down. `dnsVerified` means: a DNS commitment anchored the
chain.

### No DNS available — fail closed

DNS is the second factor. A resolver with no way to read TXT records MUST
NOT silently fall back to HTTPS-only. The reference implementation throws
unless the caller passes `allowNoDns: true` (or the legacy `verifyDNS:
false`), which is for tests and local development, is logged, and yields
`dnsVerified: false` — callers that need two factors (e.g. the commerce
legal-entity binding) reject such results.

---

## Key rotation flow

1. Generate a new key pair.
2. The old key signs a v2 rotation record (`rotateKey(agent, coolDownHours)`).
3. Prepend it to `arohaWeb.keyHistory`; replace `verificationMethod[0]`'s key
   and `keyCommitmentHash`.
4. Publish the updated document.
5. Update the DNS TXT `keyhash` to the new key (optionally keep the old record
   until the cool-down ends).
6. Until DNS is updated, resolvers accept the old key, then the new key once
   the cool-down passes. Once DNS names the new key, both keys are accepted
   until the cool-down passes, then only the new one.

---

## Quick-Start (TypeScript)

```typescript
import {
  generateWebAgent, rotateKey, resolveWebDID, selectWebDIDKey,
  wellKnownPath,
} from "@aroha-sdk/core";
import { resolveTxt } from "node:dns/promises";

// ── Agent setup ────────────────────────────────────────────────────────────
const agent = await generateWebAgent("stripe.com", "payments-agent");
// agent.did === "did:aroha-web:stripe.com:payments-agent"
serveJson(wellKnownPath(agent.did), agent.webDocument);
// Publish: _aroha.stripe.com IN TXT "<agent.dnsTXTRecord>"

// ── Key rotation ───────────────────────────────────────────────────────────
const rotated = await rotateKey(agent, 24);          // 24-hour cool-down
serveJson(wellKnownPath(rotated.did), rotated.webDocument);
// Then publish rotated.dnsTXTRecord

// ── Resolution ─────────────────────────────────────────────────────────────
const result = await resolveWebDID("did:aroha-web:stripe.com:payments-agent", {
  dnsResolver: async (domain) => (await resolveTxt(`_aroha.${domain}`)).map((r) => r.join("")),
});
if (result.dnsVerified) {
  const key = selectWebDIDKey(result, proof.verificationMethod); // throws if not accepted
}
```

### SDK status

The TypeScript SDK is the reference. The Python, Go and Java `web_did`
modules predate this revision (flat document schema, v1-style payloads) and
are **not yet interoperable** with it; until they are updated, do not mix
SDKs for `did:aroha-web` issuance and verification.

---

## Serving the Well-Known Document

```typescript
const server = new ArohaServer({
  agentDID:       agent.did,
  didDocument:    agent.document,
  webDIDDocument: agent.webDocument,   // serves /.well-known/aroha/agents/{path}/did.json
  port: 3000,
  // ...
});
```

The server serves the document with `no-cache` headers so resolvers always
see the freshest key.

---

## Comparison with Other DID Methods

| Feature | `did:web:` | `did:wba:` (ANP) | **`did:aroha-web:`** |
|---------|-----------|-----------------|---------------------|
| Transport | HTTPS | HTTPS | HTTPS + DNS TXT |
| Channels to control | 1 | 1 | **2** |
| Key rotation | No built-in | No built-in | **Signed chain + cool-down** |
| Rotation proof | None | None | **DID-bound predecessor signature** |
