<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Post-Quantum Migration

Aroha is designed for a **no-flag-day migration** to NIST post-quantum standards
(FIPS 204 ML-DSA, FIPS 205 SLH-DSA, FIPS 206 ML-KEM).

---

## Design principle

The signing surface is isolated to two files:

```
packages/aroha-core/src/crypto/signing.ts   — Ed25519 sign/verify
packages/aroha-core/src/identity/did.ts     — keypair generation
```

All callers (`buildEnvelope`, `validateEnvelope`, credential issuance) are unchanged.
Migrating to a PQ algorithm requires modifying only these two files plus the DID Document format.

---

## Migration procedure

### Step 1 — Add PQ key to DID Document

Add a second `verificationMethod` alongside the existing Ed25519 key.
Legacy agents ignore unknown key types.

```json
{
  "verificationMethod": [
    {
      "id": "did:aroha:my-agent#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aroha:my-agent",
      "publicKeyMultibase": "z<base58btc-32-bytes>"
    },
    {
      "id": "did:aroha:my-agent#key-2-pq",
      "type": "Mldsa44VerificationKey2025",
      "controller": "did:aroha:my-agent",
      "publicKeyMultibase": "u<base64url-pq-public-key>"
    }
  ],
  "authentication": [
    "did:aroha:my-agent#key-1",
    "did:aroha:my-agent#key-2-pq"
  ]
}
```

### Step 2 — Dual-sign envelopes

During the transition window, sign envelopes with both Ed25519 and the PQ key.
Add a `proofs` array alongside the existing `proof`:

```json
{
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:aroha:my-agent#key-1",
    "proofValue": "..."
  },
  "proofs": [
    {
      "type": "Mldsa44Signature2025",
      "verificationMethod": "did:aroha:my-agent#key-2-pq",
      "proofValue": "..."
    }
  ]
}
```

### Step 3 — Update the signing module

In `packages/aroha-core/src/crypto/signing.ts`, swap the import:

```typescript
// Before (Ed25519):
import * as ed from "@noble/ed25519";
export const sign   = (data: Uint8Array, key: Uint8Array) => ed.signAsync(data, key);
export const verify = (sig: Uint8Array, data: Uint8Array, key: Uint8Array) => ed.verifyAsync(sig, data, key);

// After (ML-DSA-44 / FIPS 204):
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa";
export const sign   = (data: Uint8Array, key: Uint8Array) => ml_dsa44.sign(key, data);
export const verify = (sig: Uint8Array, data: Uint8Array, key: Uint8Array) => ml_dsa44.verify(key, data, sig);
```

### Step 4 — Transition window

Run dual-signing for a minimum of **7 days** (or until all known peers have upgraded).
During this window:
- New agents verify PQ signatures if present; fall back to Ed25519
- Legacy agents verify Ed25519 only; ignore `proofs`

### Step 5 — Deprecate Ed25519

After the transition window:
1. Remove Ed25519 key from DID Document
2. Stop dual-signing — emit PQ proof only
3. Remove Ed25519 verification method from `ArohaServer`

---

## Key size comparison

| Algorithm | Public key | Signature | Security level |
|-----------|-----------|-----------|---------------|
| Ed25519 (current) | 32 bytes | 64 bytes | 128-bit classical |
| ML-DSA-44 (FIPS 204) | 1,312 bytes | 2,420 bytes | NIST Level 2 (128-bit PQ) |
| ML-DSA-65 (FIPS 204) | 1,952 bytes | 3,293 bytes | NIST Level 3 (192-bit PQ) |
| SLH-DSA-128s (FIPS 205) | 32 bytes | 7,856 bytes | NIST Level 1 (128-bit PQ, small key) |

ML-DSA-44 is the recommended migration target — it offers a reasonable tradeoff between
key/signature size and NIST Level 2 post-quantum security.

---

## Recommended library

```bash
npm install @noble/post-quantum
```

`@noble/post-quantum` (by the same team as `@noble/ed25519`) provides audited
implementations of ML-DSA, SLH-DSA, and ML-KEM with the same ergonomics as the
current crypto library.
