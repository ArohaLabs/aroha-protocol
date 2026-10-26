<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# GDPR Compliance Guide for Aroha Protocol

## TL;DR

| Data | Where it lives | GDPR risk | Recommendation |
|---|---|---|---|
| Capability manifests | IPFS (immutable) | Low — no PII if designed correctly | Never include PII in manifests |
| Verifiable Credentials | Off-chain (your DB) | High — may contain personal data | Store in your DB, only IPFS-hash the schema |
| Saga logs | In-memory / your DB | Medium — may contain booking/PII | Your DB, with retention policy |
| DID Documents | IPFS + on-chain | Low — public keys only | No PII in DID Documents |
| Reputation scores | On-chain (EVM) | Low — aggregated scores, no PII | Scores are not personal data |

## Rule 1: Capability Manifests Must Never Contain PII

Capability manifests are published to IPFS, which is **content-addressed and permanent**.
Once published, a manifest with PII cannot be deleted.

✅ Correct:
```json
{ "name": "book-flight", "description": "Reserve a commercial flight" }
```

❌ Wrong:
```json
{ "name": "book-flight", "allowedUsers": ["alice@example.com"] }
```

## Rule 2: Verifiable Credentials Stay Off-Chain

Credentials contain personal claims (`merchantTier`, `spendLimit`, named individuals).
Store them in your database. Only register a schema hash on-chain.

When a user invokes Article 17 (right to erasure):
1. Delete the credential record from your database.
2. The on-chain schema hash is not personal data — no on-chain deletion needed.
3. Revoke what you issued. A human credential held in a `CredentialRegistry` is revoked with `DELETE /aroha/credentials/:id` and an `X-Revoke-Proof` header on the agent that hosts it (see [RBAC & Human Credentials](../reference/rbac.md)). A spending mandate is revoked on the registry (`apps/registry-server`) with `POST /v1/mandates/:mandateId/revoke`.

## Rule 3: Saga Logs Are Your Responsibility

Saga logs produced by `@aroha-sdk/orchestrator` are in-memory by default.
If you persist them:
- Apply a data retention policy (e.g. delete after 90 days)
- Pseudonymise where possible (store DID, not name/email)
- Include in your DPIA (Data Protection Impact Assessment)

## Rule 4: Data Residency

This guide makes no claim about where the reference HTTP registry deployment (`https://aroha-registry.aroha-labs.workers.dev`) stores or processes data.
If you have data-residency requirements, self-host the registry (`apps/registry-server`) in a location you choose.
The EVM registry is globally distributed — do not put PII in transaction data.

## Lawful Basis

Agent-to-agent communication typically falls under **legitimate interests** (Art. 6(1)(f))
or **contract performance** (Art. 6(1)(b)). Consult your DPO for your specific use case.

## Resources

- [W3C DID Privacy Considerations](https://www.w3.org/TR/did-core/#privacy-considerations)
- [IPFS and the Right to Erasure](https://gdpr.eu/right-to-be-forgotten/)
- Open an issue at github.com/ArohaLabs/aroha-protocol for GDPR questions
