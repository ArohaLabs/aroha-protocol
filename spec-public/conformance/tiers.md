<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol Conformance Tiers

Three tiers let implementers declare exactly which parts of the protocol they support.

## Tier 1 — Aroha-Minimal (Layers 0–1)

**What it means:** The implementation can send and receive cryptographically signed
Aroha messages. No registry, no saga, no settlement required.

**Required:**
- ✅ L0: Serve `/.well-known/aroha-agent.json`
- ✅ L0: Accept `POST /aroha/v1` with JSON body
- ✅ L1: Generate `did:aroha:` DID with Ed25519 keypair
- ✅ L1: Sign outbound envelopes (Ed25519Signature2020)
- ✅ L1: Verify inbound envelope signatures
- ✅ L1: Reject replayed nonces
- ✅ L1: Reject expired envelopes

**Claim it with:** `X-Aroha-Conformance: minimal` response header.

**Use case:** Simple request/response integrations, internal service mesh agents.

---

## Tier 2 — Aroha-Standard (Layers 0–3)

**What it means:** The implementation participates fully in capability discovery and
atomic multi-agent sagas.

**Required:** Everything in Tier 1, plus:
- ✅ L2: Publish signed capability manifest
- ✅ L2: Register on an Aroha registry (HTTP or EVM)
- ✅ L3: Handle `ArohaReserve` → `ArohaReserveAck`
- ✅ L3: Handle `ArohaCommit` → `ArohaCommitAck`
- ✅ L3: Handle `ArohaCancel` → `ArohaCancelAck`
- ✅ L3: Commit and Cancel are idempotent

**Claim it with:** `X-Aroha-Conformance: standard` response header.

**Use case:** Production provider agents (e.g. FlightAgent, StripeAgent) that
participate in multi-agent orchestration.

---

## Tier 3 — Aroha-Full (Layers 0–5)

**What it means:** The implementation supports the complete protocol stack including
commerce agreements, preference signals, and settlement.

**Required:** Everything in Tier 2, plus:
- ✅ L4: `B2BAgreement` / `B2CServiceTerms` or `NullSettlement` declared in manifest
- ✅ L4: Return `SettlementOutcome` in commit acknowledgements
- ✅ L5: Accept `ArohaSatisfactionSignal` and update reputation
- ✅ L5: Honour `ArohaSpendingMandate` budget constraints

**Claim it with:** `X-Aroha-Conformance: full` response header.

**Use case:** Enterprise provider agents with billing, compliance, and reputation requirements.

---

## Self-Certification

Run the conformance test suite at the appropriate tier:

```bash
# Tier 1
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=minimal

# Tier 2
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=standard

# Tier 3 (full)
npx vitest run --config vitest.conformance.config.ts --reporter=json -- --tier=full
```

A passing run produces `conformance-results.json`. Include this file in your README
or ecosystem registry submission.

## Verified Partner Badge

Agents operated by Aroha Labs verified partners receive a `verified-partner` flag in
the registry. This bootstraps reputation for new agents from trusted organizations.
See `docs/ecosystem/partner-onboarding.md` for the verification process.
