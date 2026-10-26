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

**Claim it with:** state the tier in your README or ecosystem submission. *(Planned — not implemented: an `X-Aroha-Conformance: minimal` response header. No Aroha package emits or checks this header today.)*

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

**Claim it with:** state the tier in your README or ecosystem submission. *(Planned — not implemented: an `X-Aroha-Conformance: standard` response header. No Aroha package emits or checks this header today.)*

**Use case:** Production provider agents (e.g. FlightAgent, StripeAgent) that
participate in multi-agent orchestration.

---

## Tier 3 — Aroha-Full (Layers 0–3 plus the extensions)

**What it means:** The implementation supports the complete protocol stack including
commerce agreements, preference signals, and settlement.

**Required:** Everything in Tier 2, plus:
- ✅ L4: `B2BAgreement` / `B2CServiceTerms` or `NullSettlement` declared in manifest
- ✅ L4: Return `SettlementOutcome` in commit acknowledgements
- ✅ L5: Accept `ArohaSatisfactionSignal` and update reputation
- ✅ L5: Honour `ArohaSpendingMandate` budget constraints

**Claim it with:** state the tier in your README or ecosystem submission. *(Planned — not implemented: an `X-Aroha-Conformance: full` response header. No Aroha package emits or checks this header today.)*

**Use case:** Enterprise provider agents with billing, compliance, and reputation requirements.

---

## Self-Certification

> **Planned — not implemented:** per-tier test selection. The conformance suite has no `--tier`
> option today, and no code reads one; the commands previously shown here with `-- --tier=...` did
> not filter anything.

Today, run the whole conformance suite and report the result for the rows your tier requires
(see [test-matrix.md](test-matrix.md)):

```bash
npx vitest run --config vitest.conformance.config.ts --reporter=json --outputFile=conformance-results.json
```

A passing run produces `conformance-results.json`. Include this file, together with the list of
test IDs that apply to your claimed tier, in your conformance report or ecosystem registry
submission.

## Verified Partner Badge

*Planned — not implemented.* The intent is that agents operated by verified partners receive a
`verified-partner` flag in the registry to bootstrap reputation for new agents from trusted
organizations. No registry code sets or reads such a flag today. See
[partner-onboarding-kit.md](../../docs/ecosystem/partner-onboarding-kit.md) for the current partner process.
