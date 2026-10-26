<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Aroha Protocol Conformance Tiers

Three tiers let implementers declare exactly which parts of the protocol they support.
Layer numbers below are the specification's Layers 0–3 (Transport, Identity, Registry,
Messaging; [Aroha 1.0 §2](../spec/aroha-1.0.md#2-protocol-layers)). Orchestration (sagas),
preference context, commerce and settlement are extensions, not layers.

## Tier 1 — Aroha-Minimal (Layers 0, 1 and 3)

**What it means:** The implementation can send and receive cryptographically signed
Aroha messages. No registry, no saga, no settlement required.

**Required:**
- ✅ L0: Serve `/.well-known/aroha-agent.json`
- ✅ L0: Accept `POST /aroha/v1` with JSON body
- ✅ L1: Generate `did:aroha:` DID with Ed25519 keypair
- ✅ L3: Sign outbound envelopes (Ed25519Signature2020)
- ✅ L3: Verify inbound envelope signatures
- ✅ L3: Reject replayed nonces
- ✅ L3: Reject expired envelopes

**Claim it with:** state the tier in your README or ecosystem submission. *(Planned — not implemented: an `X-Aroha-Conformance: minimal` response header. No Aroha package emits or checks this header today.)*

**Use case:** Simple request/response integrations, internal service mesh agents.

---

## Tier 2 — Aroha-Standard (Layers 0–3)

**What it means:** The implementation implements the whole core protocol, including
capability discovery through a registry.

**Required:** Everything in Tier 1, plus:
- ✅ L2: Publish signed capability manifest
- ✅ L2: Register on an Aroha registry (HTTP or EVM)

**Claim it with:** state the tier in your README or ecosystem submission. *(Planned — not implemented: an `X-Aroha-Conformance: standard` response header. No Aroha package emits or checks this header today.)*

**Use case:** Production provider agents (e.g. FlightAgent, StripeAgent) that are
discoverable through a registry.

---

## Tier 3 — Aroha-Full (Layers 0–3 plus the extensions)

**What it means:** The implementation supports the core protocol plus the orchestration,
preference context, commerce and settlement extensions.

**Required:** Everything in Tier 2, plus:
- ✅ Orchestration extension: Handle `ArohaReserve` → `ArohaReserveAck`
- ✅ Orchestration extension: Handle `ArohaCommit` → `ArohaCommitAck`
- ✅ Orchestration extension: Handle `ArohaCancel` → `ArohaCancelAck`
- ✅ Orchestration extension: Commit and Cancel are idempotent
- ✅ Commerce / settlement extensions: `B2BAgreement` / `B2CServiceTerms` or `NullSettlement` declared in manifest
- ✅ Commerce / settlement extensions: Return `SettlementOutcome` in commit acknowledgements
- ✅ Preference context extension: Keep `ArohaSatisfactionSignal` in the orchestrator's own preference store, never sent to providers ([extensions document](../spec/extensions.md) §2.3)
- ✅ L3: Honour `ArohaSpendingMandate` budget constraints (§6.5)

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
[partner-onboarding-kit.md](../ecosystem/partner-onboarding-kit.md) for the current partner process.
