<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Guarantee–Evidence Map

Every guarantee the Aroha Protocol makes, mapped to the function that enforces
it in the reference implementation and the published test that proves it.

**Where to check:** every referenced source file ships inside the
Apache-2.0-licensed npm tarballs (`npm pack @aroha-sdk/credentials
@aroha-sdk/delegation @aroha-sdk/mcp-guard`, then read `src/`). The tests
cited as proof live beside them in the public repository
(`packages/<name>/src/*.test.ts`); tarballs no longer carry them, so that
installed packages contain only what runs. Anchors are *file + function* (never line numbers, which rot).
Server-side guarantees cite this spec rather than private infrastructure code —
the distinction is marked, not blurred.

## Authority can only narrow

| Guarantee | Enforced at | Proven by |
|---|---|---|
| A delegated spending limit can never exceed its parent's | `@aroha-sdk/credentials` · `mandate.ts` · `assertNarrowing()` | `mandate.test.ts` · "rejects spendLimitUsd widening" |
| A delegated task scope is a strict subset of the parent's | `@aroha-sdk/credentials` · `mandate.ts` · `assertTaskNarrowing()` | `chain.test.ts` · "rejects a scope widened mid-chain" |
| A blocked capability stays blocked down a chain (task mandates — spending mandates carry no capability list) | `@aroha-sdk/delegation` · `chain.ts` · `verifyTaskMandateChain()` | `chain.test.ts` · "rejects a dropped blocked capability" |
| N children cannot multiply a parent budget | `@aroha-sdk/credentials` · `spending-ledger.ts` · `SpendingLedger.allocate()` → `BudgetExhaustedError` | `mandate.test.ts` · "rejects allocation that would exceed parent limit" |

## Tokens cannot be forged, replayed, or redirected

| Guarantee | Enforced at | Proven by |
|---|---|---|
| Tampering with any field breaks the token | `@aroha-sdk/credentials` · `mandate.ts` · `verifyMandate()` / `verifyTaskMandate()` (Ed25519 over canonicalised JSON) | `chain.test.ts` · "rejects a tampered token" |
| A mandate binds exactly one grantee | `verifyTaskMandate(expectedGrantee)` | `mandate.test.ts` · "rejects grantee mismatch" |
| Mandates expire | expiry checks in both verifiers; chain-level containment in `@aroha-sdk/credentials` · `mandate.ts` · `verifyMandateChain()` | `mandate.test.ts` · "rejects an expired mandate"; `mandate-chain.test.ts` · "rejects when an ancestor has expired" |
| Rotated-out keys cannot sign; rotation cannot be replayed | Registry (server-side): atomic nonce consumption, 5-minute freshness window, self-signature by the outgoing key | [`spec/did-method.md` · §Update](../spec/did-method.md); [test-matrix](test-matrix.md) |

## Chains of custody cannot be spliced

| Guarantee | Enforced at | Proven by |
|---|---|---|
| grantor(i) = grantee(i−1), with `parentMandateId` continuity | `@aroha-sdk/credentials` · `mandate.ts` · `verifyMandateChain()` (spending mandates); `@aroha-sdk/delegation` · `chain.ts` · `verifyTaskMandateChain()` (task mandates) | `mandate-chain.test.ts` · "rejects a child whose grantor is not the parent's grantee", "rejects a child whose parentMandateId does not name the parent"; `chain.test.ts` · "rejects broken grantor→grantee custody" |
| Hops cannot be impersonated (per-link signer resolution) | `@aroha-sdk/credentials` · `mandate.ts` · `verifyMandateChain()` + `MandateKeyResolver` (spending); `@aroha-sdk/delegation` · `verifyTaskMandateChain()` + `resolvePublicKey` (task) | `mandate-chain.test.ts` · "rejects a forged child under a valid parent (signed by someone other than the grantor)"; `chain.test.ts` · "rejects a child signed by the wrong key (impersonated hop)" |
| Untrusted root issuers are rejected at the door | `@aroha-sdk/delegation` · `serve-delegated.ts` · `verifyRequest()` (trust-anchor pinning) | `examples/delegation-web/demo.mjs` · scenario 3 (forged root → HTTP 400) |

## Recursion has a floor

| Guarantee | Enforced at | Proven by |
|---|---|---|
| `maxDelegationDepth` strictly decrements; depth 0 is a dead end | `chain.ts` (chain rule) + `serve-delegated.ts` · `delegate()` (refuses before signing) | `chain.test.ts` · three depth tests ("…maxDelegationDepth=0", "…fails to decrement depth", "…omits depth when the parent bounds it") |

## The tool plane fails closed

| Guarantee | Enforced at | Proven by |
|---|---|---|
| Precedence is fixed (block > limit > gate); a zero limit denies immediately | `@aroha-sdk/mcp-guard` · `engine.ts` · `GuardEngine.decide()` | `engine.test.ts` · "applies precedence block > limit > gate", "a zero limit denies immediately" |
| Unanswered or unsupported approval prompts deny, never allow | `proxy.ts` · `requestApproval()` (timeout → deny) and `resolveGate()` (client error → deny) | deny is the only default path in `proxy.ts`; rule engine covered by the 17-test suite |

---

*Motivated in part by the scatter problem documented in Wang et al., "Harness
Handbook" (arXiv:2607.13285, 2026): a single permission behavior spread across
2,267 files of a production harness. Chokepoint enforcement is our
architectural answer; this table is our evidence discipline.*
