<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# SDK Feature Matrix

This matrix comes from reading the source of each SDK in this repository on
**2026-10-08**, updated **2026-10-19** for task mandates, the conversation profile and the registry client in Go and Java. It records what the code does, not what we plan. If you change
an SDK, update this page in the same PR.

**Summary:** TypeScript is the reference implementation. Python is beta. Go and
Java are **partial**. All four implement the envelope with the hardened
validation rules, v2 mandate tokens with full chain verification, and E-DID /
Key Event Log verification, each tested against the shared vectors in
`packages/aroha-credentials/test-vectors/mandate-v2.json` (plus cross-language
interop tests). Task mandates, conversation-profile verification and the
registry client are now in all four SDKs, with task-mandate vectors
(`task-mandate-v2.json`, `task-mandate-v2-cases.json`) and live interop in both
directions against TypeScript. Not yet outside TypeScript: multi-hop task-chain
verification (`@aroha-sdk/delegation`), task receipts and disputes. All four
SDKs define the same 19 message types and 28 error codes. `did:aroha-web` in Python, Go and Java is a port of the
TypeScript resolver, checked against a TypeScript-generated vector. Each SDK's
README is the source of truth at a given commit.

| Feature | TypeScript | Python | Go | Java |
|---|:---:|:---:|:---:|:---:|
| Package | `@aroha-sdk/core`, `@aroha-sdk/credentials`, `@aroha-sdk/registry` (npm) | `aroha` (PyPI) | module `github.com/ArohaLabs/aroha-protocol/sdks/go` — **not released**: no `sdks/go/v*` tag; build from source | `com.aroha-labs:aroha-sdk` — **not released** (not on Maven Central); build from source |
| Maturity | Reference | Beta | Partial | Partial |
| Envelope build + Ed25519 sign | ✅ | ✅ | ✅ | ✅ |
| Envelope verify (signature, expiry, nonce replay) | ✅ | ✅ | ✅ | ✅ |
| Intent / cart / payment mandates: issue + verify | ✅ (v2) | ✅ (v2) | ✅ (v2) | ✅ (v2) |
| Mandate **chain** verification | ✅ (`verifyMandateChain`, `@aroha-sdk/credentials`) | ✅ (`verify_mandate_chain`) | ✅ (`VerifyMandateChain`) | ✅ (`verifyMandateChain`) |
| Mandate token **v2** wire format (JCS of `{mandate, v: 2}`, embedded chain, required `issuedAt`) | ✅ | ✅ | ✅ | ✅ |
| Envelope validation rules (5-min max TTL, `created` skew check, signature before nonce, per-sender nonce keys) | ✅ | ✅ | ✅ | ✅ |
| Rotatable DIDs (`did:aroha:E…`) and Key Event Log verification | ✅ | ✅ | ✅ | ✅ |
| `did:aroha-web` (current schema) | ✅ | ✅ | ✅ | ✅ |
| Task mandates (issue, attenuate, verify, enforce) | ✅ | ✅ (`aroha.task_mandate`) | ✅ (`mandate.IssueTaskMandate`, `EnforceTaskConstraints`) | ✅ (`TaskMandate`) |
| Saga (Reserve → Commit → Cancel, compensation) — orchestration extension | ✅ (`@aroha-sdk/orchestrator` 1.4.0 on npm; source no longer in this repository) | ✅ | ✅ | ✅ |
| Registry client (register / discover / resolve) | ✅ (`@aroha-sdk/registry`) | ✅ (`aroha.hub`, HTTP) | ✅ (`registry`) | ✅ (`ArohaRegistryClient`) |
| Conversation profile verification (rooms, consent, turns, disclosure, action receipts) | ✅ | ✅ (`aroha.conversation`) | ✅ (`conversation`, `receipts`) | ✅ (`conversation`) |
| Task-mandate interop with TypeScript (shared vectors `task-mandate-v2.json` / live both directions) | — | ✅ | ✅ | ✅ |
| Durable stores: nonces, enrollment, spending ledger (Postgres, Redis) | ✅ (`@aroha-sdk/store-postgres`, `@aroha-sdk/store-redis`; unreleased) | ✅ (`aroha.stores`; unreleased) | ❌ | ❌ |
| Protocol message types defined | 19 | 19 | 19 | 19 |
| Protocol error codes defined | 28 | 28 | 28 | 28 |
| Automated tests (2026-10-19) | core/credentials/registry suites | 476 passed; framework-bridge suites skip unless the framework is installed, and pass with all installed | 244 passed, `go vet` clean | 174 passed |

## Message types

The **19** message types, with identical wire strings in all four SDKs:
`ArohaRequest`, `ArohaResponse`, `ArohaStream`, `ArohaNegotiate`,
`ArohaCounterOffer`, `ArohaAccept`, `ArohaReserve`, `ArohaReserveAck`,
`ArohaCommit`, `ArohaCommitAck`, `ArohaCancel`, `ArohaCancelAck`,
`ArohaDelegate`, `ArohaError`, `ArohaSatisfactionSignal`,
`ArohaSpendingMandate`, `ArohaTaskMandate`, `ArohaDispute`,
`ArohaDisputeResolution`.

## Error codes

The **28** codes, with identical wire strings in all four SDKs (`Aroha_` prefix
except where noted):
`UNAUTHORIZED`, `FORBIDDEN`, `INVALID_SIGNATURE`, `EXPIRED_MESSAGE`,
`REPLAY_DETECTED`, `UNKNOWN_CAPABILITY`, `TRUST_LEVEL_INSUFFICIENT`,
`RESERVATION_FAILED`, `RESERVATION_EXPIRED`, `COMMIT_FAILED`, `CANCEL_FAILED`,
`INVALID_TOKEN`, `NO_INVENTORY`, `CAPACITY_EXCEEDED`, `SERVICE_UNAVAILABLE`,
`INTERNAL_ERROR`, `INVALID_PARAMS`, `CSN_NO_STRUCTURAL_MATCH` (no `Aroha_` prefix),
`ACTION_LIMIT_EXCEEDED`, `COMPUTE_LIMIT_EXCEEDED`, `REVERSIBILITY_VIOLATION`,
`HUMAN_GATE_REQUIRED`, `DATA_ACCESS_VIOLATION`, `SANDBOX_REQUIRED`,
`DELEGATION_DEPTH_EXCEEDED`, `CAPABILITY_NOT_PERMITTED`,
`SETTLEMENT_RAIL_MISMATCH`, `COMMIT_DISPUTED`.

Treat a code you have no constant for (from a newer peer) as a generic error.

## Interoperability

v2 mandate tokens use the same camelCase wire fields in every SDK, and each SDK
reproduces the shared vectors byte for byte. Python and Go also run
cross-language tests against tokens produced by the TypeScript reference.

## Where the evidence lives

| SDK | Files read |
|---|---|
| TypeScript | `packages/aroha-core/src/messages/types.ts` (`ArohaErrorCode`, `ArohaMessageType`), `packages/aroha-core/src/messages/envelope.ts`, `packages/aroha-credentials/src/mandate.ts`, `packages/aroha-delegation/src/chain.ts`, `packages/aroha-registry/src/` (the saga engine, `@aroha-sdk/orchestrator`, is no longer in this repository) |
| Python | `sdks/aroha-py/aroha/messages.py`, `envelope.py`, `mandate.py`, `orchestrator.py`, `hub.py`; tests in `sdks/aroha-py/tests/` |
| Go | `sdks/go/aroha/messages/types.go`, `messages/envelope.go`, `mandate/mandate.go`, `orchestrator/saga.go`, `identity/kel.go`, `jcs/jcs.go`; tests alongside each package (`*_test.go`) |
| Java | `sdks/java/src/main/java/com/arohalabs/messages/MessageTypes.java`, `ArohaEnvelope.java`, `mandate/ArohaMandateCredential.java`, `identity/Kel.java`, `crypto/Jcs.java`, `orchestrator/SagaEngine.java`; tests in `sdks/java/src/test` |
