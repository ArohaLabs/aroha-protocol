<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Polyglot SDKs

Aroha ships first-party SDKs for TypeScript, Python, Go, and Java. They share the same **envelope format**, the 19 message types and the 35 error codes, so a `ArohaError` envelope produced by a Java agent is parsed by a Python consumer with no translation layer. They do **not** share the full protocol surface yet: TypeScript is the reference, Python is beta, and Go and Java are partial. See the **[SDK feature matrix](feature-matrix.md)** for exactly what each SDK implements.

## SDK Comparison

| | TypeScript | Python | Go | Java |
|---|---|---|---|---|
| **Install** | `npm i @aroha-sdk/core` | `pip install aroha` | unreleased — build from source ([Go SDK](go.md)) | not on Maven Central — build from source ([Java SDK](java.md)) |
| **Min version** | Node 22 | Python 3.11 | Go 1.22 | Java 21 |
| **Transport** | Node `http` | FastAPI + httpx | `net/http` | JDK `HttpServer` |
| **Async** | Native (`async/await`) | Native (`async/await`) | Goroutines | `CompletableFuture` |
| **Dev mode** | `devMode: true` | `dev_mode=True` | `DevMode: true` | `devMode=true` |
| **Crypto** | `@noble/ed25519` | `cryptography` | standard library (`crypto/ed25519`) | Bouncy Castle |

## What the SDKs Implement

The layers below exist in every SDK unless noted. Details and gaps are in the [feature matrix](feature-matrix.md).

| Layer | Module | What it does |
|---|---|---|
| **Layer 0** | `transport` | HTTP server + client, DID Document endpoint |
| **Layer 1** | `identity` | `did:aroha:` DID generation, Ed25519 keypairs, multibase encoding |
| **Layer 2** | registry client (`@aroha-sdk/registry`, `aroha.hub`, Go `registry`, Java `ArohaRegistryClient`) | Capability registration and discovery |
| **Layer 3** | `messages` | Envelope builder, validator, nonce registry. 19 message types and 35 error codes in every SDK |
| **Orchestration extension** | `orchestrator` | Saga engine (Reserve → Commit → Cancel), agent fan-out selector — an extension, not part of the core specification ([extensions](../spec/extensions.md)) |

## Wire Guarantees

- **Message types** — The same 19 string values on the wire across all SDKs: `ArohaRequest`, `ArohaResponse`, `ArohaStream`, `ArohaNegotiate`, `ArohaCounterOffer`, `ArohaAccept`, `ArohaReserve`, `ArohaReserveAck`, `ArohaCommit`, `ArohaCommitAck`, `ArohaCancel`, `ArohaCancelAck`, `ArohaDelegate`, `ArohaError`, `ArohaSatisfactionSignal`, `ArohaSpendingMandate`, `ArohaTaskMandate`, `ArohaDispute`, `ArohaDisputeResolution`
- **Error codes** — 28 shared wire strings, `Aroha_*` (e.g. `Aroha_UNKNOWN_CAPABILITY`) plus `CSN_NO_STRUCTURAL_MATCH`, not language-local enum names; treat unknown codes as generic errors.
- **Envelope fields** — `@context`, `id`, `type`, `from`, `to`, `created`, `expires`, `nonce`, `correlationId`, `body`, `proof`
- **Canonical signing** — All SDKs canonicalize the envelope with lexicographically sorted keys before signing

## Choose Your SDK

<div class="grid cards" markdown>

-   :fontawesome-brands-python: **[Python SDK](python.md)**

    ---

    FastAPI server · httpx async client · LangChain, CrewAI, AutoGen bridges

-   :fontawesome-brands-golang: **[Go SDK](go.md)**

    ---

    Goroutine-native · depends on `google/uuid` only · partial, not released (see matrix)

-   :fontawesome-brands-java: **[Java SDK](java.md)**

    ---

    JDK 21 server · CompletableFuture async · Spring AI bridge · partial, not released (see matrix)

</div>

!!! note "TypeScript SDK"
    The TypeScript SDK lives in `packages/aroha-core/` and `packages/aroha-*` alongside the rest of the monorepo. See the [Packages](../packages/index.md) section for full TypeScript API docs.

