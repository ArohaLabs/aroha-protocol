# Phase 3 Stage 2: Per-Person Memory

**Goal:** Memory belongs to the person who stated it, not to the agent — and the run protocol can finally say who is speaking.

**Status: BUILT.** See [the spec](../specs/2026-08-18-memory-and-capability-honesty-design.md) §3.4 for the design and its reasoning.

Stage 1 shipped memory belonging to the AGENT, and documented the consequence rather than fixing it: on a shared install two colleagues fed and read one store, so a fact one of them stated in confidence would surface, unprompted, in the other's conversation.

## What was built

| Change | Where |
|---|---|
| `Caller` type; `HandlerContext.caller`, required | `packages/aroha-run/src/types.ts` |
| `ServeOptions.resolveCaller`, and signature-beats-assertion precedence | `packages/aroha-run/src/serve.ts` |
| One store per owner, hashed filenames, legacy migration | `apps/aroha-runtime/src/host/memory.ts` |
| Store opened per turn from `ctx.caller` | `apps/aroha-runtime/src/host/handler.ts` |
| `x-aroha-caller`, set unconditionally by the gateway | `apps/aroha-runtime/src/gateway/server.ts`, `host/runtime.ts` |
| Verified peer DID named on the LAN and relay paths | `apps/aroha-runtime/src/transport/*.ts` |

## Verification

- 6 gateway tests with two real named users: neither can read, delete, or write to the other's memory; the install token is not a skeleton key.
- The forgery tests are load-bearing — replacing the unconditional overwrite with a merge makes one fail.
- Migration: a pre-partitioning `memory.json` lands in the unattributed bucket, not a person's.
- 508 runtime tests, whole monorepo green, binary compiles.

## Follow-on

Enabling OIDC *after* facts already exist leaves those facts in the unattributed bucket. Nothing recorded who stated them, so there is nothing to migrate them by — noted in the spec rather than papered over.
