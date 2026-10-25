# Phase 2 Stage 9: Per-User Approval Keys, and Cancellation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn an approval from *logged* into *attributable to a key only one person holds*. Today the invariants are signed with the AGENT's key and the human's name sits beside them in the audit record — which proves "this agent asserted that Dana approved", not that Dana did. This stage has the human's own key sign, so the agent cannot manufacture an approval for someone.

Plus §5.5 cancellation, which is small and has been an open gap since Stage 5.

**Why now:** it is the deepest remaining hole and has been flagged in three consecutive stages. Everything it needs already exists — named users (Stage 4), the OS-backed keystore (§9.7), and the invariant primitives.

**Architecture:** Each user gets an Ed25519 keypair at creation, private half in the OS keystore, public half in `users.json`. An approval is signed by the USER's key. Because the receiving agent has no way to resolve a user DID on its own, the request carries the user's public key alongside the signature, and the *agent* counter-signs that binding with its own key — a one-link delegation the receiver can already verify, since the agent's key is recoverable from its content-addressed DID.

**Tech Stack:** TypeScript, vitest, `@noble/ed25519`, the existing keystore.

**Spec:** [../specs/2026-08-18-human-identity-design.md](../specs/2026-08-18-human-identity-design.md) §3 Phase 3; [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §5.5

## What this does and does not prove — read before implementing

State this precisely, because overclaiming here is worse than not building it:

- **It does prove:** the approval was signed by a key held in this runtime's OS keystore under a specific user's account. The agent cannot forge it without that key, so an agent claiming "Dana approved" while Dana did not now requires stealing Dana's key, not merely writing her name in a field.
- **It does not prove** the human was physically present. A bearer token still authenticates the *session* that triggers the signing; the key signs on that session's behalf. Phase 1's disclosed limitation ("anyone holding the token is that user") is narrowed, not eliminated.
- **It does not establish org-wide identity.** The receiver trusts the agent's counter-signature that this public key belongs to this user. Without an org user directory, the agent remains the only attester. That is the honest boundary, and it should be written down rather than implied away.

## Global Constraints

- Copyright header on new files.
- **A personal install must not grow a key ceremony.** With no named users, nothing changes — same constraint every identity stage has held.
- **The keystore may degrade to a file backend** (headless Linux, no keyring). That is already disclosed by `resolveKeystore().kind`; surface it rather than pretending every install gets OS backing.
- **A user's private key never leaves the runtime.** It is used to sign, never returned by any route.
- Revoking a user must remove the key, not merely the record.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/host/users.ts` | *Modify* — issue/retrieve a per-user keypair |
| `packages/aroha-core/src/action/types.ts` | *Modify* — `UserApproval` carrying the user's signature + agent counter-signature |
| `apps/aroha-runtime/src/host/action-handler.ts` | *Modify* — verify the two-link chain |
| `apps/aroha-runtime/src/gateway/peers-api.ts` | *Modify* — sign with the user's key; add cancel |

---

## Task 1: Per-user keypairs

**Files:** `src/host/users.ts` (+ test)

- [ ] `User` gains `publicKey: string` (hex) and `did: string` (`did:aroha:personal:<uuid>`, the form `@aroha-sdk/commerce` already uses and the consult spec §6.2 names for person DIDs).
- [ ] `add()` generates a keypair, stores the private half via `resolveKeystore(ws).store("user:" + id, hex)`, and keeps only the public half on disk.
- [ ] `privateKeyFor(id)` retrieves it. Returns null when absent — a user created before this stage has no key, and that must degrade to the agent-signed path rather than crash.
- [ ] `revoke()` also calls `keystore.remove()`. A revoked user whose key is still in the keychain is a revocation that did not revoke.
- [ ] Tests: key round-trips; the private key never appears in `list()`; revoke removes it; a legacy user with no key resolves to null rather than throwing.

- [ ] Commit.

---

## Task 2: The two-link approval

**Files:** `packages/aroha-core/src/action/types.ts`, `action-handler.ts` (+ tests)

```ts
/**
 * An approval signed by a HUMAN's own key, plus the agent's attestation
 * that the key belongs to that human.
 *
 * Two signatures because the receiver can verify one of them unaided: the
 * agent's key is recoverable from its content-addressed DID, while a user
 * DID resolves to nothing without an org directory. So the agent vouches,
 * once, for the binding — and the human's signature is what the agent
 * itself cannot forge.
 */
export interface UserApproval {
  /** The human's DID (did:aroha:personal:<uuid>). */
  userDid: string;
  /** Their Ed25519 public key, hex. */
  userPublicKey: string;
  /** The human's signature over the canonical invariants. */
  userSignature: string;
  /** The agent's signature over `userDid|userPublicKey`, binding the two. */
  agentAttestation: string;
}
```

`ActionRequestParams.approval` stays as-is (agent-signed, still supported); a new optional `userApproval` carries this. Both paths remain valid — a runtime with no named users has no user key to sign with, and must keep working.

Receiving side, in order:
1. If `userApproval` present: verify `agentAttestation` against the caller agent's key (recoverable from its DID). Fails → `Aroha_UNAUTHORIZED`.
2. Verify `userSignature` over the invariants against `userPublicKey`. Fails → `Aroha_UNAUTHORIZED`.
3. `verifyInvariants` against the parameters about to execute, exactly as today.
4. Audit `approvedBy: userDid` — now backed by a signature rather than an assertion.

- [ ] Tests: valid two-link approval executes; a tampered `userPublicKey` (swapped for an attacker's) fails the attestation; a valid attestation with a *wrong* user signature fails; parameters mutated after signing still fail as before.

- [ ] Commit.

---

## Task 3: Sign with the user's key

**Files:** `src/gateway/peers-api.ts`

- [ ] `/v1/peers/action/approve` looks up the approving identity's private key. Present → build a `UserApproval`; absent → fall back to today's agent-signed `approval`, and say which was used in the response so the difference is visible rather than silent.
- [ ] Audit records which form was used. "Signed by Dana's key" and "signed by the agent on Dana's behalf" are different claims and the log should not blur them.

- [ ] Commit.

---

## Task 4: Cancellation (§5.5)

**Files:** `action-handler.ts`, `peers-api.ts`

- [ ] `POST /v1/peers/action/cancel` with `{ idempotencyKey }` records `action_cancelled` locally so an abandoned request is visible rather than merely absent.
- [ ] Receiving side: a cancelled key is refused if it later arrives with an approval. The receiver's own audit log is the store, same as idempotency.
- [ ] Tests: cancel then approve is refused; cancel is idempotent; cancelling an unknown key is a no-op that reports itself rather than erroring.

- [ ] Commit.

---

## Task 5: Full verification and spec update

- [ ] Runtime suite, build, monorepo tests, push, CI.
- [ ] Update the human-identity spec's §6: Phase 3 is now partially built, with the precise boundary from the top of this plan written into the limitations list. It must not read as if non-repudiation were solved.
