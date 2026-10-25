# Phase 2 Stage 8: Action Requests — the Requesting Side

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the loop Stage 5 deliberately left open. A human can ask a peer agent to *do* something, see exactly what that agent would do, approve or refuse it, and have the approval cryptographically bound to those exact parameters before it is sent. Until now only a programmatic caller could complete this flow.

**Why this and not something else:** it is the one place where every earlier stage converges. The audit log records it, the operator console shows it, named users make `approvedByDid` real rather than a null column, and the UI built in Stage 7 is where the human actually stands. It is also the spec's central claim — "B now holds cryptographic proof that a human at A approved this exact action" — which is currently only half-demonstrable.

**Architecture:** Two routes and a dialog. `POST /v1/peers/action` sends an unapproved request and returns what the peer *would* do. The human approves; `POST /v1/peers/action/approve` signs a `MandateInvariants` block over the exact parameters with the local agent's key and re-sends. The private key never leaves the runtime, and the signing step is server-side for exactly that reason.

**Tech Stack:** TypeScript, vitest, `@aroha-sdk/credentials` (`signInvariants`), `@aroha-sdk/core` (action wire types).

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §5.2 steps 3–5, §5.5

## Global Constraints

- Copyright header on new files.
- **The human's approval must be recorded with WHO approved it.** Stage 4 made identity available; this is the first thing that should use it. An action executed on someone's authority with no record of whose is the compliance gap the whole stack exists to close.
- **Parameters approved must be byte-identical to parameters sent.** The client signs what it is about to send, not what it was earlier shown. If those can drift, the receiving side's invariant check is the only thing catching it — and it should never have to.
- **A rejection sends nothing.** Not a cancelled request, not an empty one: the peer is never contacted again for that request.
- **The expiry must be tight.** An approval that stays valid for hours is an approval that can be replayed hours later against a changed world.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/transport/action-client.ts` | *Create* — `sendActionRequest`, the outbound half |
| `apps/aroha-runtime/src/gateway/peers-api.ts` | *Modify* — `/v1/peers/action`, `/v1/peers/action/approve` |
| `apps/aroha-runtime/src/ui/page.ts` | *Modify* — request-an-action dialog and approval block |

---

## Task 1: sendActionRequest

**Files:** Create `src/transport/action-client.ts` + test.

```ts
export async function sendActionRequest(opts: {
  askerDid: string;
  askerPrivateKey: Uint8Array;
  targetDid: string;
  targetEndpoint: string;
  targetPublicKey: Uint8Array;
  action: string;
  parameters: Record<string, string | number | boolean>;
  idempotencyKey: string;
  /** Present on the second call, after a human approved. */
  approval?: SignedInvariants;
}): Promise<
  | { ok: true; result: ActionRequestResult }
  | { ok: false; reason: string }
>;
```

Mirrors `sendConsult`: seal the envelope (the LAN listener runs `requireEncryption`), send, and return the peer's answer or a clean refusal. An unreachable peer is a refusal, not a throw — same posture as the consult path.

- [ ] **Tests** against a real `startLanListener` configured to serve actions:
  - an unapproved request returns the peer's `pending-approval` describing exactly what was asked
  - a signed approval executes and returns evidence
  - an unreachable peer returns a refusal rather than hanging
  - **the same idempotency key twice returns `replayed`** — proving the client's key travels correctly, not just that the server dedupes

- [ ] Commit.

---

## Task 2: The two routes

**Files:** `src/gateway/peers-api.ts` + test.

`POST /v1/peers/action` — body `{ peerDid, endpoint, action, parameters, asAgent? }`:
- generates an `idempotencyKey` server-side (a UUID) and returns it to the client
- sends unapproved, returns the peer's `pending-approval`
- audits `action_pending` locally, so the requesting side has its own record and not just the receiver's

`POST /v1/peers/action/approve` — body `{ peerDid, endpoint, action, parameters, idempotencyKey, asAgent? }`:
- signs `{ parameters, expiry: now + 2 min }` with the local agent's key
- re-sends with the approval attached
- audits `action_executed` (or `action_refused`) **with the approving human's `userId`**, taken from the guard's resolved identity

The tight expiry is deliberate and worth a comment: a human approves *this action now*, and an approval that outlives the moment can be replayed against a world that has changed since.

- [ ] **Tests:**
  - the pending route returns the peer's description and an idempotency key
  - the approve route executes and returns evidence
  - **the audit entry names the approving user** when named users are configured, and records `unattributed` otherwise
  - approving with parameters that differ from those sent is refused by the peer (an end-to-end proof that the binding holds across the whole round trip, not just inside one process)

- [ ] Commit.

---

## Task 3: UI

**Files:** `src/ui/page.ts` (+ page.test.ts additions)

- [ ] A "Request an action" entry in the invite dialog, or a sibling dialog: pick a peer, name the action, supply parameters as key/value JSON.
- [ ] The pending-approval response renders in the transcript as a distinct block showing **exactly what the peer said it would do** — the peer's own `describes`, not the local echo of what was typed. Showing the local copy would defeat the purpose: the point is to approve what the *other side* understood.
- [ ] Approve/Reject buttons. Approve calls the approve route and renders the evidence; Reject renders that nothing was sent.
- [ ] Same `textContent` discipline as Stage 7 — `describes.parameters` is a remote agent's echo of a request and is untrusted on the way back.

- [ ] Commit.

---

## Task 4: Full verification

- [ ] Runtime suite, `npm run build`, `npm test`, push, CI green.

---

## Still not done after this stage

- **Cancellation (§5.5).** A pending approval expires; it cannot be withdrawn early. Bounded but real.
- **Per-caller-per-action policy** on the receiving side (flat config limitation).
- **Per-user signing keys** (human-identity Phase 3). The approval is signed with the AGENT's key and the audit names the human separately. That proves "this agent asserted that this named human approved" — an improvement on "this agent asserted a human approved", but still short of the human signing directly, which is what makes an approval non-repudiable.
