# Phase 2 Stage 5: Action Requests (Receiving Side)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one agent ask another to *do* something, with safety that does not rest on trusting the asker. A consult is a read; this is the write, and it is where the whole identity/audit/console stack built in Stages 2–4 earns its place.

**Scope: the RECEIVING side (B) only.** B's policy check, the pending-approval response, signed-approval verification, idempotency, evidence, and audit. The requesting side (A) — surfacing a pending approval to a human and signing it — is inseparable from the chat UI and is the last roadmap item; tests here act as A directly, which is a genuine two-party exercise of the protocol, not a stand-in for one.

**Architecture:** The spec's §5.2 flow, verbatim. B never trusts A's claim that "my human approved" — A returns a signed invariants block binding the exact parameters, and B verifies that signature *and* checks it against what it is actually about to do. If anything mutated between approval and execution — injected content, a bug, a malicious relay — the invariant check fails and B refuses. That is the redirected-payee defence applied across agents, and every primitive it needs (`signInvariants`, `verifySignedInvariants`, `verifyInvariants`) already ships in `@aroha-sdk/credentials`.

**Tech Stack:** TypeScript, vitest, `@aroha-sdk/credentials` (invariants), `@aroha-sdk/core` (wire types, taxonomy), `@aroha-sdk/audit`.

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §5, §10, §14 step 5

## Global Constraints

- Copyright header on every new file.
- **Fail closed by default.** With no `actionCallers` and no `exposedActions` configured, every action request is refused. Turning this on must be a deliberate act, not a default anyone inherits by upgrading.
- **Two independent layers, per §5.1, and neither is sufficient alone.** B's standing policy (who may request what) *and* A's human's signed per-instance approval. Building only one is worse than building neither, because it looks finished.
- **Idempotency must survive a restart.** An action is by definition side-effecting; replaying one because the process bounced is the failure this stage exists to prevent. Reuse the durable audit log rather than adding a second store — it is already the record of what was actually done.
- **Evidence, not `{ ok: true }`.** "It says it sent the email" and "here is the message id" are different claims and only the second is auditable (§5.4).
- Error codes come from the existing `ArohaErrorCode` enum — the spec's §10 table maps every condition to one already defined. No new codes.

---

## File Structure

| File | Responsibility |
|---|---|
| `packages/aroha-core/src/action/types.ts` | *Create* — wire shapes both sides must agree on |
| `packages/aroha-core/src/action/index.ts` | *Create* — barrel |
| `packages/aroha-core/src/index.ts` | *Modify* — export it |
| `apps/aroha-runtime/src/host/action-policy.ts` | *Create* — Layer 1: who may request what |
| `apps/aroha-runtime/src/host/action-handler.ts` | *Create* — the §5.2 flow |
| `apps/aroha-runtime/src/workspace/config.ts` | *Modify* — `actionCallers`, `exposedActions` |
| `apps/aroha-runtime/src/transport/lan-server.ts` | *Modify* — serve `capability: "action"` |
| `apps/aroha-runtime/src/transport/relay-client.ts` | *Modify* — same |

---

## Task 1: Wire shapes in aroha-core

**Files:** Create `packages/aroha-core/src/action/{types.ts,index.ts}`; modify `packages/aroha-core/src/index.ts`.

```ts
/** The capability name an action request carries. */
export const ACTION_CAPABILITY = "action";

export interface ActionRequestParams {
  /** Capability id from CAPABILITY_TAXONOMY, e.g. "send-email". */
  action: string;
  /** Exact values the action will execute with. Bound by the approval. */
  parameters: Record<string, string | number | boolean>;
  /**
   * Stable across retries of ONE logical request — not per attempt. B
   * records completed keys and replays the original result rather than
   * acting twice (design spec §5.3).
   */
  idempotencyKey: string;
  /**
   * A's human's approval, binding these exact parameters. Absent on the
   * first attempt: B replies with what it WOULD do, A gets that approved
   * and signed, then re-sends the identical request with this attached.
   */
  approval?: SignedInvariants;
}

/** What B returns. */
export type ActionRequestResult =
  | {
      status: "pending-approval";
      /** Exactly what B would do, for a human at A to approve or refuse. */
      describes: { action: string; parameters: Record<string, string | number | boolean> };
      /** When an approval signed for this request stops being accepted. */
      expiresAt: string;
    }
  | { status: "done"; evidence: ActionEvidence }
  | { status: "replayed"; evidence: ActionEvidence };

export interface ActionEvidence {
  /** Provider-side identifier — a message id, a booking reference. */
  confirmation: string;
  /** ISO8601. */
  completedAt: string;
  /** Optional provider signature over the confirmation, where one exists. */
  providerSignature?: string;
}
```

`status: "replayed"` is distinct from `"done"` deliberately: a caller that cannot tell "I did this" from "this had already been done" cannot reason about its own retries.

- [ ] Tests: shape round-trips through JSON unchanged (these cross a wire).
- [ ] Commit.

---

## Task 2: ActionPolicy — Layer 1

**Files:** Create `src/host/action-policy.ts` + test; modify `config.ts`.

Config keys, following the flat `key = value` parser already in place:

```
actionCallers = did:aroha:zA,did:aroha:zB
exposedActions = send-email,create-calendar-event
```

```ts
export class ActionPolicy {
  constructor(private callers: string[], private actions: string[]) {}

  /** Layer 1 (design spec §5.1): may this caller request this action AT ALL? */
  check(callerDid: string, action: string): { ok: true } | { ok: false; reason: string };
}
```

Rules, all fail-closed:
- Empty `callers` OR empty `actions` → refuse everything. A runtime that has not been configured for action requests does not serve them.
- Caller not in `callers` → refuse.
- Action not in `actions` → refuse.
- Action not in `CAPABILITY_TAXONOMY` → refuse. An unmapped capability has no known tier or reversibility, and `getRiskTier` already fails closed at 5; honouring a request for something the taxonomy has never heard of would route around that.

**Disclosed limitation to state in the module docstring:** the flat config gives one caller list and one action list, not per-caller-per-action granularity. Every permitted caller may request every exposed action. Finer granularity needs a structured config format; until then an operator should expose only actions they would grant to any listed caller.

- [ ] Tests for each rule; commit.

---

## Task 3: The action handler — §5.2 flow

**Files:** Create `src/host/action-handler.ts` + test.

```ts
export interface ActionExecutor {
  /** Perform the action for real. Returns provider evidence. */
  (action: string, parameters: Record<string, string | number | boolean>): Promise<ActionEvidence>;
}

export function buildActionHandler(opts: {
  agent: AgentRecord;
  policy: ActionPolicy;
  audit: AuditLog;
  execute: ActionExecutor;
  resolveCallerKey: (did: string) => Uint8Array | null;
  approvalTtlMs?: number;   // default 5 minutes
}): (callerDid: string, params: ActionRequestParams) => Promise<
  { ok: true; result: ActionRequestResult } | { ok: false; code: ArohaErrorCode; message: string }
>;
```

Order of checks — each one is cheaper than the next, and each refusal is more specific:

1. **Idempotency replay.** Scan the audit log for an `action_executed` entry with this key; if found, return its evidence as `"replayed"` without executing. Checked FIRST: a replay must not be re-authorized, re-approved, or re-charged, and must succeed even if policy has since changed — the caller is owed the same answer they were already given.
2. **Policy** (Layer 1). Refuse → `Aroha_FORBIDDEN`.
3. **No approval attached** → return `pending-approval` describing exactly the action and parameters received, with `expiresAt = now + approvalTtlMs`. Audited as `action_pending`.
4. **Approval attached:**
   a. `verifySignedInvariants` against the CALLER's public key. Fails → `Aroha_UNAUTHORIZED`. This is what makes "my human approved" checkable rather than trusted.
   b. `verifyInvariants(actual, invariants)` where `actual.parameters` is the parameters B is *about to execute with*. Fails → `Aroha_INVALID_PARAMS`. This is the redirected-payee defence: if anything mutated between approval and execution, it stops here.
   c. Execute. Audit `action_executed` with the idempotency key and evidence.
   d. Execution throws → audit `action_failed`, return `Aroha_INTERNAL_ERROR`.

New audit event types: `action_pending`, `action_executed`, `action_refused`, `action_failed`.

- [ ] Tests, each one a real behaviour rather than a mock assertion:
  - unconfigured policy refuses
  - permitted caller with no approval gets `pending-approval` describing exactly what was asked, and NOTHING executes
  - a valid signed approval executes once and returns evidence
  - **parameters mutated after signing are refused** — sign for `{to: "dana@example.com"}`, send `{to: "attacker@example.com"}`, expect `Aroha_INVALID_PARAMS` and no execution. This is the single most important test in the stage.
  - an approval signed by a DIFFERENT key is refused
  - an expired approval is refused
  - the same idempotency key twice executes once and returns `"replayed"` the second time
  - every branch writes exactly one audit entry

- [ ] Commit.

---

## Task 4: Serve `capability: "action"` on both transports

Same shape as the consult wiring: check the kill switch, then dispatch. Reuse `resolveContentAddressedPublicKey` for `resolveCallerKey` — the caller's DID already carries its key on the LAN path.

- [ ] Refuse with `Aroha_UNKNOWN_CAPABILITY` when no executor/policy is configured, rather than pretending to accept.
- [ ] Two-node test through a real `startLanListener`.
- [ ] Commit.

---

## Task 5: Full verification

- [ ] Runtime suite, `npm run build`, `npm test`, push, CI green.
- [ ] Version-bump and publish `@aroha-sdk/core` (new action types are additive) — check with the user before publishing.

---

## What this stage deliberately does NOT do

Named so they are not mistaken for oversights:

- **The requesting side (A).** Surfacing a pending approval to a human, collecting the decision, and calling `signInvariants` belongs with the chat UI (the next roadmap item). Until it exists, only a programmatic caller can complete the flow.
- **Cancellation** (§5.5). `POST /v1/consults/:correlationId/cancel` releases B's pending state. As built, a pending approval simply expires — which bounds the risk but does not let A withdraw early.
- **Per-caller-per-action policy** (Task 2's limitation).
- **`lan-server.ts`/`relay-client.ts`'s hardcoded `decision: "reject"` for inbound HITL on the CHAT path** stays exactly as it is. That is the right default for a background chat connection with no human attached, and this stage replaces it only for action requests, which carry their approval with them.
