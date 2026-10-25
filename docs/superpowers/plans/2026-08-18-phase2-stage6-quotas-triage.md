# Phase 2 Stage 6: Quotas and Triage

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a runaway peer from burning this agent's model budget, and stop a vague question from burning it slowly. Two different protections against the same failure — spending money answering things that should not have been answered.

**Architecture:** A per-caller-DID sliding window checked before any model call, and a cheap classifier that decides whether a question is answerable *before* the expensive model sees it. Both sit next to the kill switch and loop guard in the same free-gates-first block. Triage runs in the §9.1 Layer 2 isolated-context shape the Worker and composer already use — it reads attacker-controlled text to make a spending decision, so it gets no tools and no authority.

**Tech Stack:** TypeScript, vitest.

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §9, §10, §14 step 6

## Global Constraints

- Copyright header on every new file.
- **Quotas are cost protection, not a Sybil defence.** The org controls DID issuance, so this defends against a looping or misconfigured peer, not a determined attacker minting identities. Say so rather than implying more.
- **Quota state is in-memory, and that is disclosed.** A restart resets it. An attacker cannot force a restart, so the exposure is bounded — but it is real and belongs in the limitations list, exactly as the spec already says.
- **Triage must not use the answering model.** If it did, the cost asymmetry that justifies it disappears — you would pay full price to decide whether to pay full price. A separate `triageModel` config is load-bearing, not a nicety.
- **A refused-as-vague consult returns a clarification request, not silence.** A call that returns nothing is indistinguishable from a bug (§10).
- Every refusal is audited, same as the kill switch. A quota that silently eats traffic is a blind spot.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/host/quota.ts` | *Create* — `QuotaGuard`: per-caller sliding window |
| `apps/aroha-runtime/src/host/triage.ts` | *Create* — `triageQuestion`: cheap answerability check |
| `apps/aroha-runtime/src/workspace/config.ts` | *Modify* — `consultQuotaPerHour`, `triageModel` |
| `apps/aroha-runtime/src/transport/lan-server.ts` | *Modify* — apply both |
| `apps/aroha-runtime/src/host/admin.ts` | *Modify* — `GET /v1/admin/quotas` becomes real |
| `apps/aroha-runtime/src/gateway/admin-api.ts` | *Modify* — the route Stage 3 deliberately left out |

Stage 3 refused to add `/v1/admin/quotas` because there were no quotas to report and a route returning nothing would imply a control that did not exist. This stage is what makes it honest to add.

---

## Task 1: QuotaGuard

**Files:** Create `src/host/quota.ts` + test.

```ts
export class QuotaGuard {
  constructor(perHour: number, now?: () => number);
  /** Would this call be allowed? Does NOT consume. */
  check(callerDid: string): { ok: true } | { ok: false; retryAfterSeconds: number };
  /** Record a call against the caller's window. */
  record(callerDid: string): void;
  /** Current consumption per caller, for the operator console. */
  usage(): Array<{ callerDid: string; used: number; limit: number }>;
}
```

`check` and `record` are separate on purpose: a call refused for looping or by the kill switch should not consume quota — a caller must not be punished twice for one refusal, and a misconfigured peer hammering a loop would otherwise exhaust a quota it never actually spent model time against.

- [ ] **Tests:**
  - under the limit passes; the Nth+1 call in the window is refused with a sensible `retryAfterSeconds`
  - the window slides — calls older than an hour stop counting (inject a clock; do not sleep)
  - callers are independent: one exhausting its quota does not affect another
  - `perHour <= 0` disables the quota entirely rather than refusing everything (an operator setting 0 means "no limit", and failing closed here would silently break a working deployment on upgrade — the opposite of the action-request default, because a quota is a *ceiling*, not a *permission*)
  - `usage()` reports per-caller counts

- [ ] Commit.

---

## Task 2: Triage

**Files:** Create `src/host/triage.ts` + test.

```ts
export type TriageVerdict =
  | { answerable: true }
  | { answerable: false; clarification: string };

export async function triageQuestion(
  engine: EngineManager,
  triageModel: string,
  question: string,
): Promise<TriageVerdict>;
```

Isolated context, same shape as `extractWithWorker` and `composeQuestion`: its own system prompt, no tools, and only a verdict crosses back. The question is attacker-controlled text being used to make a spending decision, which is exactly the Layer 2 threat.

Prompt asks for one of two literal outputs — `ANSWERABLE`, or `UNCLEAR: <what is missing>`. Parse strictly.

**Fail OPEN, deliberately, and the opposite of everywhere else in this codebase:** if the triage model is unreachable or returns something unparseable, the consult proceeds. Triage is a cost optimisation, not a security control — failing closed would turn a triage outage into a total consult outage, trading a small cost saving for an availability incident. This is worth a comment in the module because it contradicts the fail-closed instinct every other gate here follows.

- [ ] **Tests:** clear question passes; vague question returns a clarification carrying the model's stated reason; unparseable output proceeds; a throwing engine proceeds.

- [ ] Commit.

---

## Task 3: Apply both on the consult path

**Files:** `lan-server.ts` (+ test), `config.ts`.

Config:
```
consultQuotaPerHour = 100
triageModel = "llama3.2:1b"
```

Order in the consult branch, cheapest first:
1. kill switch (free, operator's explicit instruction)
2. loop guard (free)
3. **quota** (free — an in-memory count)
4. **triage** (one cheap model call)
5. the real answer (one expensive model call)

Only step 5 consumes quota — `record()` after triage passes, so a question refused as vague costs the caller nothing but the triage call.

- [ ] **Tests:** exhausted quota returns `Aroha_CAPACITY_EXCEEDED` and never calls the engine; a vague question returns a clarification rather than an answer; both are audited; with no `triageModel` configured, triage is skipped entirely rather than guessing a model.

- [ ] Commit.

---

## Task 4: `/v1/admin/quotas`

- [ ] `AdminControls.quotas()` delegating to the guard's `usage()`.
- [ ] `GET /v1/admin/quotas` returning it.
- [ ] Test through a real gateway.
- [ ] Commit.

---

## Task 5: Full verification

- [ ] Runtime suite, `npm run build`, `npm test`, push, CI green.

---

## Disclosed limitations

- **Quota state is in-memory.** A restart resets every window. An attacker cannot force a restart, so the exposure is bounded, but a runtime that crash-loops effectively has no quota.
- **Quotas are per-DID, and the org issues DIDs.** This is runaway/cost protection, not a Sybil defence.
- **Triage fails open** (Task 2). A triage outage means paying for questions that would have been refused as vague — the correct trade, but a real cost.
- **Triage quality is a model's judgement**, not a guarantee. It will sometimes pass a vague question and sometimes ask for clarification on a clear one; it is a cost filter, not a correctness control.
