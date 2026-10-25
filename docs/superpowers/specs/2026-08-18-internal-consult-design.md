<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Internal Agent Consult and Action Requests — Design

**Date:** 2026-08-18
**Status:** Draft for review
**Scope:** Agent-to-agent interaction *inside a single organisation* — one department's agent asking another's for knowledge it does not hold, or asking it to perform an action it cannot perform itself, with data boundaries enforced, every exchange audited, and loops structurally prevented.

---

## 1. Why internal first

The public agent network has a two-sided bootstrap problem: your agent can only consult useful agents if useful agents already exist, and nobody exposes an agent until there is demand. Every agent marketplace to date has died there.

Inside one organisation that problem does not exist. A single buyer supplies both sides, the agents are already known to each other, and data never leaves the org's control. The use case is also sharper: departments genuinely hold knowledge and access other departments lack — precisely the condition that makes an agent the right shape rather than a shared document or an MCP tool.

### 1.1 What this validates

Internal deployment uses more of the existing stack than the public model does:

| Already built | Role here |
|---|---|
| M9 LAN transport + mandatory encryption | Same corporate network, zero infrastructure |
| Multi-agent LAN listener (§9.7) | One host serves several department agents |
| §9.1 Layer 1 signed invariants | Proves a human approved a *specific* action |
| §9.1 Layer 2/3 defences | A consulted agent's reply is untrusted content |
| §9.1 Layer 3 `tainted` guard flag | Every consult-driven tool call is tainted by construction |
| `ArohaCommitEvidence` (§8.2) | Proof an action actually happened |
| §9.7 OS keystore | Protects departmental private keys |
| `AgentDelegationCredential` | Org → department agent identity |

`generateOrgIdentity`/`issueAgentDelegation` currently have **zero call sites**. This design is their first real use.

---

## 2. Two operations, deliberately separate

The central structural decision. "Answer my question" and "do something for me" have different trust requirements, different failure modes, and different approvers. Conflating them is how confused-deputy bugs get built.

| | **Consult** | **Action request** |
|---|---|---|
| Asks for | Knowledge | A side effect |
| Side effects | None | Yes, by definition |
| Tool use | Read-only (tier ≤ 2, `reversibility: "full"`) | As permitted by B's policy |
| Human approval | Not required | **Required**, signed |
| Idempotency | Not needed (no effect) | **Required** |
| Returns | Answer + provenance | Evidence the action occurred |

Both travel as an ordinary `ArohaRequest` (`capability: "consult"` / `"action-request"`) over existing transports. **No new message type and no protocol change** — envelopes stay signed and, off-TLS, encrypted exactly as today.

---

## 3. Common infrastructure

### 3.1 Identity: org delegation

Every department agent's authority derives from one org identity:

1. `generateOrgIdentity(name)` mints the org DID and keypair once, at setup.
2. `issueAgentDelegation(org, agentDID, authorizedCapabilities)` issues an `AgentDelegationCredential` per department agent.
3. A receiving agent verifies the caller's credential with `verifyAgentDelegation` against the org public key before doing any work.

This replaces the public model's verification tiers with one question: *is this caller delegated by our org?* An agent with no valid credential is refused with `Aroha_TRUST_LEVEL_INSUFFICIENT` — not served at a reduced tier. Org keys live in the §9.7 keystore, never a plaintext file.

### 3.2 Hop count and loop prevention

Agent A asks B, B asks A. Internally, quotas are generous enough that this burns real money before anything throttles it. Two independent limits, because they fail differently:

| Control | Catches | Limit |
|---|---|---|
| `hopCount` | Runaway depth (A→B→C→D→…) | Refuse above `maxConsultHops` (default **3**) |
| `consultChain` | Cycles (A→B→A) | Refuse if own DID already in the chain |

A count alone does not stop a 2-cycle under a generous depth limit; a chain check alone does not stop unbounded linear depth. Both are required.

Every calling agent **increments `hopCount` and appends its own DID** before sending. Every receiving agent checks both before doing any work — the first gate, ahead of quota and triage, because it is free.

Worked example with `maxConsultHops: 3`, to fix the off-by-one:

| Sender | Receiver | `hopCount` | `consultChain` | Result |
|---|---|---|---|---|
| A | B | 1 | `[A]` | allowed |
| B | C | 2 | `[A, B]` | allowed |
| C | D | 3 | `[A, B, C]` | allowed |
| D | E | 4 | `[A, B, C, D]` | **refused** — exceeds 3 |
| C | A | 3 | `[A, B, C]` | **refused** — A already in chain |

`maxConsultHops: 3` permits three calls in a chain; the fourth is refused. The cycle check fires independently of depth. `TaskConstraints.maxDelegationDepth` expresses the same idea for delegation and should be configured alongside it.

### 3.3 Capability declaration

Each agent publishes what it can answer and what actions it exposes — the input to discovery, to triage's `domainHint`, and to the operator console's "who can reach what" view. Starts as workspace config; a registry deployment is not required internally.

```ts
interface AgentCapabilityDeclaration {
  agentDID: string;
  department: string;
  /** Free-text subject areas this agent can answer consults about. */
  knowledgeDomains: string[];
  /** Action capability IDs this agent exposes, and to whom. */
  exposedActions: Array<{ capability: string; allowedCallers: string[] }>;
  /** Hash of the system prompt + model binding, for behavioural-change detection (§9.3). */
  behaviourHash: string;
}
```

---

## 4. Consult path

**The consulted agent receives a deliberately constructed question, never the caller's conversation history.**

```ts
interface ConsultParams {
  question: string;        // constructed, never raw history
  domainHint?: string;
  hopCount: number;
  consultChain: string[];
}
```

### 4.1 The Consult Composer

Question construction is an explicit step, not a forward. A separate model call — the same isolated-context shape as the §9.1 Layer 2 Worker (no tools, no mandate, narrow prompt) — takes the caller's conversation and emits only a self-contained question.

This is both the data-minimisation boundary and a quality win: a constructed question is materially more answerable than a transcript fragment. **Excluded from what crosses:** conversation history, the employee's identity, unrelated context, system prompts.

### 4.2 Tool use during a consult

The consulted agent using *its own* tools is the main case, not an edge case — it is what makes a departmental agent worth more than a frontier model. Two rules:

**Tainted by construction.** The question came from another agent — untrusted content by definition. Every consult-driven tool call goes through `mcp.decide(tool, { tainted: true })`, no exceptions. This is the §9.1 Layer 3 path shipped earlier.

**Read-only, enforced.** A consult is semantically a read. If A can make B send an email or write to a database merely by asking a question, that is privilege escalation across the departmental boundary. Consult-triggered tool calls are restricted to tier ≤ 2 and `reversibility: "full"` from the existing capability taxonomy; anything higher is **refused, not escalated** — that is what an action request is for. `TaskConstraints.reversibleOnly` expresses exactly this and is set on the consult path.

### 4.3 Response and provenance

```ts
interface ConsultResult {
  answer: string;
  /** Tools/skills consulted to produce it — makes the answer checkable. */
  sources: Array<{ tool: string; summary: string }>;
  behaviourHash: string;   // which version of this agent answered
}
```

`sources` directly addresses the hallucination-attribution problem: an attributed answer is verifiable, a bare assertion is not.

**Honest framing:** if a department only needs to expose a database query, an MCP server is simpler than an agent. The agent earns its place when judgment is involved, not just retrieval.

---

## 5. Action request path

A asks B to *do* something. Safety comes from two layers, and neither is sufficient alone.

### 5.1 The two layers

**Layer 1 — B's standing policy** (config, no human): which callers may request which action capabilities, from `AgentCapabilityDeclaration.exposedActions`. Set once. Without this, A's human could authorise something B never agreed to expose.

**Layer 2 — A's human approves the instance** (per request, signed): the originator has the intent context and is the only party who can judge whether *this specific action* is what was wanted. B's operator cannot — they would be approving content they have no context for, and showing it to them would leak A's data across the boundary.

### 5.2 The signed-approval flow

The naive version has B trusting A's claim that "my human approved." A compromised or buggy A could simply assert it. The §9.1 Layer 1 machinery removes the need for trust:

1. B's policy check: is A permitted to request this capability at all? If not → `Aroha_FORBIDDEN`.
2. B returns a **pending-approval** response describing the exact action it would take.
3. A surfaces it to its human via the existing `approval_required` / `/v1/resume` suspension.
4. On approval, A calls `signInvariants(...)` binding the exact parameters (recipient, subject, body hash) with a tight `expiry`.
5. A re-sends with the `SignedInvariants` attached.
6. B calls `verifySignedInvariants` + `verifyInvariants` against what it is *actually about to do*, then acts.

B now holds cryptographic proof that a human at A approved this exact action. If parameters mutate anywhere between approval and execution — injected content, a bug — the invariant check fails and B refuses. That is the redirected-payee defence applied to cross-agent actions.

`lan-server.ts` and `relay-client.ts` currently hard-code `decision: "reject"` for inbound approvals. That was the correct conservative default when no approval surface existed; this path replaces it for action requests specifically.

### 5.3 Idempotency

If B performs an action and the response is lost, A retrying would double-send. Every action request carries an `idempotencyKey` (stable across retries for one logical request). B records completed keys and returns the original result on replay rather than re-executing. This mirrors `ArohaCommit`'s documented idempotency in the saga pattern.

### 5.4 Evidence

B returns `ArohaCommitEvidence` (§8.2) — a confirmation identifier and, where available, a provider signature — not merely `{ ok: true }`. "It says it sent the email" and "here is the message ID" are different claims, and only the second is auditable.

### 5.5 Cancellation

A's human may change their mind while approval is pending. `POST /v1/consults/:correlationId/cancel` releases B's pending state. Approvals also expire — the `SignedInvariants.expiry` bounds how long an approval stays valid, so an abandoned request cannot execute hours later.

---

## 6. Personal data across boundaries

### 6.1 Two opposite postures

Consult and transact want opposite things from the same data, and treating them alike breaks one of them:

| | Posture | Why |
|---|---|---|
| **Consult** | **Minimise** — redact aggressively | The answering agent needs the question, not the asker |
| **Transact** | **Consent + purpose limitation** | The counterparty legitimately needs the data; redaction breaks the booking |

A design that only minimises cannot transact. A design that only consents leaks on every question. Both modes are required, selected by operation type (§2).

### 6.2 Identity by reference, not by value

Wherever a *person* is referred to, agents exchange a **person DID** (`did:aroha:personal:<uuid>`, already in `@aroha-sdk/commerce`) rather than a name, email, or employee number. This applies to audit records (`approvedByDid`), consult metadata, and action-request attribution.

The reasoning is not aesthetic. A name in an audit record is PII at rest, accumulating forever in the log that exists to demonstrate PII *discipline*. A DID is a stable, resolvable reference that reveals nothing on its own.

**Blast-radius reduction — the substantive win.** Even where a final counterparty has a legal need for real data, the *intermediaries* do not:

```
Naive:      you → your agent → vendor's agent → airline
                   (sees PII)   (sees PII)      (legally needs PII)

By reference: you → your agent → vendor's agent → airline
                    (holds DID)  (holds DID)   ← consented direct channel
```

An orchestrating agent can arrange a booking without ever holding a passport number. This is what resolves §6.1's tension: minimise for everyone *except* the party with a legal need, and give that party a direct consented channel rather than routing data through every hop.

### 6.3 What proving-instead-of-revealing can and cannot do today

`@aroha-sdk/trust`'s `nullifier.ts` implements Chaum-Pedersen DLEQ proofs, and `KycCertificate` deliberately certifies a **commitment, not raw PII**. A holder can prove *"I am a verified, not-yet-used caller"* in zero knowledge, with no further issuer involvement after enrolment.

| Claim | Supported today? |
|---|---|
| "I am a verified unique human" | **Yes** — the nullifier scheme |
| "I am over 18" without revealing DOB | **Primitive built, not wired** — `@aroha-sdk/bbs`, see §11.2 |
| "My legal name is X" for a regulated booking | **No, and no cryptography changes this** — see below |

**The hard boundary.** Where regulation ties an action to a government identity document — TSA Secure Flight, KYC on payments, age-restricted goods — a DID does not substitute. The vendor has a legal obligation to hold the actual identity, matched against physical ID. A DID does not board a plane. Identity-by-reference reduces *who else* sees the data; it cannot remove the legal requirement on the party that needs it.

**The remaining hard problem is issuer trust.** `verifyCertificate`'s own comment is explicit: it proves a key signed a certificate, not that the key belongs to a *trusted* issuer. Someone must still perform real-world verification and be trusted to have done so — the bootstrap problem in another form, and the reason self-sovereign identity has stayed perpetually near-term.

### 6.4 Outbound screening

`@aroha-sdk/policy`'s `ContentScreener` screens **inbound** content for injection. Egress has no equivalent — every existing control guards the inbound path. A new `OutboundScreener` mirrors its shape (deterministic regex, no LLM call, extensible patterns) and runs on the composed question before it leaves, in **consult** mode:

- **Redact** structured identifiers: email addresses, phone numbers, national-ID and account-number formats, payment-card numbers, and common secret formats (API keys, bearer tokens).
- **Block and surface to the user** when redaction would gut the question's meaning, rather than sending something that no longer asks anything.
- **Record every redaction category** in the audit entry.

**Stated limitation, in the product UI as well as here:** pattern matching catches *structured* PII. It does not reliably catch free-text personal names or contextual identifiers ("the employee who resigned Tuesday"). This is minimisation and auditability, not a guarantee — and once sent, no protocol can un-tell the recipient. A classifier pass is the natural upgrade, out of scope for v1.

---

## 7. Audit log and content provenance

The compliance artifact, and the reason an operator approves deployment at all.

```ts
interface InteractionAuditRecord {
  id: string;
  timestamp: number;
  correlationId: string;
  kind: "consult" | "action-request";
  fromAgentDid: string;
  toAgentDid: string;
  /**
   * Person DID of the approver, for action requests — never a name or email
   * (§6.2). A username here would slowly turn the audit log into the PII
   * repository it exists to protect. Unpopulated until §11.1 is closed.
   */
  approvedByDid: string | null;
  request: string;              // exactly what was sent, post-redaction
  redactions: string[];         // categories only, never values
  response: string | null;
  responseHash: string | null;  // §7.1
  sources: string[];            // tools/skills used to answer
  hopCount: number;
  behaviourHash: string;
  idempotencyKey: string | null;
  outcome: "answered" | "clarification" | "declined" | "quota" | "loop"
         | "awaiting-approval" | "cancelled" | "error";
  costEstimate?: number;
}
```

`redactions` stores **categories, never the redacted values** — a log that records the PII it stripped defeats its own purpose.

Storage follows the runtime's existing convention: JSON-lines under the workspace, not SQLite (see `host/store.ts` on the `bun:sqlite`/`node:sqlite` split).

**Rotation is specified here but NOT implemented, and adding it naively would introduce a worse bug than it solves.** The action-request path detects idempotent replays by scanning this log for a completed action with the same key (there is deliberately no second store — see §5.3). Rotating an `action_executed` entry out of the log therefore makes that action replayable: a caller retrying afterwards would have it performed a second time, which is precisely the failure idempotency exists to prevent.

Anything that adds rotation must first give idempotency a retention guarantee of its own — either a separate durable key store that is never rotated, or a rotation policy that provably keeps every key longer than any caller could retry. Until then the log grows without bound and is scanned linearly per action request, which is acceptable at a local runtime's scale and is the honest trade.

### 7.1 Provenance of content that leaves the channel

In-channel attribution is already solved and solved well: every response is Ed25519-signed by the producing agent's DID — cryptographic, unforgeable, exactly attributable. Statistical watermarking would be a downgrade here.

The real gap is content that *leaves* the signed channel: an employee pastes an agent's answer into a client memo, and six months later nobody can say whether a human or an agent wrote it. Signatures cannot answer that.

| Approach | Verdict |
|---|---|
| **Hash every response into the audit log** (`responseHash`, plus simhash for near-matches after light editing) | **Adopt.** Turns "did we produce this?" into a lookup. Near-zero cost, reuses the audit log. |
| **Visible provenance on UI copy/export** | **Adopt.** Low cost, works. |
| C2PA / Content Credentials for exported documents | Later — real standard, medium cost |
| **SynthID-Text** | **Not adopted.** Genuinely available (open-sourced via Hugging Face) but a *decode-time* intervention: it works only where we control the sampler, so it would function for local-model deployments and silently not for hosted-provider ones. Silent partial coverage is a bad property for an audit mechanism. Optional local-only enhancement, well after hash-based provenance. |

---

## 8. Operator console

The runtime today has **no** usage, analytics, inbound-request, or audit surface whatsoever. Internal adoption requires one, behind the existing gateway bearer token:

| Route | Purpose |
|---|---|
| `GET /v1/admin/interactions` | Paginated audit log; filter by agent, kind, outcome |
| `GET /v1/admin/interactions/:correlationId` | **Full chain trace** — every hop of one interaction |
| `GET /v1/admin/quotas` | Current per-caller consumption |
| `POST /v1/admin/actions/disable` | Kill switch — refuse all inbound action requests immediately |
| `GET /v1/admin/export` | CSV/JSON export for compliance review |

The chain trace matters disproportionately: cross-agent debugging is otherwise this system's worst operational weakness. `correlationId` already links hops; this surfaces it.

The kill switch is not optional. An operator who cannot immediately stop their agent will not deploy it.

---

## 9. Quotas and triage

Internally, quotas are runaway-loop and cost protection, not a Sybil defence (the org controls DID issuance):

- Per-caller-DID sliding window, default generous (e.g. 100/hour), configurable per agent.
- Exceeding it returns `Aroha_CAPACITY_EXCEEDED` with `Retry-After`.
- **Triage**: a cheap classifier decides *in-domain and specific enough to answer*, returning a **clarification request rather than silence** when not. Requires its own `triageModel` config — if triage runs on the same model that answers, the cost asymmetry justifying it disappears.

The triage model reads attacker-controlled text to make a spending decision, so it is an isolated context: no tools, no mandate, classify-only, input untrusted — the §9.1 Layer 2 pattern.

---

## 10. Error handling

All existing wire codes; none added:

| Condition | Code |
|---|---|
| Hop/loop limit exceeded | `Aroha_FORBIDDEN` |
| Action not exposed to this caller | `Aroha_FORBIDDEN` |
| No valid org delegation | `Aroha_TRUST_LEVEL_INSUFFICIENT` |
| Quota exhausted | `Aroha_CAPACITY_EXCEEDED` |
| Missing/invalid signed approval | `Aroha_UNAUTHORIZED` |
| Approved params ≠ actual action | `Aroha_INVALID_PARAMS` |
| Triage: too vague | `ArohaResponse` carrying a clarification request |
| Target unreachable | `Aroha_SERVICE_UNAVAILABLE` |

Every refusal is explicit and attributable. A call that returns nothing is indistinguishable from a bug; "refused: hop limit 3 exceeded" is debuggable.

---

## 11. Open gaps

Named because they are unresolved, not because they are solved.

### 11.1 No human identity exists in the runtime

`approvedByDid` above cannot be populated today. The runtime authenticates with a **single shared bearer token** (`ensureToken`) and has no user model at all — verified, not assumed. For a single-user local tool that is correct; for an org deployment where "which employee approved this action?" is the central compliance question, it is a blocker.

Scoped separately in [2026-08-18-human-identity-design.md](./2026-08-18-human-identity-design.md). It is a prerequisite for the action-request path in any regulated setting, and should not be discovered during a compliance review.

### 11.2 Selective attribute disclosure — primitive built, not yet wired

Per §6.3, the existing nullifier scheme proves *verified uniqueness*, not attributes.

**`@aroha-sdk/bbs` now implements the missing primitive**: BBS signatures over BLS12-381 per draft-irtf-cfrg-bbs-signatures, with `prove`/`verifyProof`. A holder can reveal message 2 of a signed set and prove the issuer signed a set containing it, revealing nothing about the rest, unlinkably across presentations. Correctness is pinned to the DIF/IETF reference fixtures — every valid signature and proof fixture is reproduced **byte for byte**, every invalid one rejected.

It was implemented rather than depended on because the runtime ships via `bun build --compile`, which cannot load native addons, and the maintained BBS libraries are WASM or native bindings.

**Three things remain true and must not be overstated:**

1. **Nothing in Aroha makes a trust decision on it.** It is a package with a test suite, not a credential system. `KycCertificate` still certifies a commitment; no issuance, schema, or revocation flow uses BBS yet.
2. **It is unaudited and not constant-time.** Passing the published vectors is a real bar and a different bar from an audit. That sentence belongs in any conversation where this comes up.
3. **A proof says nothing about who presents it.** It proves an issuer signed a set containing the revealed values, not that the presenter is the subject. Without separate holder binding a leaked proof is a bearer token — a gap in BBS itself, not in this implementation.

The remaining hard problem is unchanged and unsolved by any of this: **issuer trust**. Someone must still perform real-world verification and be trusted to have done it. BBS changes how much a verifier learns; it does not change who vouched.

### 11.3 Behavioural versioning

A department changing its agent's prompt or model silently changes every consumer's results. No protocol answer exists. `behaviourHash` in the declaration and audit record makes the change **detectable after the fact** — not preventable, and not a contract.

### 11.4 Non-determinism

Two identical consults may return different answers. For regulated internal use this needs retrieval-grounded answers or recorded-transcript review. Out of scope here; worth naming before a compliance conversation rather than during one.

### 11.5 Staleness

Nothing defines how long a consulted answer stays valid. An agent caching "Q3 budget is X" across a re-forecast is wrong in a way nothing here detects.

### 11.6 Org bootstrap

Setting this up — minting the org identity, delegating department agents, distributing declarations — has no defined flow. A real product needs `aroha org init` and a joining path; day-one experience is undesigned.

---

## 12. Non-goals

Deferred, not deleted:

- **Public reachability** — no tunnels, no public URLs. LAN and relay cover an internal network.
- **Federated discovery / SARs** — a directory of your own agents is not a trust problem.
- **Escrow, settlement, payments** — internal cost accounting, not payments.
- **Arbitration** — an internal dispute is resolved by a manager.
- **Brand-adjacent verification, vanity names** — the namespace is org-controlled.

---

## 13. Testing

Following this codebase's preference for real infrastructure over mocks:

- **Two real runtimes, real envelopes** — mirroring `lan-server.test.ts`, which already runs a genuine `ArohaServer` with real sealed/signed requests. Engine faked; everything below it real.
- **Loop refusal** — A→B→A refused at the third hop; chain terminates.
- **Hop limit** — a 4-deep chain refused at the configured limit.
- **PII redaction** — a question with an email and phone crosses stripped; audit names categories without storing values.
- **Delegation** — no credential refused; credential signed by a different org key refused.
- **Consult tool restriction** — a consult that triggers a tier-4 tool is refused, not escalated.
- **Signed approval** — an action request without `SignedInvariants` refused; with a valid one, executed; with parameters mutated after signing, refused.
- **Idempotency** — the same `idempotencyKey` replayed executes once and returns the original result.
- **Audit completeness** — every outcome branch writes exactly one record.

---

## 14. Build order

1. **Common infrastructure** — hop/loop checks, org delegation verification, capability declarations.
2. **Consult path** — composer, outbound screener, read-only tool policy, provenance in response.
3. **Audit log** — from day one, not retrofitted.
4. **Operator console** — including the chain trace; makes it deployable, not merely functional.
5. **Action request path** — policy layer, signed approval, idempotency, evidence.
6. **Quotas + triage.**
7. **Chat UI affordances** — invite an agent, see contributions attributed and visually distinct; approve action requests inline.

Human identity (§11.1) gates step 5 for regulated deployments and should be designed in parallel.

---

## 15. Disclosed limitations

- **PII screening is pattern-based** — structured identifiers only; free-text names are not reliably caught.
- **Identity-by-reference limits who sees data, not how much** — the party with a legal need still receives it in full (§6.3). No cryptography removes a regulatory requirement.
- **Selective attribute disclosure has a primitive but no credential flow** (§11.2) — `@aroha-sdk/bbs` is built and vector-verified, unaudited, and wired into no trust decision.
- **Issuer trust remains unsolved** — `verifyCertificate` proves a key signed a certificate, not that the issuer is trustworthy. Real-world verification still requires a trusted party.
- **Quota state is in-memory in v1** — a process restart resets it. An attacker cannot force your restart, so this is bounded, but real.
- **No human identity** (§11.1) — `approvedByDid` is unpopulated until that gap is closed.
- **Behavioural versioning and non-determinism are unsolved** (§11.3, §11.4) — detectable, not prevented.
- **Provenance outside the channel is best-effort** — hash lookup catches unedited and lightly-edited reuse, not paraphrase.
