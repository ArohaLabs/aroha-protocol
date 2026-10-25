# Phase 2 Stage 7: Chat UI Affordances

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the last six stages reachable by a human. Three things: approve or reject a pending tool call inline, see when an answer came from another agent rather than your own, and invite a peer into a conversation.

**Architecture:** `ui/page.ts` stays a single file with no build step — the deliberate M2 constraint, and this stage does not grow the surface past what one file holds legibly. Two new gateway routes back the invite affordance (`GET /v1/peers`, `POST /v1/peers/consult`), following `handleAdminApi`'s shape exactly.

**Tech Stack:** TypeScript, vanilla JS in a template literal, vitest for structural + route tests.

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §14 step 7

## Global Constraints

- Copyright header on new files.
- **No framework, no build step.** The UI file's own docstring says a framework is worth reaching for "once the UI surface grows past what one file can hold legibly — not before." Three affordances do not cross that line; adding a build step here would be the change, not the feature.
- **`innerHTML` is off-limits for anything agent-supplied.** The file already avoids it deliberately for exactly this reason. A consult answer is a REMOTE agent's text — the least trustworthy string in the product — so it must go through `textContent`.
- **A consult contribution must be visually distinct and attributed.** An answer from someone else's agent rendering identically to your own agent's is the misattribution the audit log exists to prevent, reintroduced at the only layer a human actually looks at.
- Approve/reject must send the real decision to the real `/v1/resume` route. The mechanism already works end-to-end; only the affordance is missing.

---

## Task 1: Inline approve/reject

**Files:** `src/ui/page.ts` (+ `src/ui/page.test.ts`)

The current handler is a stub, and its own comment is now stale — it says an inline affordance is "real scope once a tool that actually requests approval exists (M3)". MCP tools exist, and `mcp.decide()` returns `"gate"` verdicts today, so `approval_required` genuinely fires and a user has no way to answer it. The stream stays suspended until the 5-minute timeout and then fails.

```js
} else if (evt.type === "approval_required") {
  renderApprovalPrompt(evt, assistantEl);
}
```

`renderApprovalPrompt` builds a distinct block showing the tool name, the arguments, and the stated reason, with Approve and Reject buttons. On click it POSTs to the agent's `/v1/resume`:

```js
await api("/v1/agents/" + activeSlug + "/v1/resume", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ approvalId: evt.id, sessionId: sessionId, decision: decision }),
});
```

Details that matter:
- **Both buttons disable on click**, and the block records which was chosen. A double-approve would 404 on the second (the pending entry is deleted), but a user who cannot tell whether their click registered will click again — the feedback is the point.
- **Arguments render via `textContent`**, never `innerHTML`: they may contain content derived from a prior tool result, which is untrusted by construction (§9.1 Layer 3 is exactly why this call is gated).
- The SSE stream stays open throughout; resume is a separate request that unblocks it. No reconnection needed.

- [ ] Tests (structural — `renderApp()` returns a string, and there is no DOM harness in this project): the returned page contains the resume POST, both decisions, and no `innerHTML` assignment for approval content. State plainly in the test file that these are structural assertions and do not exercise the DOM.

- [ ] Commit.

---

## Task 2: Attributed contributions

**Files:** `src/ui/page.ts`

- [ ] A `.msg.peer` class, visually distinct from `.assistant` (left border in the accent colour, plus a small attributed header line).
- [ ] `addPeerMessage(peerName, peerDid, text)` renders the header as `name · did` with the DID in monospace, matching how DIDs are already presented elsewhere in this product, and the body via `textContent`.
- [ ] The header is not optional and not collapsible. If a human cannot tell at a glance that an answer came from another firm's agent, every downstream control that depends on that distinction is decoration.

- [ ] Commit.

---

## Task 3: Invite a peer

**Files:** `src/gateway/server.ts`, new `src/gateway/peers-api.ts`, `src/ui/page.ts`

Two routes, gated on an optional `peers` field in `GatewayOptions` the way every other feature area already gates:

| Route | Purpose |
|---|---|
| `GET /v1/peers` | LAN-discovered Aroha agents (`discoverLan`) |
| `POST /v1/peers/consult` | Compose, screen, and send a consult to one; returns the answer and redaction categories |

`POST /v1/peers/consult` takes `{ peerDid, endpoint, question }` and calls the existing `sendConsult`. It needs the local agent's key to sign as, so it takes `asAgent` (a slug) the way the Hub call route already does.

- [ ] The response includes `redactions` so the UI can tell the user what was withheld. A user who does not know their question was altered before sending cannot judge the answer they got back.
- [ ] Discovery has a fixed timeout window; the route should not hang the UI. Use the existing 3s default and say so in the response.
- [ ] UI: an "Invite an agent" button opening a dialog that lists discovered peers, sends the question, and renders the answer with `addPeerMessage` plus a withheld-categories note when non-empty.
- [ ] Tests: both routes through a real gateway; a consult to an unreachable peer returns a clean error rather than hanging.

- [ ] Commit.

---

## Task 4: Full verification

- [ ] Runtime suite, `npm run build`, `npm test`, push, CI green.

---

## Disclosed limitations

- **No DOM tests.** This project has no browser test harness, and adding one for three affordances would be a larger change than the affordances. The tests here assert the page's structure, not its behaviour — genuinely weaker, and worth saying rather than implying otherwise. The routes behind the UI *are* tested for real.
- **Peer discovery is LAN-only and one-shot.** `discoverLan` browses for a fixed window; a peer that appears a second later is not listed until the user reopens the dialog.
- **The invite flow sends one question and renders one answer.** It does not thread a peer into the ongoing conversation — the consult is a single exchange, which is what the protocol models.
