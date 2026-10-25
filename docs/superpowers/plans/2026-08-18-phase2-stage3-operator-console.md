# Phase 2 Stage 3: Operator Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the audit log Stage 2 produces reachable by a human, and give an operator a way to stop inbound consults immediately. The design spec is blunt about why this is not optional: "An operator who cannot immediately stop their agent will not deploy it."

**Architecture:** A new `handleAdminApi` in the gateway, following the exact shape of the existing `handleAgentsApi`/`handleHubApi` — a flat set of `/v1/admin/*` routes behind the same guard every other route already passes through, gated on an optional `admin` field in `GatewayOptions` the way each feature area already gates on its own optional dependency. The kill switch is a tiny piece of shared mutable state (`AdminControls`) that the transports consult before answering, and that the gateway can flip.

**Tech Stack:** TypeScript, vitest, `node:http` (the gateway's existing base).

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §8 (operator console), §14 step 4

## Global Constraints

- Copyright header on every new file.
- **No new auth surface.** These routes sit behind the existing bearer token, exactly like every other route — `checkRequest` already runs before any dispatch and there is no per-route auth hook. Per-user identity is Stage 4's job; building a second auth mechanism here would have to be undone.
- **The kill switch must be checked before any model call**, next to the loop guard, for the same reason: refusing is free, answering is not.
- **A killed consult is still audited.** An operator who hits the switch needs to see what got refused while it was on, or the switch creates exactly the blind spot the audit log exists to close.
- Two spec routes are deliberately NOT built here and must be named as such rather than silently skipped:
  - `GET /v1/admin/quotas` — there are no quotas yet (Stage 5). A route reporting nothing would imply a control that does not exist.
  - The kill switch covers **consults**, not action requests, because action requests do not exist yet (Stage 4/5). It is the analogous control over the traffic this runtime actually serves today.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/src/host/admin.ts` | *Create* — `AdminControls`: the kill switch, and audit querying |
| `apps/aroha-runtime/src/gateway/admin-api.ts` | *Create* — `handleAdminApi`, the `/v1/admin/*` routes |
| `apps/aroha-runtime/src/gateway/server.ts` | *Modify* — dispatch to it; `admin` on `GatewayOptions` |
| `apps/aroha-runtime/src/transport/lan-server.ts` | *Modify* — honour the kill switch |
| `apps/aroha-runtime/src/transport/relay-client.ts` | *Modify* — same |
| `apps/aroha-runtime/src/main.ts` | *Modify* — construct one `AdminControls`, share it |

---

## Task 1: AdminControls — kill switch and audit queries

**Files:**
- Create: `apps/aroha-runtime/src/host/admin.ts`
- Test: `apps/aroha-runtime/src/host/admin.test.ts`

**Interfaces:**
- Produces: `class AdminControls { constructor(audit: AuditLog); consultsDisabled(): boolean; setConsultsDisabled(v: boolean, actor?: string): Promise<void>; interactions(filter): AuditEntry[]; trace(correlationId): AuditEntry[]; }`

- [ ] **Step 1: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { AuditLog } from "@aroha-sdk/audit";
import { AdminControls } from "./admin.js";

async function seed(audit: AuditLog) {
  await audit.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: { correlationId: "c1", hopCount: 1 } });
  await audit.append({ type: "consult_refused",  actorDID: "did:aroha:a", detail: { correlationId: "c2", hopCount: 4 } });
  await audit.append({ type: "consult_answered", actorDID: "did:aroha:b", detail: { correlationId: "c3", hopCount: 1 } });
  await audit.append({ type: "consult_failed",   actorDID: "did:aroha:b", detail: { correlationId: "c1", hopCount: 2 } });
}

describe("AdminControls — kill switch", () => {
  it("starts enabled — a fresh runtime serves consults", () => {
    expect(new AdminControls(new AuditLog()).consultsDisabled()).toBe(false);
  });

  it("flips, and records the flip in the audit log", async () => {
    const audit = new AuditLog();
    const admin = new AdminControls(audit);

    await admin.setConsultsDisabled(true, "did:aroha:operator");
    expect(admin.consultsDisabled()).toBe(true);

    await admin.setConsultsDisabled(false, "did:aroha:operator");
    expect(admin.consultsDisabled()).toBe(false);

    // Flipping a kill switch is itself an auditable act — otherwise the log
    // shows a gap in traffic with no explanation for it.
    const flips = audit.entries().filter((e) => e.type === "admin_consults_toggled");
    expect(flips).toHaveLength(2);
    expect(flips[0].detail.disabled).toBe(true);
    expect(flips[1].detail.disabled).toBe(false);
    expect(flips[0].actorDID).toBe("did:aroha:operator");
  });
});

describe("AdminControls — interactions", () => {
  it("returns newest first", async () => {
    const audit = new AuditLog();
    await seed(audit);
    const rows = new AdminControls(audit).interactions({});
    expect(rows[0].detail.correlationId).toBe("c1");   // the last one appended
    expect(rows).toHaveLength(4);
  });

  it("filters by agent and by type", async () => {
    const audit = new AuditLog();
    await seed(audit);
    const admin = new AdminControls(audit);
    expect(admin.interactions({ agent: "did:aroha:a" })).toHaveLength(2);
    expect(admin.interactions({ type: "consult_refused" })).toHaveLength(1);
  });

  it("paginates", async () => {
    const audit = new AuditLog();
    await seed(audit);
    const admin = new AdminControls(audit);
    expect(admin.interactions({ limit: 2 })).toHaveLength(2);
    expect(admin.interactions({ limit: 2, offset: 3 })).toHaveLength(1);
  });

  it("caps an absurd limit rather than reading the whole log into a response", async () => {
    const audit = new AuditLog();
    await seed(audit);
    expect(new AdminControls(audit).interactions({ limit: 10_000 })).toHaveLength(4);
  });
});

describe("AdminControls — chain trace", () => {
  it("returns every hop of one interaction, oldest first", async () => {
    const audit = new AuditLog();
    await seed(audit);
    // c1 appears twice: answered by one agent, failed at another hop. That
    // cross-agent view is the whole point — cross-agent debugging is this
    // system's worst operational weakness without it.
    const trace = new AdminControls(audit).trace("c1");
    expect(trace).toHaveLength(2);
    expect(trace[0].seq).toBeLessThan(trace[1].seq);
    expect(trace.map((e) => e.actorDID)).toEqual(["did:aroha:a", "did:aroha:b"]);
  });

  it("returns nothing for an unknown correlation id", async () => {
    const audit = new AuditLog();
    await seed(audit);
    expect(new AdminControls(audit).trace("nope")).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify it fails.**

- [ ] **Step 3: Implement.** Add `"admin_consults_toggled"` to `AuditEventType` in `packages/aroha-audit/src/index.ts` first (additive, same as the consult types), rebuild that package (`npx tsc -p packages/aroha-audit/tsconfig.json`) so the runtime's type resolution picks it up.

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Operator controls (design spec §8).
 *
 * Two jobs, deliberately together: reading the audit trail, and being able
 * to stop inbound traffic. The spec is blunt about why the second is not
 * optional — "an operator who cannot immediately stop their agent will not
 * deploy it."
 *
 * The kill switch is process state, not config: it must take effect
 * immediately, not on the next restart, which is the entire point of a kill
 * switch. That also means it does NOT survive a restart — a deliberate
 * trade, disclosed rather than hidden: a runtime that came back up still
 * refusing consults with no visible reason would be worse. Persisting it is
 * a config change, which belongs to whoever decides the restart posture.
 */

import type { AuditEntry, AuditEventType, AuditLog } from "@aroha-sdk/audit";

/** Hard cap on one page, so a caller cannot ask for the whole log at once. */
const MAX_PAGE = 500;

export interface InteractionFilter {
  agent?: string;
  type?: AuditEventType;
  limit?: number;
  offset?: number;
}

export class AdminControls {
  private disabled = false;

  constructor(private readonly audit: AuditLog) {}

  consultsDisabled(): boolean {
    return this.disabled;
  }

  /**
   * Flip the switch. Recorded in the audit log: otherwise the trail shows a
   * gap in traffic with nothing explaining it, and "why did consults stop
   * on Tuesday?" becomes unanswerable from the artifact meant to answer it.
   */
  async setConsultsDisabled(disabled: boolean, actorDID = "operator"): Promise<void> {
    this.disabled = disabled;
    await this.audit.append({
      type: "admin_consults_toggled",
      actorDID,
      detail: { disabled },
    });
  }

  /** Newest first, filtered and paginated. */
  interactions(filter: InteractionFilter): AuditEntry[] {
    const limit = Math.min(Math.max(1, filter.limit ?? 100), MAX_PAGE);
    const offset = Math.max(0, filter.offset ?? 0);
    const matched = this.audit.entries().filter((e) =>
      (filter.agent === undefined || e.actorDID === filter.agent) &&
      (filter.type === undefined || e.type === filter.type)
    );
    return [...matched].reverse().slice(offset, offset + limit);
  }

  /**
   * Every entry sharing one correlationId, oldest first — the full chain of
   * one interaction across every agent that touched it. Cross-agent
   * debugging is this system's worst operational weakness without this, and
   * correlationId already links the hops; this only surfaces it.
   */
  trace(correlationId: string): AuditEntry[] {
    return this.audit.entries().filter((e) => e.detail.correlationId === correlationId);
  }
}
```

- [ ] **Step 4: Run to verify it passes. Step 5: Commit.**

---

## Task 2: The /v1/admin routes

**Files:**
- Create: `apps/aroha-runtime/src/gateway/admin-api.ts`
- Modify: `apps/aroha-runtime/src/gateway/server.ts`
- Test: `apps/aroha-runtime/src/gateway/admin-api.test.ts`

Routes:

| Route | Purpose |
|---|---|
| `GET /v1/admin/interactions?agent=&type=&limit=&offset=` | Paginated audit log |
| `GET /v1/admin/interactions/:correlationId` | Full chain trace of one interaction |
| `GET /v1/admin/status` | Kill-switch state + audit persistence health |
| `POST /v1/admin/consults/disable` / `.../enable` | The kill switch |
| `GET /v1/admin/export` | Whole log as JSONL, for compliance review |

`GET /v1/admin/status` surfaces `audit.persistence()` — the Stage 2 divergence counter. An operator asking "is my audit trail complete?" is exactly who that number was recorded for.

- [ ] **Step 1: Write the failing test** — a real gateway via `startGateway`, matching `agents-api.test.ts`'s existing `call()` helper shape (host/origin/sec-fetch-site/authorization headers). Cover: interactions list, filter, trace, disable→status→enable round trip, export, and that the guard still rejects an unauthenticated admin call.

- [ ] **Step 2: Run to verify it fails. Step 3: Implement** following `handleAgentsApi`'s shape exactly — an exported `async function handleAdminApi(req, res, url, admin): Promise<boolean>` returning false when no path matched, dispatched from `handle()` with `if (opts.admin && url.pathname.startsWith("/v1/admin"))`.

- [ ] **Step 4: Run. Step 5: Commit.**

---

## Task 3: Transports honour the kill switch

**Files:** `lan-server.ts`, `relay-client.ts` (+ their tests)

- [ ] **Step 1: Write failing tests** — with the switch on, a consult is refused with `Aroha_FORBIDDEN`, the engine is never called, and an audit entry is still written.

- [ ] **Step 2–3: Implement.** Add `admin?: AdminControls` to both option types. Check it immediately before the loop guard — both are free, and this one is the operator's explicit instruction so it wins:

```ts
        if (opts.admin?.consultsDisabled()) {
          await opts.audit?.append({
            type: "consult_refused",
            actorDID: agent.did,
            detail: {
              correlationId: envelope.correlationId, from: envelope.from,
              question: params.question, hopCount: params.hopCount,
              reason: "Consults are disabled by the operator",
            },
          });
          respond(/* ArohaError, Forbidden, "Consults are disabled by the operator" */);
          return;
        }
```

- [ ] **Step 4: Run. Step 5: Commit.**

---

## Task 4: Wire into `aroha up`

- [ ] Construct one `AdminControls(audit)` alongside the existing `openAuditLog(ws)`; pass to `startGateway` (`admin`), `startLanListener`, and `connectRelay`.
- [ ] Full runtime suite, `npm run build`, `npm test`, push, confirm CI.

---

## Roadmap after this stage

Human identity Phase 1 (named local users — the last thing blocking `approvedByDid`), then the action-request path, quotas + triage, and the chat UI affordances. Human identity should come before action requests: the spec gates the action-request path on it for any regulated deployment, and retrofitting attribution into an approval flow that already shipped is the harder order.
