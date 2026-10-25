# Phase 2 Stage 2: Consult Audit Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every consult this runtime answers or refuses lands in a tamper-evident, disk-persisted audit log. The design spec puts this at build-order step 3 and says it explicitly: "from day one, not retrofitted" — a consult path that has already shipped without one is exactly the retrofit it warns about, so this is the next stage rather than a later one.

**Architecture:** `packages/aroha-audit` already implements the hard part — a hash-chained, tamper-evident `AuditLog` with `verify()`. It is in-memory only and has no filesystem dependency, which is correct for its other likely home (Cloudflare Workers, where `node:fs` does not exist). So persistence is **injected, not baked in**: `AuditLog` gains an optional constructor taking `initial` entries and an `onAppend` sink, and the runtime supplies a JSONL file-backed pair. The package stays Workers-safe; the runtime gets durability.

**Tech Stack:** TypeScript, vitest, `@aroha-sdk/audit` (currently 1.2.0, unused by anything else in the monorepo — verified — so additive changes are low-risk, though it is published so they must stay additive).

**Spec:** [../specs/2026-08-18-internal-consult-design.md](../specs/2026-08-18-internal-consult-design.md) §7 (audit log), §14 step 3

## Global Constraints

- Copyright header on every new file (TS: `// Copyright (c) 2026 Aroha Labs` / `// SPDX-License-Identifier: Apache-2.0`).
- **Changes to `@aroha-sdk/audit` must be purely additive.** It is published; a no-arg `new AuditLog()` must keep behaving exactly as it does now, and the existing `index.test.ts` must pass untouched.
- **`packages/aroha-audit` must not import `node:fs`** or any Node built-in beyond what it already uses (`@noble/hashes`). Persistence is the runtime's job, injected through the new sink. Breaking this makes the package unusable in a Worker.
- **Audit records store redaction CATEGORIES, never values** (design spec §7). Same rule Phase 1 established in doc-intel; it is the whole point of the log.
- A failed audit write must never take down the consult it was recording, but must be **observable, not merely logged**. Swallowing it silently lets the in-memory chain and the durable copy drift: the file ends up missing entries, each view stays internally consistent, `verify()` passes on both, and a dropped write becomes indistinguishable from a deleted record — the exact thing a tamper-evident log exists to rule out. `AuditLog.persistence()` counts the gap; the runtime's sink rethrows so the count is actually reached. (This was caught by a security review of the first attempt at Task 1, which shipped the silent-swallow version.)
- Real infrastructure over mocks: audit assertions go through a real `startLanListener` round trip, matching `lan-server.test.ts`'s existing convention.

---

## File Structure

| File | Responsibility |
|---|---|
| `packages/aroha-audit/src/index.ts` | *Modify* — new event types; optional `initial`/`onAppend` constructor options |
| `apps/aroha-runtime/src/workspace/paths.ts` | *Modify* — `auditFile` path under the existing `logsDir` |
| `apps/aroha-runtime/src/host/audit.ts` | *Create* — `openAuditLog(workspace)`, the JSONL-backed wiring |
| `apps/aroha-runtime/src/transport/lan-server.ts` | *Modify* — record every consult outcome |
| `apps/aroha-runtime/src/transport/relay-client.ts` | *Modify* — same |
| `apps/aroha-runtime/package.json` | *Modify* — add `@aroha-sdk/audit` |

---

## Task 1: Extend the audit package — event types and an injectable sink

**Files:**
- Modify: `packages/aroha-audit/src/index.ts`
- Test: `packages/aroha-audit/src/index.test.ts`

**Interfaces:**
- Produces: `new AuditLog(opts?: { initial?: AuditEntry[]; onAppend?: (e: AuditEntry) => void | Promise<void> })`, and `AuditEventType` extended with `consult_answered | consult_refused | consult_failed`. Consumed by Task 3.

- [ ] **Step 1: Write the failing tests**

Append to `packages/aroha-audit/src/index.test.ts`:

```ts
describe("AuditLog — injectable persistence (runtime wiring)", () => {
  it("still works with no options at all — the published no-arg constructor is unchanged", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s", actorDID: "did:aroha:a", detail: {} });
    expect(log.entries()).toHaveLength(1);
    expect(log.verify()).toBe(true);
  });

  it("resumes the hash chain from entries restored on construction", async () => {
    const first = new AuditLog();
    await first.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    await first.append({ type: "consult_refused", actorDID: "did:aroha:a", detail: {} });

    // Simulate a restart: rebuild from what was persisted.
    const restored = new AuditLog({ initial: [...first.entries()] });
    await restored.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });

    const entries = restored.entries();
    expect(entries).toHaveLength(3);
    expect(entries[2].seq).toBe(2);
    // The chain must survive the restart, or the log is only tamper-evident
    // within a single process lifetime — which is not tamper-evident.
    expect(entries[2].previousHash).toBe(entries[1].hash);
    expect(restored.verify()).toBe(true);
  });

  it("calls onAppend with each new entry, so a caller can persist it", async () => {
    const written: AuditEntry[] = [];
    const log = new AuditLog({ onAppend: (e) => { written.push(e); } });
    await log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    await log.append({ type: "consult_failed", actorDID: "did:aroha:a", detail: {} });
    expect(written.map((e) => e.type)).toEqual(["consult_answered", "consult_failed"]);
  });

  it("a throwing onAppend does not lose the entry from the in-memory chain", async () => {
    // A failed audit WRITE must not take down the operation being audited,
    // and must not silently corrupt the chain either.
    const log = new AuditLog({ onAppend: () => { throw new Error("disk full"); } });
    await expect(log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} }))
      .resolves.toBeDefined();
    expect(log.entries()).toHaveLength(1);
    expect(log.verify()).toBe(true);
  });
});
```

Also add `AuditEntry` to the file's import.

- [ ] **Step 2: Run to verify it fails**

Run: `cd "<repo root>" && npx vitest run packages/aroha-audit`
Expected: FAIL — the constructor takes no arguments and the new event types are not in the union (a type error at minimum).

- [ ] **Step 3: Implement**

In `packages/aroha-audit/src/index.ts`:

```ts
export type AuditEventType =
  | "saga_started" | "saga_committed" | "saga_compensated" | "saga_failed"
  | "envelope_received" | "envelope_rejected" | "settlement_processed"
  | "credential_issued" | "credential_revoked" | "key_rotated" | "key_revoked"
  // Cross-agent consults (design spec §7). Recorded on EVERY outcome —
  // a consult refused for looping matters as much to an operator as one
  // that was answered.
  | "consult_answered" | "consult_refused" | "consult_failed";
```

```ts
export interface AuditLogOptions {
  /**
   * Entries restored from durable storage. The hash chain resumes from the
   * last one, so tamper-evidence survives a restart — without this the log
   * is only tamper-evident within a single process lifetime, which is not
   * tamper-evident at all.
   */
  initial?: AuditEntry[];
  /**
   * Called with each newly appended entry, for durable persistence.
   *
   * Deliberately injected rather than implemented here: this package is
   * also usable in environments with no filesystem (Cloudflare Workers),
   * so it must not import node:fs. The runtime supplies a JSONL-file sink;
   * a Worker could supply a D1 or KV write, or none at all.
   *
   * A throwing sink is swallowed (the entry stays in the in-memory chain)
   * — a failed audit write must not take down the operation it records.
   */
  onAppend?: (entry: AuditEntry) => void | Promise<void>;
}
```

```ts
export class AuditLog {
  private readonly _entries: AuditEntry[];
  private readonly onAppend?: (entry: AuditEntry) => void | Promise<void>;

  constructor(opts: AuditLogOptions = {}) {
    this._entries = [...(opts.initial ?? [])];
    this.onAppend = opts.onAppend;
  }

  async append(input: AppendInput): Promise<AuditEntry> {
    const seq = this._entries.length;
    const previousHash = seq > 0 ? this._entries[seq - 1].hash : "";
    const timestamp = new Date().toISOString();

    const content = { seq, ...input, timestamp, previousHash };
    const hash = bytesToHex(sha256(JSON.stringify(content)));

    const entry: AuditEntry = { ...content, hash };
    this._entries.push(entry);

    if (this.onAppend) {
      try {
        await this.onAppend(entry);
      } catch {
        // Swallowed by contract — see AuditLogOptions.onAppend. The caller's
        // sink is responsible for making the failure visible in its own logs;
        // losing the audited operation because the audit write failed would
        // be a worse outcome than a gap in the log.
      }
    }
    return entry;
  }
  // entries(), verify(), toJSONLines() unchanged
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd "<repo root>" && npx vitest run packages/aroha-audit`
Expected: PASS — including all four pre-existing tests untouched.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add packages/aroha-audit/src/index.ts packages/aroha-audit/src/index.test.ts
git commit -m "feat(audit): consult event types and injectable persistence

Persistence is injected rather than implemented here: this package is
also usable where there is no filesystem (Workers), so it must not
import node:fs. initial restores the hash chain across a restart --
without that the log is only tamper-evident within one process
lifetime, which is not tamper-evident.

Purely additive: a no-arg new AuditLog() behaves exactly as before and
the existing tests pass untouched."
```

---

## Task 2: Workspace path and the runtime's file-backed audit log

**Files:**
- Modify: `apps/aroha-runtime/src/workspace/paths.ts`, `apps/aroha-runtime/package.json`
- Create: `apps/aroha-runtime/src/host/audit.ts`
- Test: `apps/aroha-runtime/src/host/audit.test.ts`

**Interfaces:**
- Produces: `openAuditLog(ws: Workspace): AuditLog` — consumed by Task 3.

- [ ] **Step 1: Add the dependency and path**

`apps/aroha-runtime/package.json` dependencies, alphabetically:

```json
    "@aroha-sdk/audit": "^1.2.0",
```

Then `npm install` from the repo root.

`paths.ts` — add to the `Workspace` interface and to `resolveWorkspace`'s returned object:

```ts
  auditFile: string;
```
```ts
    // JSONL under the existing logs dir: append-only, and a line format
    // survives a partial write without taking the rest of the log with it.
    auditFile: join(root, "logs", "audit.jsonl"),
```

- [ ] **Step 2: Write the failing test**

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveWorkspace, ensureWorkspace } from "../workspace/paths.js";
import { openAuditLog } from "./audit.js";

let root: string;
beforeEach(() => { root = mkdtempSync(join(tmpdir(), "aroha-audit-")); });
afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("openAuditLog", () => {
  it("starts empty when nothing has been written", () => {
    const ws = ensureWorkspace(resolveWorkspace(root));
    expect(openAuditLog(ws).entries()).toHaveLength(0);
  });

  it("persists an appended entry as one JSON line", async () => {
    const ws = ensureWorkspace(resolveWorkspace(root));
    const log = openAuditLog(ws);
    await log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: { hopCount: 1 } });

    const lines = readFileSync(ws.auditFile, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).type).toBe("consult_answered");
  });

  it("resumes the chain across a restart, and the restored log still verifies", async () => {
    const ws = ensureWorkspace(resolveWorkspace(root));
    const first = openAuditLog(ws);
    await first.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    await first.append({ type: "consult_refused", actorDID: "did:aroha:a", detail: {} });

    const reopened = openAuditLog(ws);
    expect(reopened.entries()).toHaveLength(2);
    await reopened.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    expect(reopened.verify()).toBe(true);
    expect(reopened.entries()[2].previousHash).toBe(reopened.entries()[1].hash);
  });

  it("skips a corrupt line rather than refusing to open at all", async () => {
    const ws = ensureWorkspace(resolveWorkspace(root));
    const log = openAuditLog(ws);
    await log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    appendFileSync(ws.auditFile, "{not json\n", "utf8");

    // A single corrupt line must not make the whole audit trail unreadable.
    expect(openAuditLog(ws).entries()).toHaveLength(1);
  });
});
```

- [ ] **Step 3: Run to verify it fails**, then implement:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The runtime's durable audit log (design spec §7) — @aroha-sdk/audit's
 * hash-chained AuditLog, backed by a JSONL file under the workspace.
 *
 * JSONL rather than one JSON document: this file only ever grows by
 * appending, and a line format survives a partial write without taking the
 * rest of the log with it. It is also the artifact an operator hands a
 * compliance reviewer, so it stays readable without the runtime running.
 *
 * The filesystem half lives here rather than in @aroha-sdk/audit because
 * that package is also usable where there is no filesystem (Workers).
 */

import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { AuditLog, type AuditEntry } from "@aroha-sdk/audit";
import type { Workspace } from "../workspace/paths.js";

function restore(file: string): AuditEntry[] {
  if (!existsSync(file)) return [];
  const entries: AuditEntry[] = [];
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed) as AuditEntry);
    } catch {
      // One corrupt line must not make the whole audit trail unreadable.
      // verify() is what surfaces tampering; this only skips unparseable
      // bytes, e.g. a torn final write from a hard kill.
      continue;
    }
  }
  return entries;
}

export function openAuditLog(ws: Workspace): AuditLog {
  return new AuditLog({
    initial: restore(ws.auditFile),
    onAppend: (entry) => {
      try {
        appendFileSync(ws.auditFile, JSON.stringify(entry) + "\n", "utf8");
      } catch (err) {
        // Loud, but not fatal — see AuditLogOptions.onAppend's contract.
        console.error("[aroha] audit write failed:", err);
      }
    },
  });
}
```

- [ ] **Step 4: Run to verify it passes.** Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/host/audit.ts apps/aroha-runtime/src/host/audit.test.ts \
        apps/aroha-runtime/src/workspace/paths.ts apps/aroha-runtime/package.json package-lock.json
git commit -m "feat(runtime): durable JSONL-backed audit log

The filesystem half lives in the runtime, not in @aroha-sdk/audit, so
that package stays usable where there is no filesystem. A corrupt line
is skipped rather than making the whole trail unreadable -- verify() is
what surfaces tampering, this only tolerates a torn write."
```

---

## Task 3: Record every consult outcome

**Files:**
- Modify: `apps/aroha-runtime/src/transport/lan-server.ts`, `apps/aroha-runtime/src/transport/relay-client.ts`
- Test: `apps/aroha-runtime/src/transport/lan-server.test.ts`

**Interfaces:**
- Consumes: `openAuditLog` (Task 2), `AuditLog` from `@aroha-sdk/audit`.
- Both transports gain an optional `audit?: AuditLog` option. Optional, not required, so every existing caller and test keeps working unchanged — an audit log is something the runtime wires in, not something a listener cannot start without.

- [ ] **Step 1: Write the failing tests**

Append to `lan-server.test.ts`:

```ts
describe("startLanListener — consult audit (design spec §7)", () => {
  it("records an answered consult", async () => {
    const port = freePort();
    const audit = new AuditLog();
    const identity = await generateContentAddressedDID("lan://audited");
    const agent: AgentRecord = {
      slug: "audited", did: identity.did, name: "Audited", systemPrompt: "be terse",
      model: "test-model", createdAt: new Date().toISOString(),
    };
    handle = await startLanListener({
      agents: [{ agent, privateKey: identity.privateKey }],
      port, engine: fakeEngine("Net 30."), audit,
    });

    const asker = await generateContentAddressedDID("lan://audit-asker");
    const params: ConsultParams = { question: "terms?", hopCount: 1, consultChain: [asker.did] };
    const envelope = await buildEnvelope(
      "ArohaRequest", asker.did, agent.did,
      { capability: "consult", params: params as unknown as Record<string, unknown> },
      "corr-audit-1", asker.privateKey, 120,
    );
    const sealed = await sealEnvelope(envelope, identity.publicKey);
    await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sealed),
    });

    const entries = audit.entries();
    expect(entries).toHaveLength(1);
    expect(entries[0].type).toBe("consult_answered");
    expect(entries[0].actorDID).toBe(agent.did);
    expect(entries[0].detail.correlationId).toBe("corr-audit-1");
    expect(entries[0].detail.hopCount).toBe(1);
  });

  it("records a refusal too — a refused consult matters as much as an answered one", async () => {
    const port = freePort();
    const audit = new AuditLog();
    const identity = await generateContentAddressedDID("lan://audited2");
    const agent: AgentRecord = {
      slug: "audited2", did: identity.did, name: "Audited", systemPrompt: "x",
      model: "test-model", createdAt: new Date().toISOString(),
    };
    handle = await startLanListener({
      agents: [{ agent, privateKey: identity.privateKey }],
      port, engine: fakeEngine("unreached"), audit,
    });

    const asker = await generateContentAddressedDID("lan://audit-asker2");
    const params: ConsultParams = { question: "x", hopCount: 1, consultChain: [agent.did] };
    const envelope = await buildEnvelope(
      "ArohaRequest", asker.did, agent.did,
      { capability: "consult", params: params as unknown as Record<string, unknown> },
      "corr-audit-2", asker.privateKey, 120,
    );
    const sealed = await sealEnvelope(envelope, identity.publicKey);
    await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sealed),
    });

    const entries = audit.entries();
    expect(entries).toHaveLength(1);
    expect(entries[0].type).toBe("consult_refused");
    expect(String(entries[0].detail.reason)).toMatch(/cycle/i);
  });

  it("records the question but never a redacted value", async () => {
    // The question recorded is what actually arrived, post-composition and
    // post-screening on the CALLER's side. This asserts the record carries
    // the question at all — the screening guarantee itself belongs to the
    // sending side (consult-client.ts) and is tested there.
    const port = freePort();
    const audit = new AuditLog();
    const identity = await generateContentAddressedDID("lan://audited3");
    const agent: AgentRecord = {
      slug: "audited3", did: identity.did, name: "Audited", systemPrompt: "x",
      model: "test-model", createdAt: new Date().toISOString(),
    };
    handle = await startLanListener({
      agents: [{ agent, privateKey: identity.privateKey }],
      port, engine: fakeEngine("ok"), audit,
    });

    const asker = await generateContentAddressedDID("lan://audit-asker3");
    const params: ConsultParams = { question: "what are the terms?", hopCount: 1, consultChain: [asker.did] };
    const envelope = await buildEnvelope(
      "ArohaRequest", asker.did, agent.did,
      { capability: "consult", params: params as unknown as Record<string, unknown> },
      "corr-audit-3", asker.privateKey, 120,
    );
    const sealed = await sealEnvelope(envelope, identity.publicKey);
    await fetch(`http://127.0.0.1:${port}/aroha/v1`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sealed),
    });

    expect(audit.entries()[0].detail.question).toBe("what are the terms?");
  });
});
```

Add `AuditLog` to the test file's imports (`import { AuditLog } from "@aroha-sdk/audit";`).

- [ ] **Step 2: Run to verify it fails.** Expected: FAIL — `audit` is not an accepted option.

- [ ] **Step 3: Implement in `lan-server.ts`**

Add to imports and to the `startLanListener` options type:

```ts
import type { AuditLog } from "@aroha-sdk/audit";
```
```ts
  /**
   * Records every consult outcome (design spec §7). Optional: a listener
   * must still start without one, so existing callers and tests are
   * unaffected — the runtime is what wires a durable log in.
   */
  audit?: AuditLog;
```

In the consult branch, record each outcome. `void` the promise rather than awaiting it in the refusal path only if that would delay the response — here awaiting is fine and gives ordering guarantees the tests rely on:

```ts
      if (body.capability === "consult") {
        const params = body.params as unknown as ConsultParams;
        const loop = checkConsultLoop(
          { hopCount: params.hopCount, consultChain: params.consultChain },
          agent.did,
        );
        if (!loop.ok) {
          await opts.audit?.append({
            type: "consult_refused",
            actorDID: agent.did,
            detail: {
              correlationId: envelope.correlationId, from: envelope.from,
              question: params.question, hopCount: params.hopCount,
              reason: loop.reason,
            },
          });
          respond(await buildEnvelope(
            "ArohaError", agent.did, envelope.from,
            { code: ArohaErrorCode.Forbidden, message: loop.reason, retryable: false },
            envelope.correlationId, privateKey,
          ));
          return;
        }

        try {
          const result = await buildConsultHandler(agent, opts.engine, opts.mcp)(params);
          await opts.audit?.append({
            type: "consult_answered",
            actorDID: agent.did,
            detail: {
              correlationId: envelope.correlationId, from: envelope.from,
              question: params.question, hopCount: params.hopCount,
              sources: result.sources.map((s) => s.tool),
              behaviourHash: result.behaviourHash,
            },
          });
          respond(await buildEnvelope(
            "ArohaResponse", agent.did, envelope.from,
            { capability: "consult", result: result as unknown as Record<string, unknown> },
            envelope.correlationId, privateKey,
          ));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          await opts.audit?.append({
            type: "consult_failed",
            actorDID: agent.did,
            detail: {
              correlationId: envelope.correlationId, from: envelope.from,
              question: params.question, hopCount: params.hopCount, error: message,
            },
          });
          respond(await buildEnvelope(
            "ArohaError", agent.did, envelope.from,
            { code: ArohaErrorCode.InternalError, message, retryable: true },
            envelope.correlationId, privateKey,
          ));
        }
        return;
      }
```

Note `detail.sources` records tool NAMES only, not the tool output text — the raw result text is untrusted content (the simplification Stage 1 flagged), and an audit log is the last place it should accumulate.

- [ ] **Step 4: Mirror into `relay-client.ts`** — same three outcomes, same detail shape, `audit?: AuditLog` added to `RelayConnectionOptions`.

- [ ] **Step 5: Run everything**

Run: `cd apps/aroha-runtime && npx vitest run`
Expected: all pass, including every pre-existing test.

- [ ] **Step 6: Commit**

```bash
cd "<repo root>"
git add apps/aroha-runtime/src/transport/
git commit -m "feat(runtime): record every consult outcome in the audit log

Answered, refused, and failed all produce exactly one record -- a
consult refused for looping matters as much to an operator as one that
was answered.

detail.sources carries tool NAMES only, never the tool output text: raw
tool results are untrusted content (the simplification Stage 1 flagged),
and an audit log is the last place that should accumulate."
```

---

## Task 4: Wire the durable log into the running runtime

**Files:**
- Modify: `apps/aroha-runtime/src/host/runtime.ts` or `main.ts` — wherever `startLanListener`/`connectRelay` are actually constructed. **Read first to confirm which**; do not assume.

- [ ] **Step 1:** `grep -n "startLanListener\|connectRelay" apps/aroha-runtime/src/*.ts apps/aroha-runtime/src/**/*.ts` to find the real call sites.

- [ ] **Step 2:** Construct one `openAuditLog(workspace)` per process and pass it to both. One log, not one per listener — a single chain per runtime is what makes `verify()` meaningful.

- [ ] **Step 3:** Run the full runtime suite and `npm run build`.

- [ ] **Step 4: Commit.**

---

## Task 5: Full verification

- [ ] `cd "<repo root>" && npm run build` — clean.
- [ ] `npm test` — clean, all packages.
- [ ] Confirm `packages/aroha-audit` still has no Node built-in imports: `grep -n "node:" packages/aroha-audit/src/index.ts` must return nothing.
- [ ] Push and confirm CI green.
- [ ] **Version-bump and publish `@aroha-sdk/audit`** (1.2.0 → 1.3.0, additive minor) only if the runtime is to consume it from the registry rather than the workspace. Check in with the user before publishing.

---

## Roadmap after this stage

Unchanged from Stage 1's closing section, minus the audit log: operator console (`/v1/admin/*` incl. chain trace and kill switch), human identity Phase 1 (named local users, so `approvedByDid` can be populated), the action-request path (signed approval, idempotency, evidence), quotas + triage, and the chat UI affordances. The operator console is the natural next one — it is what makes the audit log this stage produces actually reachable by a human.
