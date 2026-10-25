// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { AuditLog, type AuditEntry } from "./index.js";

describe("AuditLog tamper detection", () => {
  it("chains entries — each entry hashes the previous", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s1", actorDID: "did:aroha:a", detail: {} });
    await log.append({ type: "saga_committed", sagaId: "s1", actorDID: "did:aroha:a", detail: {} });
    const entries = log.entries();
    expect(entries[1].previousHash).toBe(entries[0].hash);
  });

  it("detects tampering when an entry is mutated", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s2", actorDID: "did:aroha:b", detail: {} });
    await log.append({ type: "saga_committed", sagaId: "s2", actorDID: "did:aroha:b", detail: {} });
    // Mutate first entry
    (log.entries()[0] as any).sagaId = "tampered";
    expect(log.verify()).toBe(false);
  });

  it("verify returns true for an untampered log", async () => {
    const log = new AuditLog();
    await log.append({ type: "envelope_received", sagaId: "s3", actorDID: "did:aroha:c", detail: { nonce: "abc" } });
    expect(log.verify()).toBe(true);
  });

  it("first entry has empty previousHash", async () => {
    const log = new AuditLog();
    await log.append({ type: "key_rotated", actorDID: "did:aroha:d", detail: {} });
    expect(log.entries()[0].previousHash).toBe("");
  });

  it("toJSONLines produces one JSON object per line", async () => {
    const log = new AuditLog();
    await log.append({ type: "saga_started", sagaId: "s4", actorDID: "did:aroha:e", detail: {} });
    await log.append({ type: "saga_committed", sagaId: "s4", actorDID: "did:aroha:e", detail: {} });
    const lines = log.toJSONLines().split("\n");
    expect(lines).toHaveLength(2);
    const parsed = lines.map(l => JSON.parse(l));
    expect(parsed[0].type).toBe("saga_started");
    expect(parsed[1].type).toBe("saga_committed");
  });
});

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

  it("counts a failed persist instead of swallowing it silently", async () => {
    // The in-memory chain now holds an entry storage does not. On restart the
    // log restores without it, and because each view is internally consistent
    // verify() passes on both — so a dropped write would be indistinguishable
    // from a deleted record unless the drift is recorded somewhere.
    const log = new AuditLog({ onAppend: () => { throw new Error("disk full"); } });
    expect(log.persistence()).toEqual({ failures: 0 });

    await log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    await log.append({ type: "consult_refused", actorDID: "did:aroha:a", detail: {} });

    expect(log.persistence().failures).toBe(2);
    expect(log.persistence().lastError).toBe("disk full");
  });

  it("reports healthy persistence when the sink succeeds", async () => {
    const log = new AuditLog({ onAppend: () => { /* persisted fine */ } });
    await log.append({ type: "consult_answered", actorDID: "did:aroha:a", detail: {} });
    expect(log.persistence()).toEqual({ failures: 0 });
  });
});
