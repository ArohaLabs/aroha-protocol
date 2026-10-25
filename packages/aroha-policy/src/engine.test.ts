// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach } from "vitest";
import { ArohaPolicyEngine } from "./engine.js";
import type { CapabilityPolicy } from "./types.js";

const SENDER = "did:aroha:agent-abc";
const CAP = "book-flight";

function policy(overrides: Partial<CapabilityPolicy>): CapabilityPolicy {
  return { capabilityId: CAP, ...overrides };
}

describe("ArohaPolicyEngine", () => {
  let engine: ArohaPolicyEngine;

  beforeEach(() => {
    engine = new ArohaPolicyEngine();
  });

  // ─── No policy ───────────────────────────────────────────────────────────────

  it("allows any request when no policy is registered", async () => {
    const result = await engine.evaluate(CAP, { amount: 999 }, SENDER);
    expect(result.outcome).toBe("allow");
  });

  // ─── Wildcard policy ─────────────────────────────────────────────────────────

  it("applies wildcard policy when no specific policy matches", async () => {
    engine.addPolicy({
      capabilityId: "*",
      requiredParamKeys: ["userId"],
    });
    const result = await engine.evaluate("some-other-cap", {}, SENDER);
    expect(result.outcome).toBe("deny");
    expect(result.violatedRule).toBe("requiredParamKeys");
  });

  it("prefers specific policy over wildcard", async () => {
    engine.addPolicy({ capabilityId: "*", requiredParamKeys: ["userId"] });
    engine.addPolicy({ capabilityId: CAP }); // no rules — should allow
    const result = await engine.evaluate(CAP, {}, SENDER);
    expect(result.outcome).toBe("allow");
  });

  // ─── requiredParamKeys ───────────────────────────────────────────────────────

  describe("requiredParamKeys", () => {
    beforeEach(() => {
      engine.addPolicy(policy({ requiredParamKeys: ["origin", "dest"] }));
    });

    it("allows when all required keys are present", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK", dest: "NRT" }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("denies when a required key is missing", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK" }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("requiredParamKeys");
      expect(r.reason).toMatch(/"dest"/);
    });

    it("denies when all required keys are missing", async () => {
      const r = await engine.evaluate(CAP, {}, SENDER);
      expect(r.outcome).toBe("deny");
    });
  });

  // ─── allowedParamKeys ────────────────────────────────────────────────────────

  describe("allowedParamKeys", () => {
    beforeEach(() => {
      engine.addPolicy(policy({ allowedParamKeys: ["origin", "dest", "class"] }));
    });

    it("allows when all param keys are in the allowlist", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK", dest: "NRT" }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("denies when an unknown param key is present", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK", unknownField: "x" }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("allowedParamKeys");
    });

    it("denies for any single unknown key", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK", injected: true }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.reason).toMatch(/"injected"/);
    });
  });

  // ─── blockedParamValues ──────────────────────────────────────────────────────

  describe("blockedParamValues", () => {
    beforeEach(() => {
      engine.addPolicy(
        policy({
          blockedParamValues: [
            { key: "action", value: "delete" },
            { key: "dryRun", value: false },
          ],
        })
      );
    });

    it("allows when no blocked (key, value) pairs are present", async () => {
      const r = await engine.evaluate(CAP, { action: "create" }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("denies when a blocked value is matched", async () => {
      const r = await engine.evaluate(CAP, { action: "delete" }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("blockedParamValues");
      expect(r.reason).toMatch(/"action"/);
    });

    it("denies on blocked boolean value", async () => {
      const r = await engine.evaluate(CAP, { dryRun: false }, SENDER);
      expect(r.outcome).toBe("deny");
    });

    it("allows when blocked key is absent", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK" }, SENDER);
      expect(r.outcome).toBe("allow");
    });
  });

  // ─── paramAllowedValues ──────────────────────────────────────────────────────

  describe("paramAllowedValues", () => {
    beforeEach(() => {
      engine.addPolicy(
        policy({
          paramAllowedValues: [
            { key: "class", allowedValues: ["economy", "business"] },
          ],
        })
      );
    });

    it("allows when param value is in the allowed list", async () => {
      const r = await engine.evaluate(CAP, { class: "economy" }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("denies when param value is not in the allowed list", async () => {
      const r = await engine.evaluate(CAP, { class: "first" }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("paramAllowedValues");
      expect(r.reason).toMatch(/"first"/);
    });

    it("allows when the constrained key is absent entirely", async () => {
      const r = await engine.evaluate(CAP, { origin: "JFK" }, SENDER);
      expect(r.outcome).toBe("allow");
    });
  });

  // ─── maxSpendPerCall ─────────────────────────────────────────────────────────

  describe("maxSpendPerCall", () => {
    it("allows when spend is within limit", async () => {
      engine.addPolicy(
        policy({ maxSpendPerCall: { amount: 500, currency: "USD" } })
      );
      const r = await engine.evaluate(CAP, { amount: 499 }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("denies when spend exceeds limit", async () => {
      engine.addPolicy(
        policy({ maxSpendPerCall: { amount: 500, currency: "USD" } })
      );
      const r = await engine.evaluate(CAP, { amount: 501 }, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("maxSpendPerCall");
      expect(r.reason).toMatch(/501/);
      expect(r.reason).toMatch(/USD/);
    });

    it("allows when the amount param is absent", async () => {
      engine.addPolicy(
        policy({ maxSpendPerCall: { amount: 100, currency: "USD" } })
      );
      const r = await engine.evaluate(CAP, { origin: "JFK" }, SENDER);
      expect(r.outcome).toBe("allow");
    });

    it("reads amount from a custom paramKey", async () => {
      engine.addPolicy(
        policy({
          maxSpendPerCall: { amount: 10, currency: "USD", paramKey: "price" },
        })
      );
      const r = await engine.evaluate(CAP, { price: 15 }, SENDER);
      expect(r.outcome).toBe("deny");
    });

    it("allows when spend equals the limit exactly", async () => {
      engine.addPolicy(
        policy({ maxSpendPerCall: { amount: 100, currency: "USD" } })
      );
      const r = await engine.evaluate(CAP, { amount: 100 }, SENDER);
      expect(r.outcome).toBe("allow");
    });
  });

  // ─── rateLimitPerMinute ──────────────────────────────────────────────────────

  describe("rateLimitPerMinute", () => {
    it("allows calls within the limit", async () => {
      engine.addPolicy(policy({ rateLimitPerMinute: 3 }));
      for (let i = 0; i < 3; i++) {
        const r = await engine.evaluate(CAP, {}, SENDER);
        expect(r.outcome).toBe("allow");
      }
    });

    it("denies on the call that exceeds the limit", async () => {
      engine.addPolicy(policy({ rateLimitPerMinute: 2 }));
      await engine.evaluate(CAP, {}, SENDER);
      await engine.evaluate(CAP, {}, SENDER);
      const r = await engine.evaluate(CAP, {}, SENDER);
      expect(r.outcome).toBe("deny");
      expect(r.violatedRule).toBe("rateLimitPerMinute");
    });

    it("rate limits are scoped per sender DID", async () => {
      engine.addPolicy(policy({ rateLimitPerMinute: 1 }));
      await engine.evaluate(CAP, {}, "did:aroha:sender-A");
      // second call from a different sender should still be allowed
      const r = await engine.evaluate(CAP, {}, "did:aroha:sender-B");
      expect(r.outcome).toBe("allow");
    });

    it("rate limits are scoped per capability", async () => {
      engine.addPolicy({ capabilityId: "book-hotel", rateLimitPerMinute: 1 });
      engine.addPolicy({ capabilityId: "book-flight", rateLimitPerMinute: 1 });
      await engine.evaluate("book-hotel", {}, SENDER);
      // hitting book-hotel limit should not affect book-flight
      const r = await engine.evaluate("book-flight", {}, SENDER);
      expect(r.outcome).toBe("allow");
    });
  });

  // ─── removePolicy ────────────────────────────────────────────────────────────

  describe("removePolicy", () => {
    it("allows requests after the policy for that capability is removed", async () => {
      engine.addPolicy(policy({ requiredParamKeys: ["userId"] }));
      const before = await engine.evaluate(CAP, {}, SENDER);
      expect(before.outcome).toBe("deny");

      engine.removePolicy(CAP);
      const after = await engine.evaluate(CAP, {}, SENDER);
      expect(after.outcome).toBe("allow");
    });

    it("does not affect policies for other capabilities", async () => {
      engine.addPolicy({ capabilityId: "book-hotel", requiredParamKeys: ["city"] });
      engine.removePolicy(CAP); // remove non-existent — should not throw
      const r = await engine.evaluate("book-hotel", {}, SENDER);
      expect(r.outcome).toBe("deny");
    });
  });

  // ─── Rule evaluation order ───────────────────────────────────────────────────

  it("stops at the first violated rule and returns it", async () => {
    engine.addPolicy(
      policy({
        requiredParamKeys: ["userId"],    // checked first
        allowedParamKeys: ["userId"],
        maxSpendPerCall: { amount: 10, currency: "USD" },
      })
    );
    // Missing userId triggers requiredParamKeys before allowedParamKeys or maxSpend
    const r = await engine.evaluate(CAP, { amount: 999 }, SENDER);
    expect(r.violatedRule).toBe("requiredParamKeys");
  });
});
