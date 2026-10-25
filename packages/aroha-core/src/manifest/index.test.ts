// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { buildAgentManifest, buildMcpManifest, buildSkillManifest, validateManifest } from "./index.js";

const DID = "did:aroha:test-agent";

describe("buildAgentManifest", () => {
  it("defaults to private, unpublished, local", () => {
    const m = buildAgentManifest(DID, { name: "Test Agent" });
    expect(m.visibility).toBe("private");
    expect(m.published).toBe(false);
    expect(m.deployTarget).toBe("local");
    expect(m.kind).toBe("agent");
    expect(m.did).toBe(DID);
    expect(m.capabilities).toEqual([]);
  });

  it("carries capabilities, model, trigger through", () => {
    const m = buildAgentManifest(DID, {
      name: "Test Agent",
      capabilities: [{ id: "rag:docs", name: "Docs", trustLevel: "medium" }],
      model: "claude-sonnet-5",
      trigger: "manual",
    });
    expect(m.capabilities).toHaveLength(1);
    expect(m.model).toBe("claude-sonnet-5");
    expect(m.trigger).toBe("manual");
  });

  it("passes validateManifest", () => {
    const m = buildAgentManifest(DID, { name: "Test Agent" });
    expect(validateManifest(m)).toEqual({ ok: true, errors: [] });
  });

  it("carries settlementRails through (spec §8.1) — absent by default", () => {
    const withRails = buildAgentManifest(DID, { name: "Test Agent", settlementRails: ["stripe", "usdc-base"] });
    expect(withRails.settlementRails).toEqual(["stripe", "usdc-base"]);

    const without = buildAgentManifest(DID, { name: "Test Agent" });
    expect(without.settlementRails).toBeUndefined();
  });
});

describe("buildMcpManifest", () => {
  it("defaults endpoint to null and auth to none", () => {
    const m = buildMcpManifest(DID, { name: "Test MCP" });
    expect(m.endpoint).toBeNull();
    expect(m.auth).toEqual({ type: "none" });
    expect(m.tools).toEqual([]);
  });

  it("passes validateManifest", () => {
    const m = buildMcpManifest(DID, { name: "Test MCP", tools: [{ name: "search" }] });
    expect(validateManifest(m)).toEqual({ ok: true, errors: [] });
  });
});

describe("buildSkillManifest", () => {
  it("defaults skillType to custom", () => {
    const m = buildSkillManifest(DID, { name: "Test Skill" });
    expect(m.skillType).toBe("custom");
  });

  it("passes validateManifest", () => {
    const m = buildSkillManifest(DID, { name: "Test Skill", skillType: "rag" });
    expect(validateManifest(m)).toEqual({ ok: true, errors: [] });
  });
});

describe("validateManifest", () => {
  it("rejects a non-object", () => {
    expect(validateManifest(null).ok).toBe(false);
    expect(validateManifest("x").ok).toBe(false);
  });

  it("rejects a did not shaped like did:aroha:...", () => {
    const result = validateManifest({ ...buildAgentManifest(DID, { name: "x" }), did: "not-a-did" });
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.includes("did"))).toBe(true);
  });

  it("rejects an invalid kind", () => {
    const result = validateManifest({ ...buildAgentManifest(DID, { name: "x" }), kind: "bogus" });
    expect(result.ok).toBe(false);
  });

  it("flags published:true + visibility:private as contradictory", () => {
    const result = validateManifest({
      ...buildAgentManifest(DID, { name: "x" }),
      published: true,
      visibility: "private",
    });
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.includes("contradictory"))).toBe(true);
  });

  it("allows published:true with visibility:public", () => {
    const result = validateManifest({
      ...buildAgentManifest(DID, { name: "x" }),
      published: true,
      visibility: "public",
    });
    expect(result.ok).toBe(true);
  });

  it("requires capabilities array on an agent manifest", () => {
    const m = buildAgentManifest(DID, { name: "x" }) as unknown as Record<string, unknown>;
    delete m.capabilities;
    expect(validateManifest(m).ok).toBe(false);
  });

  it("requires tools array on an mcp manifest", () => {
    const m = buildMcpManifest(DID, { name: "x" }) as unknown as Record<string, unknown>;
    delete m.tools;
    expect(validateManifest(m).ok).toBe(false);
  });

  it("requires skillType string on a skill manifest", () => {
    const m = buildSkillManifest(DID, { name: "x" }) as unknown as Record<string, unknown>;
    delete m.skillType;
    expect(validateManifest(m).ok).toBe(false);
  });
});
