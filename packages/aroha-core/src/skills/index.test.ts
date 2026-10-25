// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { defineSkill, SkillRegistry, SkillRegistryError } from "./index.js";

describe("SkillRegistry", () => {
  it("registers, lists, and invokes a skill", async () => {
    const registry = new SkillRegistry();
    const skill = defineSkill<{ query: string }, { results: string[] }>({
      id: "web-search",
      name: "Web Search",
      skillType: "web-search",
      handler: ({ query }) => ({ results: [`result for ${query}`] }),
    });
    registry.register(skill);

    expect(registry.list()).toHaveLength(1);
    expect(registry.get("web-search")).toBe(skill);

    const result = await registry.invoke<{ query: string }, { results: string[] }>("web-search", { query: "test" });
    expect(result.results).toEqual(["result for test"]);
  });

  it("supports an async handler", async () => {
    const registry = new SkillRegistry();
    registry.register(defineSkill({
      id: "async-skill",
      name: "Async",
      skillType: "custom",
      handler: async (input: number) => input * 2,
    }));

    expect(await registry.invoke("async-skill", 21)).toBe(42);
  });

  it("rejects registering the same id twice", () => {
    const registry = new SkillRegistry();
    const make = () => defineSkill({ id: "dup", name: "Dup", skillType: "custom", handler: () => null });
    registry.register(make());
    expect(() => registry.register(make())).toThrow(SkillRegistryError);
  });

  it("throws invoking an unregistered skill", async () => {
    const registry = new SkillRegistry();
    await expect(registry.invoke("nope", {})).rejects.toThrow(SkillRegistryError);
  });
});
