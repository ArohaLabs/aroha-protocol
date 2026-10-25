// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal Skills primitive.
 *
 * There was previously no "Skill" concept anywhere in this SDK — apps
 * building on Aroha that wanted a reusable, named, independently-invocable
 * unit of behavior distinct from a full agent or an MCP tool had to invent
 * the whole vocabulary themselves (see buildSkillManifest in ../manifest,
 * which at least standardizes the manifest shape but says nothing about how
 * a skill is actually invoked). This is the invocation contract that shape
 * was missing: a typed definition plus a small registry to look skills up
 * by id and call them. Deliberately does not prescribe a fixed skillType
 * vocabulary (that's app/domain-specific) or a transport (a skill can be
 * called in-process, or an app can expose SkillRegistry.invoke behind its
 * own HTTP route — this only standardizes "here is what a skill looks like
 * and how you call it once you have one").
 */

export interface SkillInputSchema {
  type: "object";
  properties: Record<string, unknown>;
  required?: string[];
}

export interface SkillDefinition<TInput = unknown, TOutput = unknown> {
  id: string;
  name: string;
  description?: string;
  /** Open string, not a fixed enum — the taxonomy of skill kinds is app-specific. */
  skillType: string;
  inputSchema?: SkillInputSchema;
  handler: (input: TInput) => Promise<TOutput> | TOutput;
}

/** Identity function — exists for type inference at the call site and a stable place to add validation later. */
export function defineSkill<TInput, TOutput>(
  definition: SkillDefinition<TInput, TOutput>,
): SkillDefinition<TInput, TOutput> {
  return definition;
}

export class SkillRegistryError extends Error {}

/** In-process registry: register skills once, look them up and invoke them by id. */
export class SkillRegistry {
  private readonly skills = new Map<string, SkillDefinition>();

  register(skill: SkillDefinition): void {
    if (this.skills.has(skill.id)) {
      throw new SkillRegistryError(`Skill "${skill.id}" is already registered`);
    }
    this.skills.set(skill.id, skill);
  }

  get(id: string): SkillDefinition | undefined {
    return this.skills.get(id);
  }

  list(): SkillDefinition[] {
    return [...this.skills.values()];
  }

  async invoke<TInput = unknown, TOutput = unknown>(id: string, input: TInput): Promise<TOutput> {
    const skill = this.skills.get(id);
    if (!skill) throw new SkillRegistryError(`No skill registered with id "${id}"`);
    return (await skill.handler(input)) as TOutput;
  }
}
