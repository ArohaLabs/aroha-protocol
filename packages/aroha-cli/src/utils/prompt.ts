// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

let rl: ReturnType<typeof createInterface> | null = null;

function getRL() {
  if (!rl) rl = createInterface({ input, output });
  return rl;
}

export function closePrompts(): void {
  rl?.close();
  rl = null;
}

export async function ask(question: string, defaultValue?: string): Promise<string> {
  const hint = defaultValue ? ` \x1b[2m(${defaultValue})\x1b[0m` : "";
  const answer = await getRL().question(`  \x1b[36m?\x1b[0m ${question}${hint}: `);
  return answer.trim() || (defaultValue ?? "");
}

export async function choose<T extends string>(
  question: string,
  choices: T[],
  defaultValue?: T
): Promise<T> {
  const list = choices.map((c, i) => `    ${i + 1}) ${c}`).join("\n");
  console.log(`  \x1b[36m?\x1b[0m ${question}`);
  console.log(list);
  const hint = defaultValue ? ` \x1b[2m(${defaultValue})\x1b[0m` : "";
  while (true) {
    const answer = await getRL().question(`  Enter number or name${hint}: `);
    const trimmed = answer.trim();
    if (!trimmed && defaultValue) return defaultValue;
    const idx = Number(trimmed) - 1;
    if (!isNaN(idx) && choices[idx]) return choices[idx];
    const match = choices.find((c) => c.toLowerCase() === trimmed.toLowerCase());
    if (match) return match;
    console.log("  Invalid choice, try again.");
  }
}

export async function confirm(question: string, defaultYes = true): Promise<boolean> {
  const hint = defaultYes ? "Y/n" : "y/N";
  const answer = await getRL().question(`  \x1b[36m?\x1b[0m ${question} \x1b[2m(${hint})\x1b[0m: `);
  const trimmed = answer.trim().toLowerCase();
  if (!trimmed) return defaultYes;
  return trimmed === "y" || trimmed === "yes";
}

export async function askList(question: string, hint = "comma-separated"): Promise<string[]> {
  const answer = await ask(`${question} \x1b[2m(${hint})\x1b[0m`);
  return answer.split(",").map((s) => s.trim()).filter(Boolean);
}
