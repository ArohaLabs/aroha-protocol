// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { readFile } from "node:fs/promises";
import { join } from "node:path";

export type Protocol = "a2a" | "agntcy" | "mcp" | "langchain" | "crewai" | "autogen" | "unknown";

/** Infer the agentic protocol used by a directory from deps and file content. */
export async function detectProtocol(dir: string): Promise<Protocol> {
  // --- JavaScript / TypeScript project ---
  try {
    const raw = await readFile(join(dir, "package.json"), "utf8");
    const pkg = JSON.parse(raw) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    if (deps["@google/a2a"] || deps["a2a-sdk"] || deps["@a2a-js/sdk"]) return "a2a";
    if (deps["agntcy"] || deps["@agntcy/core"] || deps["@agntcy/sdk"]) return "agntcy";
    if (deps["@modelcontextprotocol/sdk"] || deps["@anthropic-ai/mcp"]) return "mcp";
    if (deps["langchain"] || deps["@langchain/core"] || deps["@langchain/openai"]) return "langchain";
  } catch {
    // no package.json
  }

  // --- Python project ---
  try {
    const req = await readFile(join(dir, "requirements.txt"), "utf8");
    if (/\blangchain\b/i.test(req)) return "langchain";
    if (/\bcrewai\b/i.test(req)) return "crewai";
    if (/\bpyautogen\b|\bautogen\b/i.test(req)) return "autogen";
    if (/\bagntcy\b/i.test(req)) return "agntcy";
    if (/\ba2a[_-]?sdk\b/i.test(req)) return "a2a";
  } catch {}

  try {
    const pyproj = await readFile(join(dir, "pyproject.toml"), "utf8");
    if (/langchain/i.test(pyproj)) return "langchain";
    if (/crewai/i.test(pyproj)) return "crewai";
    if (/agntcy/i.test(pyproj)) return "agntcy";
  } catch {}

  // --- File content heuristics ---
  try {
    const files = await readFileIfExists(dir, [
      "agent.py", "main.py", "src/agent.ts", "src/index.ts", "src/main.ts",
    ]);
    for (const content of files) {
      if (/AgentCard|TaskHandler|a2a\.json/i.test(content)) return "a2a";
      if (/AgentcyClient|agntcy_sdk/i.test(content)) return "agntcy";
      if (/McpServer|FastMCP|mcp_server/i.test(content)) return "mcp";
      if (/LangChain|ChatOpenAI|AgentExecutor|create_react_agent/i.test(content)) return "langchain";
      if (/CrewAI|Crew\(|Agent\(role=/i.test(content)) return "crewai";
      if (/ConversableAgent|GroupChat|AutoGen/i.test(content)) return "autogen";
    }
  } catch {}

  // --- Agntcy YAML manifest ---
  try {
    const manifest = await readFile(join(dir, "agntcy.yaml"), "utf8");
    if (manifest.includes("capabilities:")) return "agntcy";
  } catch {}

  return "unknown";
}

async function readFileIfExists(dir: string, paths: string[]): Promise<string[]> {
  const results: string[] = [];
  for (const p of paths) {
    try {
      results.push(await readFile(join(dir, p), "utf8"));
    } catch {}
  }
  return results;
}
