// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `aroha create-app` — scaffold a complete multi-agent Aroha project
 *
 * Generates:
 *   orchestrator/   — LLM host agent using @aroha-sdk/micro
 *   agents/worker-a/ — first worker agent stub
 *   agents/worker-b/ — second worker agent stub
 *   frontend/        — Next.js chat UI (streaming)
 *   docker-compose.yml
 *   package.json (npm workspaces)
 */

import { resolve } from "node:path";
import { ask, confirm, closePrompts } from "../utils/prompt.js";
import { writeScaffold, dirExists, banner, success, log, fatal } from "../utils/scaffold.js";
import { createAppTemplate } from "../templates/create-app.js";

export interface CreateAppFlags {
  yes?: boolean;
}

export async function runCreateApp(
  name: string | undefined,
  flags: CreateAppFlags
): Promise<void> {
  banner("aroha create-app — multi-agent project scaffold");

  if (!name) {
    name = await ask("Project name", "my-aroha-app");
  }

  const safe = name.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "");
  if (safe !== name) { log("info", `Name normalized to "${safe}"`); name = safe; }

  const outDir = resolve(process.cwd(), name);

  if (await dirExists(outDir)) {
    if (flags.yes) {
      fatal(`Directory "${name}" already exists. Remove it first or choose a different name.`);
    }
    const ok = await confirm(`Directory "${name}" already exists. Overwrite?`, false);
    if (!ok) { log("skip", "Aborted."); closePrompts(); return; }
  }

  closePrompts();

  const files = createAppTemplate({ name });
  await writeScaffold(outDir, files);

  success(`Created "${name}" — your Aroha multi-agent project`);

  console.log("  Next steps:\n");
  console.log(`    cd ${name}`);
  console.log("    npm install");
  console.log("    npx aroha dev          # start local sandbox (terminal 1)");
  console.log("    npm run dev           # start all agents + frontend (terminal 2)\n");
  console.log("  Open http://localhost:3001 to chat with your agents.\n");
}
