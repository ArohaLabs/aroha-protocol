// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { resolve } from "node:path";
import { ask, choose, confirm, closePrompts } from "../utils/prompt.js";
import { writeScaffold, dirExists, banner, success, fatal, log } from "../utils/scaffold.js";
import { detectProtocol, type Protocol } from "../utils/detect.js";
import { a2aConverterTemplate } from "../templates/converters/a2a.js";
import { agntcyConverterTemplate } from "../templates/converters/agntcy.js";
import { mcpConverterTemplate } from "../templates/converters/mcp.js";
import { langchainConverterTemplate } from "../templates/converters/langchain.js";

export type SupportedProtocol = "a2a" | "agntcy" | "mcp" | "langchain";

export interface ConvertFlags {
  from?: SupportedProtocol;
  dir?: string;
  out?: string;
  name?: string;
  port?: number;
  endpoint?: string;
  language?: "typescript" | "python";
  yes?: boolean;
}

const SUPPORTED: SupportedProtocol[] = ["a2a", "agntcy", "mcp", "langchain"];

export async function runConvert(flags: ConvertFlags): Promise<void> {
  banner("aroha convert — wrap an existing agent for Aroha");

  // ── Protocol detection ──────────────────────────────────────────────────────
  let protocol = flags.from;
  if (!protocol && flags.dir) {
    const detected = await detectProtocol(resolve(process.cwd(), flags.dir));
    if (detected !== "unknown" && SUPPORTED.includes(detected as SupportedProtocol)) {
      protocol = detected as SupportedProtocol;
      log("info", `Detected protocol: ${protocol} (from ${flags.dir})`);
    }
  }

  if (!protocol) {
    protocol = await choose(
      "Which protocol is the existing agent using?",
      SUPPORTED,
      "a2a"
    );
  }

  // ── Agent name ──────────────────────────────────────────────────────────────
  let name = flags.name;
  if (!name) {
    const defaultName = flags.dir
      ? resolve(process.cwd(), flags.dir).split(/[\\/]/).pop()?.replace(/[^a-z0-9-]/gi, "-").toLowerCase() ?? "my-agent"
      : `my-${protocol}-agent`;
    name = await ask("Output agent name", `${defaultName}-aroha`);
  }
  name = name.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "");

  // ── Output directory ────────────────────────────────────────────────────────
  const outDir = resolve(process.cwd(), flags.out ?? name);
  if (await dirExists(outDir)) {
    const overwrite = await confirm(`Directory "${outDir}" already exists. Overwrite?`, false);
    if (!overwrite) { closePrompts(); return; }
  }

  const port = flags.port ?? Number(await ask("Aroha port for this wrapper", "3001"));

  // ── Protocol-specific options ───────────────────────────────────────────────
  let files: Map<string, string>;

  switch (protocol) {
    case "a2a": {
      const a2aEndpoint =
        flags.endpoint ?? await ask("Upstream A2A agent endpoint", "http://localhost:8080");
      files = a2aConverterTemplate({ name, port, a2aEndpoint });
      log("info", `A2A bridge → ${a2aEndpoint}`);
      break;
    }

    case "agntcy": {
      const agntcyEndpoint =
        flags.endpoint ?? await ask("Upstream Agntcy agent endpoint", "http://localhost:8080");
      files = agntcyConverterTemplate({ name, port, agntcyEndpoint });
      log("info", `Agntcy bridge → ${agntcyEndpoint}`);
      break;
    }

    case "mcp": {
      const mcpEndpoint =
        flags.endpoint ?? await ask("Upstream MCP server endpoint", "http://localhost:8080");
      files = mcpConverterTemplate({ name, port, mcpEndpoint });
      log("info", `MCP bridge → ${mcpEndpoint}`);
      break;
    }

    case "langchain": {
      const language = flags.language ??
        await choose<"typescript" | "python">("LangChain implementation language", ["typescript", "python"], "typescript");
      files = langchainConverterTemplate({ name, port, language });
      log("info", `LangChain (${language}) → Aroha wrapper`);
      break;
    }

    default:
      fatal(`Unsupported protocol: ${protocol as string}. Supported: ${SUPPORTED.join(", ")}`);
  }

  closePrompts();
  await writeScaffold(outDir, files);

  success(`Aroha wrapper "${name}" created in ./${flags.out ?? name}/`);

  console.log("  Next steps:");
  console.log(`    cd ${flags.out ?? name}`);
  console.log("    npm install");
  if (protocol === "langchain") {
    console.log("    # Edit src/tools.ts and register your LangChain tools");
  } else {
    console.log("    # Edit src/capability-map.ts or src/*-adapter.ts to match your agent's schema");
  }
  console.log("    npm run dev");
  console.log(`\n  Full migration guide: docs/recipes/convert-from-${protocol}.md\n`);
}
