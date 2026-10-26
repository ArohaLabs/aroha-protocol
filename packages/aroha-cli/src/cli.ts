#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
import { parseArgs } from "node:util";
import { runInit } from "./commands/init.js";
import { runConvert, type SupportedProtocol } from "./commands/convert.js";
import { runAddCapability } from "./commands/add.js";
import { runCreateBridge } from "./commands/create-bridge.js";
import { runDev } from "./commands/dev.js";
import { runCreateApp } from "./commands/create-app.js";
import { runDoctor } from "./commands/doctor.js";
import { setTelemetry, telemetryStatus, track } from "./utils/telemetry.js";

const HELP = `
\x1b[1maroha\x1b[0m — Aroha Protocol CLI

\x1b[1mUsage\x1b[0m
  aroha dev                            Start local dev sandbox (registry + dashboard)
  aroha create-app [name]              Scaffold a multi-agent project (Day 0)
  aroha init [name] [options]          Scaffold a single Aroha agent
  aroha convert [options]              Wrap an existing agent for Aroha
  aroha add capability [id] [options]  Add a capability to an existing agent

\x1b[1maroha dev\x1b[0m
  --port <n>   Dashboard + registry port (default: 3000)

  Starts an in-memory capability registry and live dashboard.
  Any @aroha-sdk/micro agent with devMode: true auto-registers here on startup.

  Examples:
    aroha dev
    aroha dev --port 4000

\x1b[1maroha create-app\x1b[0m
  [name]       Project name (default: my-aroha-app)
  -y, --yes    Skip prompts, use defaults

  Scaffolds a ready-to-run multi-agent project:
    orchestrator/   LLM host agent (@aroha-sdk/micro)
    agents/worker-a/ First worker agent stub
    agents/worker-b/ Second worker agent stub
    frontend/        Next.js streaming chat UI
    docker-compose.yml

  Examples:
    npx @aroha-sdk/cli create-app
    aroha create-app my-hackathon -y


\x1b[1maroha init\x1b[0m
  --type <provider|orchestrator>   Agent type (default: prompted)
  --port <n>                       Aroha server port (default: prompted)
  --api-port <n>                   REST API port for orchestrators (default: 3010)
  --capabilities <a,b,c>           Comma-separated capability IDs
  -y, --yes                        Skip prompts, use defaults

  Examples:
    aroha init my-flight-agent --type provider --port 3001 --capabilities search-flights,book-flight
    aroha init my-assistant --type orchestrator --port 3000

\x1b[1maroha convert\x1b[0m
  --from <a2a|agntcy|mcp|langchain>  Source protocol (auto-detected if --dir is given)
  --dir <path>                        Existing agent directory (for auto-detection)
  --out <path>                        Output directory (default: <name>)
  --name <name>                       Name for the generated wrapper
  --port <n>                          Aroha port for the wrapper (default: prompted)
  --endpoint <url>                    Upstream agent URL (for a2a/agntcy/mcp)
  --language <typescript|python>      For LangChain: target language (default: typescript)
  -y, --yes                           Skip prompts, use defaults

  Examples:
    aroha convert --from a2a --endpoint http://localhost:8080
    aroha convert --from langchain --dir ./my-lc-agent
    aroha convert --dir ./existing-agent       # auto-detects protocol

\x1b[1maroha add capability\x1b[0m
  [id]        Capability ID (kebab-case)
  --saga      Add reserve/commit/cancel saga handlers

  Examples:
    aroha add capability search-hotels
    aroha add capability book-hotel --saga

\x1b[1maroha create-bridge\x1b[0m
  --name <name>    Bridge name in kebab-case (e.g. hubspot, stripe, salesforce)
  --sdk <name>     SDK or protocol display name (e.g. HubSpot, Stripe, Salesforce)
  --out <path>     Output directory (default: aroha-<name>-bridge)
  -y, --yes        Skip prompts, use defaults

  Scaffolds a standalone @aroha-sdk/<name>-bridge npm package following the
  duck-typed, zero-hard-dependency bridge pattern. Publish it to npm and
  submit it to the Aroha ecosystem registry.

  Examples:
    aroha create-bridge --name hubspot --sdk HubSpot
    aroha create-bridge --name stripe --sdk Stripe -y

\x1b[1maroha doctor\x1b[0m
  [endpoint]   Aroha agent endpoint to test (optional)

  Checks your environment and verifies the agent is reachable:
    ✓ Node.js version (must be ≥22)
    ✓ .env file has AROHA_AGENT_DID
    ✓ /.well-known/aroha-agent.json is a DID document whose id is AROHA_AGENT_DID
      and whose verificationMethod has a usable Ed25519 key (if given)
    ✓ Unsigned test request to /aroha/v1 gets a 200, 400 or 401 reply (if given)

  Examples:
    aroha doctor
    aroha doctor http://localhost:3001

\x1b[1maroha telemetry\x1b[0m [status|on|off]
  The CLI ships with NO telemetry endpoint and sends nothing by default.
  Telemetry exists only if you set AROHA_TELEMETRY_ENDPOINT to an https URL
  you control; "on"/"off" then opt this machine in or out (command names and
  Node version only). "status" shows the current state.

\x1b[1mGlobal flags\x1b[0m
  --help, -h   Show this help
  --version    Print CLI version
`;

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    strict: false,
    options: {
      // init
      type:         { type: "string" },
      port:         { type: "string" },
      "api-port":   { type: "string" },
      capabilities: { type: "string" },
      // create-bridge
      sdk:          { type: "string" },
      // convert
      from:         { type: "string" },
      dir:          { type: "string" },
      out:          { type: "string" },
      name:         { type: "string" },
      endpoint:     { type: "string" },
      language:     { type: "string" },
      // add
      saga:         { type: "boolean" },
      // common
      yes:          { type: "boolean", short: "y" },
      help:         { type: "boolean", short: "h" },
      version:      { type: "boolean" },
    },
  });

  if (values.version) {
    const { createRequire } = await import("node:module");
    const require = createRequire(import.meta.url);
    const pkg = require("../package.json") as { version: string };
    console.log(pkg.version);
    return;
  }

  const [command, sub1, sub2] = positionals;

  if (!command || values.help) {
    console.log(HELP);
    return;
  }

  switch (command) {
    case "dev": {
      await runDev({
        port: values.port ? Number(values.port as string) : undefined,
      });
      break;
    }

    case "create-app": {
      await runCreateApp(sub1, {
        yes: values.yes as boolean | undefined,
      });
      break;
    }

    case "init": {
      track("init", Object.keys(values).map((k) => `--${k}`));
      const capsRaw = values.capabilities as string | undefined;
      await runInit(sub1, {
        type: values.type as "provider" | "orchestrator" | undefined,
        port: values.port ? Number(values.port as string) : undefined,
        apiPort: values["api-port"] ? Number(values["api-port"] as string) : undefined,
        capabilities: capsRaw ? capsRaw.split(",").map((s) => s.trim()) : undefined,
        yes: values.yes as boolean | undefined,
      });
      break;
    }

    case "convert": {
      track("convert", Object.keys(values).map((k) => `--${k}`));
      await runConvert({
        from: values.from as SupportedProtocol | undefined,
        dir: values.dir as string | undefined,
        out: values.out as string | undefined,
        name: values.name as string | undefined,
        port: values.port ? Number(values.port as string) : undefined,
        endpoint: values.endpoint as string | undefined,
        language: values.language as "typescript" | "python" | undefined,
        yes: values.yes as boolean | undefined,
      });
      break;
    }

    case "add": {
      if (sub1 !== "capability") {
        console.error(`Unknown "add" subcommand: ${sub1}. Did you mean "add capability"?`);
        process.exit(1);
      }
      await runAddCapability(sub2, {
        saga: values.saga as boolean | undefined,
        port: values.port ? Number(values.port as string) : undefined,
      });
      break;
    }

    case "create-bridge": {
      track("create-bridge", Object.keys(values).map((k) => `--${k}`));
      await runCreateBridge({
        name: values.name as string | undefined,
        sdk: values.sdk as string | undefined,
        out: values.out as string | undefined,
        yes: values.yes as boolean | undefined,
      });
      break;
    }

    case "doctor": {
      track("doctor");
      await runDoctor(sub1);
      break;
    }

    case "telemetry": {
      if (sub1 === "on")  { setTelemetry(true);  break; }
      if (sub1 === "off") { setTelemetry(false); break; }
      if (sub1 === undefined || sub1 === "status") { console.log(telemetryStatus()); break; }
      console.error(`Usage: aroha telemetry [status|on|off]`);
      process.exit(1);
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      console.log(HELP);
      process.exit(1);
  }
}

function errorHint(err: unknown): string | null {
  const msg = err instanceof Error ? err.message : String(err);
  if (/signature/i.test(msg) || /invalid.*key/i.test(msg))
    return "→ Check that AROHA_PRIVATE_KEY is set and is a valid base64 Ed25519 private key.";
  if (/ECONNREFUSED|ENOTFOUND|fetch failed/i.test(msg))
    return "→ Is your agent server running? Try: npm run dev\n  Or check the endpoint URL.";
  if (/did.*not.*found|unknown.*did/i.test(msg))
    return "→ Check AROHA_AGENT_DID in your .env matches the DID in your manifest.";
  if (/AROHA_AGENT_DID/i.test(msg))
    return "→ Add AROHA_AGENT_DID=did:aroha:<name> to your .env file.\n  Run `aroha init --yes` to generate one automatically.";
  if (/port.*in use|EADDRINUSE/i.test(msg))
    return "→ Port is already in use. Stop the existing process or use a different port: --port 3002";
  if (/Cannot find module/i.test(msg))
    return "→ Run `npm install` to install dependencies, then `npm run build` to compile.";
  if (/permission denied/i.test(msg))
    return "→ Try running with elevated permissions, or check file/directory ownership.";
  return null;
}

main().catch((err: unknown) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`\n\x1b[31m✗\x1b[0m ${msg}`);
  const hint = errorHint(err);
  if (hint) console.error(`\x1b[33m${hint}\x1b[0m`);
  console.error(`\n  Run \x1b[1maroha doctor\x1b[0m to check your environment.\n`);
  process.exit(1);
});
