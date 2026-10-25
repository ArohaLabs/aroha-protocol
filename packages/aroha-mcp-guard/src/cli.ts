#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// mcp-guard CLI — wrap any MCP server with guardrails, zero code:
//
//   npx @aroha-sdk/mcp-guard --gate "delete_*" --limit "create_*:5" -- \
//     npx -y @modelcontextprotocol/server-github
//
// In an MCP client config, replace the server command with this wrapper.

import { homedir } from "node:os";
import { join } from "node:path";
import { GuardEngine, parseRules } from "./engine.js";
import { GuardProxy } from "./proxy.js";

const HELP = `mcp-guard — a firewall for your AI agent's tools (aroha-labs.com)

Usage:
  mcp-guard [options] -- <command> [args...]

Options:
  --block <globs>     Always deny matching tools (comma-separated, repeatable)
  --limit <g>:<n>     Allow at most n calls per session (repeatable)
  --gate <globs>      Require human approval before each call (MCP 2026-07-28
                      input_required round trip; elicitation for older clients)
  --log <path>        Audit log path (JSONL). Default: ~/.aroha/mcp-guard.jsonl
  --no-log            Disable the audit log
  --name <label>      Label for this wrapped server in the audit log
  --gate-timeout <s>  Seconds to wait for human approval (default 120)
  --help              Show this help

Everything after "--" is the wrapped MCP server command, unchanged.

Example (Claude Desktop / Cursor / any MCP client config):
  {
    "mcpServers": {
      "github": {
        "command": "npx",
        "args": ["-y", "@aroha-sdk/mcp-guard",
                 "--gate", "delete_*,merge_*",
                 "--limit", "create_*:10",
                 "--",
                 "npx", "-y", "@modelcontextprotocol/server-github"]
      }
    }
  }
`;

function fail(message: string): never {
  process.stderr.write(`[mcp-guard] ${message}\n\n${HELP}`);
  process.exit(1);
}

function main(): void {
  const argv = process.argv.slice(2);
  const sep = argv.indexOf("--");
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  if (sep === -1) fail('missing "--" separator before the wrapped server command');

  const flags = argv.slice(0, sep);
  const command = argv.slice(sep + 1);
  if (command.length === 0) fail('no command given after "--"');

  const block: string[] = [];
  const limit: string[] = [];
  const gate: string[] = [];
  let logPath: string | undefined = join(homedir(), ".aroha", "mcp-guard.jsonl");
  let label: string | undefined;
  let gateTimeoutMs = 120_000;

  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    const next = () => {
      const v = flags[++i];
      if (v === undefined) fail(`${flag} requires a value`);
      return v;
    };
    switch (flag) {
      case "--block":  block.push(next()); break;
      case "--limit":  limit.push(next()); break;
      case "--gate":   gate.push(next()); break;
      case "--log":    logPath = next(); break;
      case "--no-log": logPath = undefined; break;
      case "--name":   label = next(); break;
      case "--gate-timeout": {
        const s = Number(next());
        if (!Number.isFinite(s) || s <= 0) fail("--gate-timeout must be a positive number of seconds");
        gateTimeoutMs = s * 1000;
        break;
      }
      default: fail(`unknown option: ${flag}`);
    }
  }

  // Env fallbacks so config files can keep args minimal
  if (process.env.AROHA_GUARD_BLOCK) block.push(process.env.AROHA_GUARD_BLOCK);
  if (process.env.AROHA_GUARD_LIMIT) limit.push(process.env.AROHA_GUARD_LIMIT);
  if (process.env.AROHA_GUARD_GATE)  gate.push(process.env.AROHA_GUARD_GATE);

  let engine: GuardEngine;
  try {
    engine = new GuardEngine(parseRules({ block, limit, gate }));
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  // Multi-process deployments that share approvals need a shared key; one
  // proxy process is fine with its random default.
  const stateKeyHex = process.env.AROHA_GUARD_STATE_KEY;
  let stateKey: Uint8Array | undefined;
  if (stateKeyHex) {
    if (!/^[0-9a-fA-F]{64,}$/.test(stateKeyHex)) fail("AROHA_GUARD_STATE_KEY must be at least 32 bytes of hex");
    stateKey = new Uint8Array(Buffer.from(stateKeyHex, "hex"));
  }

  new GuardProxy({
    engine,
    command: command[0],
    args: command.slice(1),
    logPath,
    label,
    gateTimeoutMs,
    stateKey,
  });
}

main();
