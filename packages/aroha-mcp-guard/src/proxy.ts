// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// GuardProxy — a transparent stdio JSON-RPC proxy between an MCP client and a
// wrapped MCP server. Forwards everything untouched except tools/call, which
// GuardSession (session.ts) checks against the GuardEngine first.
//
// Human gates: MCP 2026-07-28 clients get a Multi Round-Trip Request
// (`input_required` + `inputResponses` retry); older clients get a
// server→client elicitation. Without elicitation support the call is denied
// with instructions. Calls to a tool whose definition changed since it was
// first seen need a fresh approval (see session.ts).
//
// MCP stdio transport frames messages as newline-delimited JSON.

import { spawn, type ChildProcess } from "node:child_process";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { GuardEngine } from "./engine.js";
import { GuardSession, type JsonRpcMessage } from "./session.js";

export interface ProxyOptions {
  engine: GuardEngine;
  command: string;
  args: string[];
  logPath?: string;
  label?: string;
  /** Gate approval timeout in ms for pre-2026 elicitation (default 120s). */
  gateTimeoutMs?: number;
  /** HMAC key for MRTR requestState (≥ 32 bytes). Default: random per process. */
  stateKey?: Uint8Array;
}

interface AuditEntry {
  ts: string;
  label?: string;
  tool: string;
  decision: string;
  detail?: string;
}

/** Incremental newline-delimited JSON parser — tolerates partial chunks. */
export function createLineParser(onMessage: (msg: JsonRpcMessage, raw: string) => void) {
  let buffer = "";
  return (chunk: Buffer | string) => {
    buffer += chunk.toString();
    let nl: number;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).replace(/\r$/, "");
      buffer = buffer.slice(nl + 1);
      if (!line.trim()) continue;
      let msg: JsonRpcMessage;
      try {
        msg = JSON.parse(line) as JsonRpcMessage;
      } catch {
        // Not JSON — pass the raw line through untouched (defensive).
        onMessage({ jsonrpc: "2.0" }, line);
        continue;
      }
      onMessage(msg, line);
    }
  };
}

export class GuardProxy {
  private child: ChildProcess;
  private session: GuardSession;
  private logPath?: string;
  private label?: string;
  private startedAt = Date.now();

  constructor(private opts: ProxyOptions) {
    this.logPath = opts.logPath;
    this.label = opts.label;

    // Windows needs a shell for .cmd shims (npx, npm). Passing an args array
    // with shell:true is deprecated/unsafe, so build one quoted command line.
    if (process.platform === "win32") {
      const quote = (s: string) => (/[\s"^&|<>()%!]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
      this.child = spawn([opts.command, ...opts.args].map(quote).join(" "), {
        stdio: ["pipe", "pipe", "inherit"],
        shell: true,
      });
    } else {
      this.child = spawn(opts.command, opts.args, {
        stdio: ["pipe", "pipe", "inherit"],
      });
    }

    this.session = new GuardSession({
      engine: opts.engine,
      gateTimeoutMs: opts.gateTimeoutMs,
      stateKey: opts.stateKey,
      toClient: (msg) => this.toClient(JSON.stringify(msg)),
      toServer: (msg) => this.toServer(JSON.stringify(msg)),
      audit: (entry) => this.audit(entry),
    });

    this.child.on("error", (err) => {
      process.stderr.write(`[mcp-guard] failed to start wrapped server: ${err.message}\n`);
      process.exit(1);
    });

    this.child.on("exit", (code) => {
      this.writeReceipt();
      process.exit(code ?? 0);
    });

    // Client → proxy → server. Unparseable lines pass through untouched.
    const clientParser = createLineParser((msg, raw) => {
      if (msg.method === undefined && msg.id === undefined && msg.result === undefined && msg.error === undefined) this.toServer(raw);
      else this.session.fromClient(msg);
    });
    process.stdin.on("data", clientParser);
    process.stdin.on("end", () => this.child.stdin?.end());

    // Server → proxy → client
    const serverParser = createLineParser((msg, raw) => {
      if (msg.method === undefined && msg.id === undefined && msg.result === undefined && msg.error === undefined) this.toClient(raw);
      else this.session.fromServer(msg);
    });
    this.child.stdout?.on("data", serverParser);
  }

  private toServer(line: string): void {
    this.child.stdin?.write(line + "\n");
  }

  private toClient(line: string): void {
    process.stdout.write(line + "\n");
  }

  private audit(entry: Omit<AuditEntry, "ts" | "label">): void {
    if (!this.logPath) return;
    const full: AuditEntry = { ts: new Date().toISOString(), label: this.label, ...entry };
    try {
      mkdirSync(dirname(this.logPath), { recursive: true });
      appendFileSync(this.logPath, JSON.stringify(full) + "\n");
    } catch {
      // Audit failures must never break the proxy.
    }
  }

  /** TaskReceipt-shaped session summary, written to the audit log on exit. */
  private writeReceipt(): void {
    if (!this.logPath) return;
    try {
      appendFileSync(
        this.logPath,
        JSON.stringify({
          ts: new Date().toISOString(),
          label: this.label,
          type: "session-receipt",
          durationMs: Date.now() - this.startedAt,
          callsAllowed: this.session.callsAllowed,
          callsDenied: this.session.callsDenied,
          limits: this.opts.engine.usage(),
        }) + "\n"
      );
    } catch {
      /* ignore */
    }
  }
}
