// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { identityTs } from "./provider.js";
import { NODE_ENGINE, TOOLCHAIN, sdkDeps } from "./versions.js";

export interface CreateAppOptions { name: string }

export function createAppTemplate(opts: CreateAppOptions): Map<string, string> {
  const files = new Map<string, string>();
  const { name } = opts;

  // ── Root ──────────────────────────────────────────────────────────────────
  files.set("package.json",       rootPackageJson(name));
  files.set("docker-compose.yml", dockerCompose(name));
  files.set(".env.example",       envExample());
  files.set(".gitignore",         gitignore());
  files.set("README.md",          readme(name));

  // ── Orchestrator ──────────────────────────────────────────────────────────
  files.set("orchestrator/package.json",   orchestratorPackageJson(name));
  files.set("orchestrator/tsconfig.json",  tsconfig());
  files.set("orchestrator/src/index.ts",   orchestratorIndex(name));
  files.set("orchestrator/src/identity.ts", identityTs());

  // ── Worker A ──────────────────────────────────────────────────────────────
  files.set("agents/worker-a/package.json",  workerPackageJson("worker-a"));
  files.set("agents/worker-a/tsconfig.json", tsconfig());
  files.set("agents/worker-a/src/index.ts",  workerAIndex());

  // ── Worker B ──────────────────────────────────────────────────────────────
  files.set("agents/worker-b/package.json",  workerPackageJson("worker-b"));
  files.set("agents/worker-b/tsconfig.json", tsconfig());
  files.set("agents/worker-b/src/index.ts",  workerBIndex());

  // ── Frontend ──────────────────────────────────────────────────────────────
  files.set("frontend/package.json",                  frontendPackageJson());
  files.set("frontend/next.config.js",                nextConfig());
  files.set("frontend/app/layout.tsx",                appLayout(name));
  files.set("frontend/app/page.tsx",                  appPage());
  files.set("frontend/app/api/chat/route.ts",         chatRoute());
  files.set("frontend/app/globals.css",               globalsCss());

  return files;
}

// ─── Root files ───────────────────────────────────────────────────────────────

function rootPackageJson(name: string): string {
  return JSON.stringify({
    name,
    version: "0.1.0",
    private: true,
    workspaces: ["orchestrator", "agents/*", "frontend"],
    scripts: {
      dev: "npm run dev --workspaces --if-present",
      build: "npm run build --workspaces --if-present",
      "dev:orchestrator": "npm run dev --workspace=orchestrator",
      "dev:worker-a": "npm run dev --workspace=agents/worker-a",
      "dev:worker-b": "npm run dev --workspace=agents/worker-b",
      "dev:frontend": "npm run dev --workspace=frontend",
    },
  }, null, 2);
}

function dockerCompose(name: string): string {
  return `version: "3.9"
name: ${name}

services:
  orchestrator:
    build: ./orchestrator
    ports: ["3000:3000"]
    environment:
      - NODE_ENV=production
      - HOST=0.0.0.0
      - WORKER_A_ENDPOINT=http://worker-a:3001/aroha/v1
      - WORKER_B_ENDPOINT=http://worker-b:3002/aroha/v1
    depends_on: [worker-a, worker-b]

  worker-a:
    build: ./agents/worker-a
    ports: ["3001:3001"]
    environment:
      - NODE_ENV=production
      - HOST=0.0.0.0

  worker-b:
    build: ./agents/worker-b
    ports: ["3002:3002"]
    environment:
      - NODE_ENV=production
      - HOST=0.0.0.0

  frontend:
    build: ./frontend
    ports: ["3010:3010"]
    environment:
      - ORCHESTRATOR_URL=http://orchestrator:3000
    depends_on: [orchestrator]
`;
}

function envExample(): string {
  return `# Copy to .env and fill in values
NODE_ENV=development

# Optional: Anthropic API key for LLM intent routing in the orchestrator
ANTHROPIC_API_KEY=

# Orchestrator signing key (64 hex chars). Generated into orchestrator/.env on
# first run if unset; set it explicitly in production / Docker.
AROHA_PRIVATE_KEY=

# Endpoints (only needed in production — dev mode auto-discovers on localhost)
WORKER_A_ENDPOINT=http://localhost:3001/aroha/v1
WORKER_B_ENDPOINT=http://localhost:3002/aroha/v1
`;
}

function gitignore(): string {
  return `node_modules/
dist/
.env
*.local
.next/
`;
}

function readme(name: string): string {
  return `# ${name}

A multi-agent Aroha application scaffolded by \`aroha create-app\`.

## Architecture

\`\`\`
frontend (Next.js chat)
    │  POST /api/chat
    ▼
orchestrator (port 3000)   ← routes intent to worker agents
    │  ArohaRequest
    ├──► worker-a (port 3001)  — implements capability A
    └──► worker-b (port 3002)  — implements capability B
\`\`\`

## Quick start

\`\`\`bash
# Terminal 1 — local dev sandbox (optional but shows live agent map)
npx @aroha-sdk/cli dev

# Terminal 2 — start all agents + frontend
npm install
npm run dev
\`\`\`

Open **http://localhost:3010** to chat with your agents.

## Going to production

1. Run with \`NODE_ENV=production\` (docker-compose already does) — devMode is only on when \`NODE_ENV=development\`.
2. Add \`ANTHROPIC_API_KEY\` (or your preferred LLM) to \`.env\`.
3. Run \`docker compose up --build\`.

That's it — no other code changes required. The Aroha protocol (Ed25519 DIDs, saga state machine, policy enforcement) activates automatically when \`devMode: false\`.

## File structure

\`\`\`
orchestrator/src/index.ts   — host agent: receives chat, routes to workers
agents/worker-a/src/index.ts — first capability stub (rename to match your domain)
agents/worker-b/src/index.ts — second capability stub
frontend/app/page.tsx        — Next.js chat UI
frontend/app/api/chat/route.ts — streams orchestrator response to browser
\`\`\`
`;
}

// ─── Orchestrator ─────────────────────────────────────────────────────────────

function orchestratorPackageJson(name: string): string {
  return JSON.stringify({
    name: `${name}-orchestrator`,
    version: "0.1.0",
    type: "module",
    scripts: {
      dev: "tsx src/index.ts",
      build: "tsc -p tsconfig.json",
      start: "node dist/index.js",
    },
    dependencies: {
      ...sdkDeps("@aroha-sdk/micro", "@aroha-sdk/core"),
      "@noble/ed25519": "^2.1.0",
    },
    devDependencies: { ...TOOLCHAIN },
    engines: { node: NODE_ENGINE },
  }, null, 2);
}

function orchestratorIndex(name: string): string {
  return `/**
 * Orchestrator — routes chat input to worker agents using Aroha.
 *
 * devMode is on only when NODE_ENV=development (see .env.example); any other
 * NODE_ENV — including unset — verifies Ed25519 signatures.
 */
import { createAgent } from "@aroha-sdk/micro";
import { ArohaClient, buildEnvelope, newCorrelationId } from "@aroha-sdk/core";
import { loadOrCreateIdentity } from "./identity.js";

const WORKER_A = process.env.WORKER_A_ENDPOINT ?? "http://localhost:3001";
const WORKER_B = process.env.WORKER_B_ENDPOINT ?? "http://localhost:3002";
const PORT = Number(process.env.PORT ?? 3000);
// devMode ONLY when NODE_ENV is explicitly "development": an unset NODE_ENV
// (the usual state on a fresh VM or container) must not switch signature
// verification off. Core refuses devMode outside development anyway.
const DEV  = process.env.NODE_ENV === "development";

// ── Own identity (used to sign outbound requests to workers) ──────────────────
// Loaded from AROHA_PRIVATE_KEY; generated and saved to .env on first run so
// the DID stays the same across restarts. In Docker, pass AROHA_PRIVATE_KEY
// as an environment variable — the container filesystem is not persistent.
const identity = await loadOrCreateIdentity("${name}-orchestrator", \`http://localhost:\${PORT}/aroha/v1\`);
const client   = new ArohaClient();

// ── Capability: chat ─────────────────────────────────────────────────────────
// The frontend calls this via POST /api/chat → this handler routes to workers.

async function callWorker(
  endpoint: string,
  capability: string,
  params: Record<string, unknown>
): Promise<unknown> {
  const envelope = await buildEnvelope(
    "ArohaRequest",
    identity.did,
    "did:aroha:worker",    // resolved at runtime in production; fine for dev
    { capability, params },
    newCorrelationId(),
    identity.privateKey
  );
  const response = await client.send(endpoint + "/aroha/v1", envelope);
  if (!response) throw new Error(\`No response from \${endpoint}\`);
  if (response.type === "ArohaError") {
    throw new Error((response.body as { message: string }).message);
  }
  return (response.body as { result: unknown }).result;
}

// ── Orchestrator agent ────────────────────────────────────────────────────────

// HOST=0.0.0.0 (set in docker-compose) is needed for the other containers to reach it.
const orchestrator = createAgent({ name: "${name}-orchestrator", port: PORT, devMode: DEV, host: process.env.HOST });

orchestrator.on("chat", async ({ message }) => {
  const msg = String(message ?? "").toLowerCase();

  // Simple keyword routing — replace with LLM intent parsing for production
  if (msg.includes("a") || msg.includes("worker-a")) {
    const result = await callWorker(WORKER_A, "capability-a", { input: message });
    return { reply: \`Worker A says: \${JSON.stringify(result)}\`, source: "worker-a" };
  }

  if (msg.includes("b") || msg.includes("worker-b")) {
    const result = await callWorker(WORKER_B, "capability-b", { input: message });
    return { reply: \`Worker B says: \${JSON.stringify(result)}\`, source: "worker-b" };
  }

  return {
    reply: "I can route to worker-a (say 'a') or worker-b (say 'b'). What would you like?",
    source: "orchestrator",
  };
});

await orchestrator.start();
`;
}

// ─── Workers ──────────────────────────────────────────────────────────────────

function workerPackageJson(workerName: string): string {
  return JSON.stringify({
    name: workerName,
    version: "0.1.0",
    type: "module",
    scripts: {
      dev: "tsx src/index.ts",
      build: "tsc -p tsconfig.json",
      start: "node dist/index.js",
    },
    dependencies: sdkDeps("@aroha-sdk/micro"),
    devDependencies: { ...TOOLCHAIN },
    engines: { node: NODE_ENGINE },
  }, null, 2);
}

function workerAIndex(): string {
  return `import { createAgent } from "@aroha-sdk/micro";

const agent = createAgent({
  name: "worker-a",
  port: Number(process.env.PORT ?? 3001),
  host: process.env.HOST,
  devMode: process.env.NODE_ENV === "development",
});

/**
 * capability-a — replace with your domain logic.
 *
 * Params are whatever JSON the orchestrator sends.
 * Return any JSON-serialisable value.
 */
agent.on("capability-a", async ({ input }) => {
  // TODO: implement your logic here
  return {
    processed: true,
    agent: "worker-a",
    echo: input,
    timestamp: new Date().toISOString(),
  };
});

await agent.start();
`;
}

function workerBIndex(): string {
  return `import { createAgent } from "@aroha-sdk/micro";

const agent = createAgent({
  name: "worker-b",
  port: Number(process.env.PORT ?? 3002),
  host: process.env.HOST,
  devMode: process.env.NODE_ENV === "development",
});

/**
 * capability-b — replace with your domain logic.
 */
agent.on("capability-b", async ({ input }) => {
  // TODO: implement your logic here
  return {
    processed: true,
    agent: "worker-b",
    echo: input,
    timestamp: new Date().toISOString(),
  };
});

await agent.start();
`;
}

// ─── Frontend ─────────────────────────────────────────────────────────────────

function frontendPackageJson(): string {
  return JSON.stringify({
    name: "frontend",
    version: "0.1.0",
    private: true,
    scripts: {
      dev: "next dev -p 3010",
      build: "next build",
      start: "next start -p 3010",
    },
    dependencies: {
      next: "^15.0.0",
      react: "^19.0.0",
      "react-dom": "^19.0.0",
    },
    devDependencies: {
      typescript: TOOLCHAIN.typescript,
      "@types/node": TOOLCHAIN["@types/node"],
      "@types/react": "^19.0.0",
      "@types/react-dom": "^19.0.0",
    },
  }, null, 2);
}

function nextConfig(): string {
  return `/** @type {import('next').NextConfig} */
const nextConfig = {};
export default nextConfig;
`;
}

function appLayout(name: string): string {
  return `import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "${name}",
  description: "Multi-agent Aroha application",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
`;
}

function appPage(): string {
  return `"use client";
import { useState, useRef, useEffect } from "react";

interface Message { role: "user" | "agent"; text: string; source?: string }

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "agent", text: "Hello! I can route your messages to worker-a or worker-b. Try saying 'a' or 'b'.", source: "orchestrator" },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function send() {
    if (!input.trim() || loading) return;
    const msg = input.trim();
    setInput("");
    setMessages((m) => [...m, { role: "user", text: msg }]);
    setLoading(true);
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg }),
      });
      const data = await res.json() as { reply: string; source?: string };
      setMessages((m) => [...m, { role: "agent", text: data.reply, source: data.source }]);
    } catch {
      setMessages((m) => [...m, { role: "agent", text: "Error reaching the orchestrator. Is it running?" }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="chat-root">
      <header className="chat-header">
        <span className="chat-title">Aroha Agent Chat</span>
        <span className="chat-badge">dev</span>
      </header>
      <div className="chat-messages">
        {messages.map((m, i) => (
          <div key={i} className={\`chat-msg \${m.role}\`}>
            <div className="chat-bubble">{m.text}</div>
            {m.source && <div className="chat-source">{m.source}</div>}
          </div>
        ))}
        {loading && (
          <div className="chat-msg agent">
            <div className="chat-bubble typing">…</div>
          </div>
        )}
        <div ref={bottomRef}/>
      </div>
      <div className="chat-input-row">
        <input
          className="chat-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Type a message…"
          autoFocus
        />
        <button className="chat-send" onClick={send} disabled={loading}>Send</button>
      </div>
    </main>
  );
}
`;
}

function chatRoute(): string {
  return `import { NextRequest, NextResponse } from "next/server";

const ORCHESTRATOR = process.env.ORCHESTRATOR_URL ?? "http://localhost:3000";

export async function POST(req: NextRequest) {
  const { message } = await req.json() as { message: string };

  // Build a minimal dev envelope (orchestrator has devMode: true so no signing needed)
  const envelope = {
    "@context": ["https://aroha-labs.com/contexts/v1"],
    id: \`urn:uuid:\${crypto.randomUUID()}\`,
    type: "ArohaRequest",
    from: "did:aroha:frontend",
    to:   "did:aroha:orchestrator",
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 60_000).toISOString(),
    nonce: crypto.randomUUID().replace(/-/g, ""),
    correlationId: crypto.randomUUID(),
    body: { capability: "chat", params: { message } },
  };

  const upstream = await fetch(\`\${ORCHESTRATOR}/aroha/v1\`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope),
  });

  if (!upstream.ok) {
    return NextResponse.json({ reply: "Orchestrator error: " + upstream.status }, { status: 502 });
  }

  const resp = await upstream.json() as { type: string; body: { result: { reply: string; source?: string } } };
  const result = resp.body?.result ?? { reply: "(empty response)" };
  return NextResponse.json(result);
}
`;
}

function globalsCss(): string {
  return `*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: #0d0d0d;
  color: #e0e0e0;
  height: 100vh;
  display: flex;
  justify-content: center;
  align-items: stretch;
}

.chat-root {
  width: 100%;
  max-width: 680px;
  display: flex;
  flex-direction: column;
  height: 100vh;
  border-left: 1px solid #1e1e1e;
  border-right: 1px solid #1e1e1e;
}

.chat-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 20px;
  border-bottom: 1px solid #1e1e1e;
  background: #111;
}

.chat-title { font-weight: 600; font-size: 15px; }

.chat-badge {
  font-size: 10px;
  padding: 2px 7px;
  border-radius: 999px;
  background: #1a2a1a;
  color: #4ade80;
  border: 1px solid #2d4a2d;
  letter-spacing: 0.5px;
}

.chat-messages {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.chat-msg { display: flex; flex-direction: column; }
.chat-msg.user { align-items: flex-end; }
.chat-msg.agent { align-items: flex-start; }

.chat-bubble {
  max-width: 80%;
  padding: 10px 14px;
  border-radius: 12px;
  font-size: 14px;
  line-height: 1.5;
}

.user .chat-bubble { background: #3b82f6; color: #fff; border-bottom-right-radius: 4px; }
.agent .chat-bubble { background: #1e1e1e; color: #e0e0e0; border-bottom-left-radius: 4px; }

.typing { letter-spacing: 4px; color: #666; }

.chat-source {
  font-size: 10px;
  color: #555;
  margin-top: 3px;
  padding: 0 4px;
}

.chat-input-row {
  display: flex;
  gap: 8px;
  padding: 14px 20px;
  border-top: 1px solid #1e1e1e;
  background: #111;
}

.chat-input {
  flex: 1;
  background: #1a1a1a;
  border: 1px solid #2a2a2a;
  border-radius: 8px;
  padding: 10px 14px;
  color: #e0e0e0;
  font-size: 14px;
  outline: none;
}

.chat-input:focus { border-color: #3b82f6; }

.chat-send {
  background: #3b82f6;
  color: #fff;
  border: none;
  border-radius: 8px;
  padding: 10px 18px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
}

.chat-send:hover { background: #2563eb; }
.chat-send:disabled { background: #1e3a5f; cursor: default; }
`;
}

// ─── Shared ───────────────────────────────────────────────────────────────────

function tsconfig(): string {
  return JSON.stringify({
    compilerOptions: {
      target: "ES2022",
      module: "NodeNext",
      moduleResolution: "NodeNext",
      lib: ["ES2022"],
      strict: true,
      declaration: true,
      sourceMap: true,
      outDir: "./dist",
      rootDir: "./src",
    },
    include: ["src/**/*"],
    exclude: ["dist", "node_modules"],
  }, null, 2);
}
