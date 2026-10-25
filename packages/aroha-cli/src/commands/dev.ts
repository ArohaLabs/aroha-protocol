// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `aroha dev` — Local Aroha sandbox
 *
 * Spins up a zero-config in-memory capability registry + live dashboard on
 * localhost:3000. Any @aroha-sdk/micro agent with devMode: true will automatically
 * register here on startup.
 *
 * Dashboard: http://localhost:3000
 * Registry:  GET  /registry
 *            POST /registry/register
 * Events:    GET  /events  (SSE — one JSON line per event)
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

// ─── State ────────────────────────────────────────────────────────────────────

interface AgentRecord {
  did: string;
  name: string;
  endpoint: string;
  capabilities: string[];
  registeredAt: string;
}

const agents = new Map<string, AgentRecord>(); // keyed by DID
const sseClients = new Set<ServerResponse>();

function broadcast(event: { type: string; data: unknown }): void {
  const line = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of sseClients) {
    try { res.write(line); } catch { sseClients.delete(res); }
  }
}

// ─── HTTP handler ─────────────────────────────────────────────────────────────

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  // ── SSE event stream ──────────────────────────────────────────────────────
  if (method === "GET" && url === "/events") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    res.write("data: {\"type\":\"connected\"}\n\n");
    sseClients.add(res);
    // Send current registry state immediately so new browser tabs see agents
    for (const agent of agents.values()) {
      res.write(`data: ${JSON.stringify({ type: "agent-registered", data: agent })}\n\n`);
    }
    req.on("close", () => sseClients.delete(res));
    return;
  }

  // ── Registry: list ────────────────────────────────────────────────────────
  if (method === "GET" && url === "/registry") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify([...agents.values()], null, 2));
    return;
  }

  // ── Registry: register ────────────────────────────────────────────────────
  if (method === "POST" && url === "/registry/register") {
    const body = await readBody(req);
    let record: AgentRecord;
    try {
      record = JSON.parse(body) as AgentRecord;
      if (!record.did || !record.endpoint) throw new Error("Missing required fields");
      record.registeredAt = record.registeredAt ?? new Date().toISOString();
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid registration payload" }));
      return;
    }
    agents.set(record.did, record);
    broadcast({ type: "agent-registered", data: record });
    console.log(`  \x1b[32m+\x1b[0m registered  ${record.name}  (${record.capabilities.join(", ")})`);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── Dashboard ─────────────────────────────────────────────────────────────
  if (method === "GET" && (url === "/" || url === "/index.html")) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(dashboardHtml());
    return;
  }

  res.writeHead(404); res.end();
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export interface DevFlags { port?: number }

export async function runDev(flags: DevFlags): Promise<void> {
  const port = flags.port ?? 3000;

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error("aroha dev error:", err);
      try { res.writeHead(500); res.end(); } catch { /* already sent */ }
    });
  });

  await new Promise<void>((resolve) => server.listen(port, resolve));

  const B = "\x1b[1m"; const C = "\x1b[36m"; const G = "\x1b[32m"; const R = "\x1b[0m";
  console.log(`\n${B}Aroha Dev Sandbox${R}`);
  console.log("─────────────────────────────────");
  console.log(`  ${G}✓${R} Dashboard   ${C}http://localhost:${port}${R}`);
  console.log(`  ${G}✓${R} Registry    ${C}http://localhost:${port}/registry${R}`);
  console.log(`  ${G}✓${R} Events      ${C}http://localhost:${port}/events${R}  (SSE)\n`);
  console.log("  Waiting for agents to connect...");
  console.log("  Start any @aroha-sdk/micro agent — it will appear here automatically.\n");

  // Keep alive — Ctrl+C to exit
  process.on("SIGINT", () => { console.log("\n  Stopped."); server.close(); process.exit(0); });
  await new Promise(() => { /* run forever */ });
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ─── Dashboard HTML ───────────────────────────────────────────────────────────

function dashboardHtml(): string {
  return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Aroha Dev Sandbox</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d0d0d;color:#e0e0e0;min-height:100vh;display:grid;grid-template-rows:auto 1fr;grid-template-columns:1fr 1fr;gap:0}
  header{grid-column:1/-1;display:flex;align-items:center;gap:12px;padding:16px 24px;border-bottom:1px solid #1e1e1e;background:#111}
  .logo{font-size:20px;font-weight:700;letter-spacing:-0.5px;color:#fff}
  .logo span{color:#3b82f6}
  .badge{font-size:11px;padding:2px 8px;border-radius:999px;background:#1a2a1a;color:#4ade80;border:1px solid #2d4a2d;letter-spacing:0.5px}
  .pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;margin-right:6px;animation:pulse 2s ease-in-out infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
  .panel{padding:20px;overflow-y:auto;border-right:1px solid #1e1e1e}
  .panel:last-child{border-right:none}
  .panel-title{font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:#666;margin-bottom:16px}
  .empty{color:#444;font-size:13px;padding:20px 0}
  .agent-card{background:#161616;border:1px solid #222;border-radius:8px;padding:14px;margin-bottom:10px;transition:border-color .2s}
  .agent-card:hover{border-color:#333}
  .agent-name{font-weight:600;font-size:14px;color:#fff;margin-bottom:4px}
  .agent-endpoint{font-size:11px;color:#3b82f6;font-family:monospace;margin-bottom:8px;word-break:break-all}
  .agent-did{font-size:10px;color:#555;font-family:monospace;margin-bottom:8px;word-break:break-all}
  .caps{display:flex;flex-wrap:wrap;gap:4px}
  .cap{font-size:10px;padding:2px 7px;border-radius:4px;background:#1a1a2e;border:1px solid #2d2d4d;color:#818cf8;font-family:monospace}
  .event-list{display:flex;flex-direction:column;gap:4px}
  .event{font-size:12px;font-family:monospace;padding:8px 10px;border-radius:6px;border-left:3px solid #333;background:#141414;word-break:break-all;animation:fadeIn .3s ease}
  @keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
  .event.registered{border-color:#4ade80}
  .event.envelope{border-color:#3b82f6}
  .event.error{border-color:#f87171}
  .ts{color:#555;margin-right:8px}
  .count{color:#666;font-size:11px;margin-left:8px}
  .test-form{margin-top:16px;background:#161616;border:1px solid #222;border-radius:8px;padding:14px}
  .test-form label{display:block;font-size:11px;color:#666;margin-bottom:4px;margin-top:10px}
  .test-form label:first-child{margin-top:0}
  .test-form input,.test-form textarea,.test-form select{width:100%;background:#0d0d0d;border:1px solid #2a2a2a;border-radius:5px;padding:6px 8px;color:#e0e0e0;font-size:12px;font-family:monospace;outline:none}
  .test-form input:focus,.test-form textarea:focus,.test-form select:focus{border-color:#3b82f6}
  .test-form textarea{resize:vertical;min-height:64px}
  .send-btn{margin-top:12px;background:#3b82f6;color:#fff;border:none;border-radius:5px;padding:7px 16px;font-size:13px;font-weight:500;cursor:pointer;width:100%;transition:background .15s}
  .send-btn:hover{background:#2563eb}
  .send-btn:disabled{background:#1e3a5f;cursor:default}
  .result{margin-top:10px;font-size:11px;font-family:monospace;white-space:pre-wrap;background:#0d0d0d;border-radius:5px;padding:8px;border:1px solid #1e1e1e;max-height:120px;overflow-y:auto}
</style>
</head>
<body>
<header>
  <div class="logo">Aroha <span>Dev</span> Sandbox</div>
  <div class="badge"><span class="pulse"></span>live</div>
</header>

<div class="panel" id="agentsPanel">
  <div class="panel-title">Agents <span id="agentCount" class="count">0</span></div>
  <div id="agentList"><p class="empty">No agents yet. Start a <code>@aroha-sdk/micro</code> agent to see it here.</p></div>

  <div class="test-form">
    <div style="font-size:12px;font-weight:600;margin-bottom:8px;color:#888">Send test message</div>
    <label>Agent</label>
    <select id="targetAgent"><option value="">— select an agent —</option></select>
    <label>Capability</label>
    <input id="capInput" type="text" placeholder="e.g. get-weather"/>
    <label>Params (JSON)</label>
    <textarea id="paramsInput">{\n  "city": "Tokyo"\n}</textarea>
    <button class="send-btn" id="sendBtn" onclick="sendMsg()">Send ArohaRequest</button>
    <div id="sendResult" class="result" style="display:none"></div>
  </div>
</div>

<div class="panel">
  <div class="panel-title">Event stream <span id="eventCount" class="count">0</span></div>
  <div id="eventList" class="event-list"><p class="empty">Events will appear here as agents communicate.</p></div>
</div>

<script>
const agentMap = new Map();
let eventTotal = 0;
let es = null;
let reconnectTimer = null;

function connectSSE() {
  if (es) { try { es.close(); } catch {} }
  es = new EventSource('/events');
  es.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'agent-registered') onAgentRegistered(msg.data);
    if (msg.type === 'envelope')         onEnvelope(msg.data);
    if (msg.type !== 'connected')        addEvent(msg);
  };
  es.onerror = () => {
    es.close();
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => { reconnectTimer = null; connectSSE(); }, 2000);
    }
  };
}
connectSSE();

function onAgentRegistered(agent) {
  agentMap.set(agent.did, agent);
  renderAgents();
}

function renderAgents() {
  const list = document.getElementById('agentList');
  const sel  = document.getElementById('targetAgent');
  document.getElementById('agentCount').textContent = agentMap.size;

  if (!agentMap.size) {
    list.innerHTML = '<p class="empty">No agents yet. Start a <code>@aroha-sdk/micro</code> agent to see it here.</p>';
    sel.innerHTML  = '<option value="">— select an agent —</option>';
    return;
  }

  list.innerHTML = [...agentMap.values()].map(a => \`
    <div class="agent-card">
      <div class="agent-name">\${esc(a.name)}</div>
      <div class="agent-endpoint">\${esc(a.endpoint)}/aroha/v1</div>
      <div class="agent-did">\${esc(a.did)}</div>
      <div class="caps">\${(a.capabilities||[]).map(c=>\`<span class="cap">\${esc(c)}</span>\`).join('')}</div>
    </div>
  \`).join('');

  sel.innerHTML = '<option value="">— select an agent —</option>' +
    [...agentMap.values()].map(a => \`<option value="\${esc(a.endpoint)}">\${esc(a.name)}</option>\`).join('');

  sel.onchange = () => {
    const a = [...agentMap.values()].find(x => x.endpoint === sel.value);
    if (a?.capabilities?.[0]) document.getElementById('capInput').value = a.capabilities[0];
  };
}

function onEnvelope(data) { addEvent({ type: 'envelope', data }); }

function addEvent(msg) {
  eventTotal++;
  document.getElementById('eventCount').textContent = eventTotal;

  const list = document.getElementById('eventList');
  if (list.querySelector('.empty')) list.innerHTML = '';

  const el = document.createElement('div');
  const cls = msg.type === 'agent-registered' ? 'registered' : msg.type === 'envelope' ? 'envelope' : '';
  el.className = 'event ' + cls;
  const ts = new Date().toLocaleTimeString('en', { hour12: false });
  el.innerHTML = \`<span class="ts">\${ts}</span>\${esc(msg.type)}: \${esc(JSON.stringify(msg.data ?? {}).slice(0,140))}\`;
  list.prepend(el);
  if (list.children.length > 80) list.lastChild.remove();
}

async function sendMsg() {
  const endpoint = document.getElementById('targetAgent').value;
  const cap      = document.getElementById('capInput').value.trim();
  const rawParms = document.getElementById('paramsInput').value.trim();
  const btn      = document.getElementById('sendBtn');
  const result   = document.getElementById('sendResult');

  if (!endpoint || !cap) { alert('Select an agent and enter a capability'); return; }
  let params;
  try { params = JSON.parse(rawParms); } catch { alert('Params must be valid JSON'); return; }

  btn.disabled = true; btn.textContent = 'Sending…';
  result.style.display = 'none';

  // Build a minimal dev envelope (no real signing needed since devMode skips verify)
  const envelope = {
    "@context": ["https://aroha-labs.com/contexts/v1"],
    id: "urn:uuid:" + crypto.randomUUID(),
    type: "ArohaRequest",
    from: "did:aroha:dashboard",
    to:   "did:aroha:target",
    created: new Date().toISOString(),
    expires: new Date(Date.now() + 60000).toISOString(),
    nonce: crypto.randomUUID().replace(/-/g,''),
    correlationId: crypto.randomUUID(),
    body: { capability: cap, params },
  };

  try {
    const r = await fetch(endpoint + '/aroha/v1', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(envelope),
    });
    const text = await r.text();
    let pretty;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch { pretty = text; }
    result.textContent = pretty;
    result.style.display = 'block';
    addEvent({ type: 'envelope', data: { cap, status: r.status } });
  } catch(e) {
    result.textContent = 'Error: ' + e.message;
    result.style.display = 'block';
  } finally {
    btn.disabled = false; btn.textContent = 'Send ArohaRequest';
  }
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>`;
}
