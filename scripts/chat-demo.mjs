// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Personal Agent — Chat Interface (LLM-powered)
 *
 * Every agent (Personal, Flight, Hotel, Payment) runs its own LLM call.
 * The Aroha protocol layer wraps those LLM decisions in signed Ed25519 envelopes.
 *
 * LLM backend priority (per README):
 *   1. VLLM_URL  — local vllm server (Qwen/Qwen2.5-1.5B-Instruct or any OpenAI-compatible model)
 *   2. ANTHROPIC_API_KEY — Claude as fallback
 *   3. Rule-based  — if neither is configured
 *
 * Agent roles:
 *   Personal Agent  — orchestrates, understands user intent, writes conversational chat replies
 *   Flight Agent    — analyzes flight options, picks best fit, explains reasoning
 *   Hotel Agent     — analyzes hotel options, recommends for business traveler
 *   Payment Agent   — validates transaction, generates confirmation
 *
 * Usage (from README):
 *   # vllm (local GPU — recommended):
 *   VLLM_URL=http://localhost:8000/v1 node scripts/chat-demo.mjs
 *
 *   # Anthropic fallback:
 *   ANTHROPIC_API_KEY=sk-ant-... node scripts/chat-demo.mjs
 *
 *   # With Gmail:
 *   VLLM_URL=http://localhost:8000/v1 GMAIL_USER=you@example.com GMAIL_APP_PASSWORD="xxxx xxxx xxxx xxxx" node scripts/chat-demo.mjs
 */

import { createServer } from "http";
import { randomUUID } from "crypto";
import { readFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { ethers } from "ethers";
import Anthropic from "@anthropic-ai/sdk";
import nodemailer from "nodemailer";
import { generateDID, buildEnvelope } from "@aroha-sdk/core";

const __mjs_dir = dirname(fileURLToPath(import.meta.url));
const CHAIN_ADDR_PATH = join(__mjs_dir, "..", "chain-addresses.json");

// ─── Anvil chain constants (Foundry well-known test keys — local dev only) ────

// Anvil account #0: deployer / orchestrator
const ANVIL_DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// Minimal ABIs — only what the demo actually calls
const REGISTRY_ABI = [
  "function register(bytes32 didHash, string calldata manifestCID, bytes calldata publicKey) external payable",
  "function indexCapabilities(bytes32 didHash, bytes32[] calldata capabilityHashes) external",
  "function queryByCapability(bytes32[] calldata capabilityHashes) external view returns (tuple(bytes32 didHash, address ownerAddress, string manifestCID, bytes publicKey, uint256 stakedWei, uint32 reputationScore, bool active, uint256 registeredAt, uint256 lastUpdatedAt)[] memory)",
  "function minStakeWei() external view returns (uint256)",
];
const ESCROW_ABI = [
  "function open(bytes32 sagaId, uint256 ttlSeconds) external payable",
  "function approveSplit(bytes32 sagaId, address payable recipient, uint256 amount) external",
  "function release(bytes32 sagaId) external",
  "function getEscrow(bytes32 sagaId) external view returns (tuple(bytes32 sagaId, address payer, uint256 totalAmount, uint256 releasedAmount, uint8 state, uint256 createdAt, uint256 expiresAt))",
];
const REPUTATION_ABI = [
  "function recordOutcome(bytes32 sagaId, bytes32 agentDID, uint8 outcome) external",
  "function getScore(bytes32 agentDID) external view returns (uint32)",
];

// ─── Chain state (null = simulation mode) ────────────────────────────────────
let chain = null; // { provider, signer, registry, escrow, reputation, addrs }

// ─── Startup activity buffer (populated before session exists) ───────────────
const _startupBuf = [];
function _queueActivity(from, to, type, summary, envelope = null) {
  _startupBuf.push({ id: randomUUID(), ts: Date.now(), from, to, type, summary, envelope });
}

async function initChain() {
  if (!existsSync(CHAIN_ADDR_PATH)) {
    console.log("[chain] chain-addresses.json not found — running in simulation mode");
    console.log("[chain] To enable on-chain: forge build && node scripts/setup-chain.mjs");
    return;
  }
  try {
    const addrs   = JSON.parse(readFileSync(CHAIN_ADDR_PATH, "utf8"));
    const url     = addrs.anvilUrl ?? "http://127.0.0.1:8545";
    const provider = new ethers.JsonRpcProvider(url);
    await provider.getBlockNumber(); // connectivity check
    const signer   = new ethers.Wallet(ANVIL_DEPLOYER_KEY, provider);
    chain = {
      provider,
      signer,
      registry:   new ethers.Contract(addrs.registry,   REGISTRY_ABI,   signer),
      escrow:     new ethers.Contract(addrs.escrow,     ESCROW_ABI,     signer),
      reputation: new ethers.Contract(addrs.reputation, REPUTATION_ABI, signer),
      addrs,
    };
    console.log("[chain] ✓ Anvil connected @", url);
    console.log("[chain]   Registry  :", addrs.registry);
    console.log("[chain]   Escrow    :", addrs.escrow);
    console.log("[chain]   Reputation:", addrs.reputation);
  } catch (e) {
    console.warn("[chain] Anvil unreachable (", e.message, ") — running in simulation mode");
    chain = null;
  }
}

async function registerAgentsOnChain(agents) {
  if (!chain) return;
  try {
    const minStake = await chain.registry.minStakeWei();
    const CAPS = {
      "flight-agent":  ["book-flight"],
      "hotel-agent":   ["book-hotel"],
      "payment-agent": ["process-payment"],
    };
    for (const agent of agents) {
      const didHash  = ethers.keccak256(ethers.toUtf8Bytes(agent.did));
      const pubBytes = ethers.hexlify(agent.publicKey); // Uint8Array → hex
      const caps     = (CAPS[agent.did.split(":")[2]] ?? []).map(
        c => ethers.keccak256(ethers.toUtf8Bytes(c))
      );
      process.stdout.write("[chain] Registering " + agent.did.slice(0, 32) + "… ");
      try {
        // fetch fresh nonce each tx to avoid stale cache after anvil resets
        const nonce1 = await chain.provider.getTransactionCount(chain.signer.address, "pending");
        const tx1 = await chain.registry.register(
          didHash,
          `ipfs://aroha-demo-${agent.did.slice(-8)}`,
          pubBytes,
          { value: minStake, nonce: nonce1 }
        );
        await tx1.wait();
        if (caps.length > 0) {
          const nonce2 = await chain.provider.getTransactionCount(chain.signer.address, "pending");
          await (await chain.registry.indexCapabilities(didHash, caps, { nonce: nonce2 })).wait();
        }
        console.log("✓");
      } catch (e) {
        console.log("skipped (", e.message.slice(0, 50), ")");
      }
    }
    console.log("[chain] ✓ All agents registered on-chain");
  } catch (e) {
    console.warn("[chain] Agent registration failed:", e.message);
  }
}

// ── Chain helper: real registry query ────────────────────────────────────────
async function chainRegistryQuery() {
  if (!chain) {
    pushActivity("chain", "registry", "⛓ ArohaRegistry.sol", "queryByCapability(0x62666c74) → 3 agents · stake ✓ · reputation verified [simulated]");
    return;
  }
  try {
    const capHashes = ["book-flight", "book-hotel", "process-payment"]
      .map(c => ethers.keccak256(ethers.toUtf8Bytes(c)));
    const agents = await chain.registry.queryByCapability(capHashes);
    const block  = await chain.provider.getBlockNumber();
    pushActivity("chain", "registry", "⛓ ArohaRegistry.sol",
      `queryByCapability(3 caps) → ${agents.length} agent(s) · block #${block} · on-chain ✓`);
  } catch (e) {
    pushActivity("chain", "registry", "⛓ ArohaRegistry.sol", `queryByCapability → ERROR: ${e.message.slice(0, 60)}`);
  }
}

// ── Chain helper: open escrow ────────────────────────────────────────────────
async function chainEscrowOpen(sid, grandTotal) {
  if (!chain) {
    pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol",
      `lockFunds(saga:${sid.slice(0, 8)}, $${grandTotal.toLocaleString()}) → funds held · saga open [simulated]`);
    return;
  }
  try {
    const sagaBytes = ethers.keccak256(ethers.toUtf8Bytes(sid));
    const tx        = await chain.escrow.open(sagaBytes, 3600, { value: ethers.parseEther("1.0") });
    const receipt   = await tx.wait();
    pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol",
      `open(saga:${sid.slice(0, 8)}) · 1.0 ETH locked · tx:${receipt.hash.slice(0, 14)}… · block #${receipt.blockNumber}`);
  } catch (e) {
    pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol",
      `open(saga:${sid.slice(0, 8)}) → ERROR: ${e.message.slice(0, 60)}`);
  }
}

// ── Chain helper: release escrow + record reputation ─────────────────────────
async function chainEscrowRelease(sid) {
  if (!chain) {
    pushActivity("chain", "escrow",     "⛓ ArohaEscrow.sol",     `release(saga:${sid.slice(0, 8)}) → settled [simulated]`);
    pushActivity("chain", "reputation", "⛓ ArohaReputation.sol", `recordOutcome(3 agents, SUCCESS) → rep++ [simulated]`);
    return;
  }
  try {
    const sagaBytes = ethers.keccak256(ethers.toUtf8Bytes(sid));
    const addrs     = chain.addrs.agentWallets;
    // Approve splits: 60% flight, 35% hotel (remaining 5% refunds to payer)
    await (await chain.escrow.approveSplit(sagaBytes, addrs.flight,  ethers.parseEther("0.60"))).wait();
    await (await chain.escrow.approveSplit(sagaBytes, addrs.hotel,   ethers.parseEther("0.35"))).wait();
    const relTx      = await chain.escrow.release(sagaBytes);
    const relReceipt = await relTx.wait();
    pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol",
      `release(saga:${sid.slice(0, 8)}) · 0.60+0.35 ETH split · tx:${relReceipt.hash.slice(0, 14)}… · block #${relReceipt.blockNumber} · RELEASED`);
  } catch (e) {
    pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol",
      `release(saga:${sid.slice(0, 8)}) → ERROR: ${e.message.slice(0, 60)}`);
  }
  // Reputation — record SUCCESS (enum 0) for each agent
  try {
    const sagaRep = ethers.keccak256(ethers.toUtf8Bytes(sid));
    for (const agent of [flight, hotel, payment]) {
      const agentDID = ethers.keccak256(ethers.toUtf8Bytes(agent.did));
      await (await chain.reputation.recordOutcome(sagaRep, agentDID, 0)).wait();
    }
    const flightScore  = await chain.reputation.getScore(ethers.keccak256(ethers.toUtf8Bytes(flight.did)));
    const hotelScore   = await chain.reputation.getScore(ethers.keccak256(ethers.toUtf8Bytes(hotel.did)));
    const paymentScore = await chain.reputation.getScore(ethers.keccak256(ethers.toUtf8Bytes(payment.did)));
    pushActivity("chain", "reputation", "⛓ ArohaReputation.sol",
      `recordOutcome(SUCCESS ×3) · FL:${flightScore} HT:${hotelScore} PY:${paymentScore} · on-chain ✓`);
  } catch (e) {
    pushActivity("chain", "reputation", "⛓ ArohaReputation.sol",
      `recordOutcome → ERROR: ${e.message.slice(0, 60)}`);
  }
}

const PORT            = parseInt(process.env.PORT ?? "3050");
const VLLM_URL        = process.env.VLLM_URL ?? "";
const VLLM_MODEL      = process.env.VLLM_MODEL ?? "Qwen/Qwen2.5-1.5B-Instruct";
const ANTHROPIC_KEY   = process.env.ANTHROPIC_API_KEY ?? "";
const GMAIL_USER      = process.env.GMAIL_USER ?? "";
const GMAIL_PASSWORD  = process.env.GMAIL_APP_PASSWORD ?? "";

const LLM_BACKEND = VLLM_URL ? "vllm" : ANTHROPIC_KEY ? "anthropic" : "none";

// ─── LLM backend: vllm (OpenAI-compatible) ────────────────────────────────────

async function vllmCall(systemPrompt, userContent, maxTokens = 400) {
  const resp = await fetch(`${VLLM_URL}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: VLLM_MODEL,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user",   content: userContent },
      ],
      max_tokens: maxTokens,
      temperature: 0.7,
    }),
  });
  if (!resp.ok) throw new Error(`vllm ${resp.status}: ${await resp.text()}`);
  const data = await resp.json();
  return data.choices?.[0]?.message?.content ?? "";
}

/** vllm streaming — reads SSE from the OpenAI-compatible /chat/completions endpoint. */
async function vllmStream(systemPrompt, userContent, maxTokens, onDelta) {
  const resp = await fetch(`${VLLM_URL}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: VLLM_MODEL,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user",   content: userContent },
      ],
      max_tokens: maxTokens,
      temperature: 0.7,
      stream: true,
    }),
  });
  if (!resp.ok) throw new Error(`vllm ${resp.status}: ${await resp.text()}`);
  let full = "";
  const reader = resp.body.getReader();
  const dec    = new TextDecoder();
  let buf = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop();
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      const raw = line.slice(6).trim();
      if (raw === "[DONE]") break;
      try {
        const chunk = JSON.parse(raw);
        const delta = chunk.choices?.[0]?.delta?.content ?? "";
        if (delta) { full += delta; onDelta(delta); }
      } catch {}
    }
  }
  return full;
}

// ─── LLM backend: Anthropic ───────────────────────────────────────────────────

const ai = ANTHROPIC_KEY ? new Anthropic({ apiKey: ANTHROPIC_KEY }) : null;

async function anthropicCall(systemPrompt, userContent, maxTokens = 400) {
  const msg = await ai.messages.create({
    model: "claude-haiku-4-5-20251001",
    max_tokens: maxTokens,
    system: systemPrompt,
    messages: [{ role: "user", content: userContent }],
  });
  return msg.content.find(b => b.type === "text")?.text ?? "";
}

async function anthropicStream(systemPrompt, userContent, maxTokens, onDelta) {
  let full = "";
  const stream = ai.messages.stream({
    model: "claude-sonnet-4-6",
    max_tokens: maxTokens,
    system: systemPrompt,
    messages: [{ role: "user", content: userContent }],
  });
  for await (const chunk of stream) {
    if (chunk.type === "content_block_delta" && chunk.delta.type === "text_delta") {
      full += chunk.delta.text;
      onDelta(chunk.delta.text);
    }
  }
  return full;
}

// ─── Unified LLM interface ────────────────────────────────────────────────────

/** Call the active LLM backend. Returns null if no backend is configured. */
async function llm(agentName, systemPrompt, userContent, maxTokens = 400) {
  if (LLM_BACKEND === "none") return null;
  pushActivity("llm", agentName, "LLM",
    `${agentName} → ${LLM_BACKEND === "vllm" ? VLLM_MODEL : "claude-haiku-4-5"} (${maxTokens} tok)`);
  try {
    const text = LLM_BACKEND === "vllm"
      ? await vllmCall(systemPrompt, userContent, maxTokens)
      : await anthropicCall(systemPrompt, userContent, maxTokens);
    pushActivity(agentName, "llm", "LLM", `${agentName} → ${text.length} chars`);
    return text;
  } catch (err) {
    pushActivity(agentName, "llm", "LLM", `ERROR: ${err.message}`);
    return null;
  }
}

/** Streaming version — forwards deltas to browser via SSE. */
async function llmStream(agentName, systemPrompt, userContent, maxTokens = 600) {
  if (LLM_BACKEND === "none") return null;
  pushActivity("llm", agentName, "LLM",
    `${agentName} → ${LLM_BACKEND === "vllm" ? VLLM_MODEL : "claude-sonnet-4-6"} streaming…`);

  const msgId = randomUUID();

  try {
    // Only open a streaming bubble once we know the first token is coming
    let started = false;
    const onFirstDelta = (delta, onDelta) => {
      if (!started) { started = true; broadcast("chat_stream_start", { id: msgId, agent: agentName }); }
      onDelta(delta);
    };
    const full = LLM_BACKEND === "vllm"
      ? await vllmStream(systemPrompt, userContent, maxTokens, delta => onFirstDelta(delta, d => broadcast("chat_stream_delta", { id: msgId, delta: d })))
      : await anthropicStream(systemPrompt, userContent, maxTokens, delta => onFirstDelta(delta, d => broadcast("chat_stream_delta", { id: msgId, delta: d })));
    if (started) broadcast("chat_stream_end", { id: msgId, text: full });
    pushActivity(agentName, "llm", "LLM", `${agentName} streamed ${full.length} chars`);
    return full || null;
  } catch (err) {
    pushActivity(agentName, "llm", "LLM", `STREAM ERROR: ${err.message}`);
    console.error(`[llmStream] ${agentName}:`, err.message);
    return null;
  }
}

// ─── Agent boots ──────────────────────────────────────────────────────────────

console.log("[Chat] Generating agent identities…");
const [personal, flight, hotel, payment] = await Promise.all([
  generateDID("personal-agent",  `http://localhost:${PORT}/aroha/v1/personal`),
  generateDID("flight-agent",    `http://localhost:${PORT}/aroha/v1/flight`),
  generateDID("hotel-agent",     `http://localhost:${PORT}/aroha/v1/hotel`),
  generateDID("payment-agent",   `http://localhost:${PORT}/aroha/v1/payment`),
]);
console.log("[Chat] Personal :", personal.did);
console.log("[Chat] Flight   :", flight.did);
console.log("[Chat] Hotel    :", hotel.did);
console.log("[Chat] Payment  :", payment.did);
console.log("[Chat] LLM      :", LLM_BACKEND === "vllm" ? `vllm @ ${VLLM_URL} (${VLLM_MODEL})` : LLM_BACKEND === "anthropic" ? "Anthropic (claude-sonnet-4-6)" : "DISABLED — set VLLM_URL or ANTHROPIC_API_KEY");
console.log("[Chat] Gmail    :", GMAIL_USER || "(not configured)");

// ─── Blockchain (Anvil) ────────────────────────────────────────────────────────
await initChain();
if (chain) await registerAgentsOnChain([flight, hotel, payment]);
console.log("[chain] Mode    :", chain ? `on-chain (${chain.addrs.anvilUrl})` : "simulation");

// ─── Startup activity log (buffered until session is ready) ────────────────
_queueActivity("system", "personal", "Boot", `Personal Agent online · ${personal.did.slice(0, 32)}…`);
_queueActivity("system", "flight",   "Boot", `Flight Agent online   · ${flight.did.slice(0, 32)}…`);
_queueActivity("system", "hotel",    "Boot", `Hotel Agent online    · ${hotel.did.slice(0, 32)}…`);
_queueActivity("system", "payment",  "Boot", `Payment Agent online  · ${payment.did.slice(0, 32)}…`);
if (chain) {
  _queueActivity("chain", "registry",   "⛓ ArohaRegistry.sol",   `deployed · ${chain.addrs.registry}`);
  _queueActivity("chain", "escrow",     "⛓ ArohaEscrow.sol",     `deployed · ${chain.addrs.escrow}`);
  _queueActivity("chain", "reputation", "⛓ ArohaReputation.sol", `deployed · ${chain.addrs.reputation}`);
} else {
  _queueActivity("chain", "system", "⛓ Chain", "Simulation mode — run setup-chain.mjs to enable on-chain");
}

// ─── vllm health check ────────────────────────────────────────────────────────
let vllmReady = LLM_BACKEND !== "vllm"; // non-vllm backends are always "ready"
if (LLM_BACKEND === "vllm") {
  (async () => {
    for (let attempt = 1; attempt <= 60; attempt++) {
      try {
        const r = await fetch(`${VLLM_URL}/models`);
        if (r.ok) {
          vllmReady = true;
          console.log(`[Chat] vllm ready after ${attempt * 2}s`);
          broadcast("llm_status", { ready: true, backend: "vllm", model: VLLM_MODEL });
          return;
        }
      } catch {}
      if (attempt === 1) {
        console.log("[Chat] Waiting for vllm to load model…");
        broadcast("llm_status", { ready: false, backend: "vllm", model: VLLM_MODEL, msg: "vllm loading model…" });
      }
      await new Promise(r => setTimeout(r, 2000));
    }
    console.warn("[Chat] vllm did not become ready within 120s — LLM calls will fail");
    broadcast("llm_status", { ready: false, backend: "vllm", model: VLLM_MODEL, msg: "vllm unreachable" });
  })();
}

// ─── Agent system prompts ────────────────────────────────────────────────────

const PROMPTS = {
  personal: `You are a Personal Agent in the Aroha multi-agent protocol network. You help users plan and book business travel by orchestrating specialized sub-agents (flight, hotel, payment).

Your personality: professional, warm, efficient. You never pad responses with unnecessary filler. You understand context and preferences without the user having to repeat themselves.

Rules:
- Keep chat replies concise — 1-3 sentences unless detail is genuinely needed.
- When presenting agent results, briefly explain your recommendation and why.
- Never say "I" in a robotic way. Speak naturally.
- If the user asks about something outside travel, gracefully redirect.`,

  flight: `You are a Flight Agent in the Aroha multi-agent protocol network. You specialize in analyzing flight options for business travelers.

When given a list of flight options and a traveler's profile, you:
1. Identify the best option (balancing price, duration, stops, departure time)
2. Explain your reasoning in 2-3 sentences
3. Return a JSON object: { "recommendedId": "...", "reasoning": "...", "highlights": ["...", "..."] }

Always return valid JSON. No markdown code blocks — raw JSON only.`,

  hotel: `You are a Hotel Agent in the Aroha multi-agent protocol network. You specialize in hotel recommendations for business travelers.

When given hotel options and trip context, you:
1. Identify the best hotel (balancing location, amenities, price, and business suitability)
2. Explain your reasoning in 2-3 sentences
3. Return a JSON object: { "recommendedId": "...", "reasoning": "...", "highlights": ["...", "..."] }

Always return valid JSON. No markdown code blocks — raw JSON only.`,

  payment: `You are a Payment Agent in the Aroha multi-agent protocol network. You handle atomic payment processing for multi-party travel bookings.

When confirming a payment, generate a brief professional confirmation message (1-2 sentences) acknowledging the charge amount, last 4 card digits, and that the transaction is part of an atomic saga that has fully committed.

Return only the confirmation text — no JSON, no formatting.`,
};

// ─── Gmail ────────────────────────────────────────────────────────────────────

const mailer = GMAIL_USER ? nodemailer.createTransport({
  service: "gmail",
  auth: { user: GMAIL_USER, pass: GMAIL_PASSWORD },
}) : null;

async function sendEmail(to, subject, html) {
  if (!mailer) return { sent: false };
  try {
    const info = await mailer.sendMail({ from: `"Aroha Personal Agent" <${GMAIL_USER}>`, to, subject, html });
    return { sent: true, messageId: info.messageId };
  } catch (err) {
    console.error("[Gmail]", err.message);
    return { sent: false, error: err.message };
  }
}

// ─── Calendar ────────────────────────────────────────────────────────────────

function makeICS(summary, location, start, end, description) {
  const fmt = d => d.replace(/[-:]/g, "").replace(/\.\d+Z/, "Z");
  return [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Aroha Personal Agent//EN",
    "BEGIN:VEVENT",
    `UID:${randomUUID()}@aroha-labs.com`,
    `DTSTAMP:${fmt(new Date().toISOString())}`,
    `DTSTART:${fmt(new Date(start).toISOString())}`,
    `DTEND:${fmt(new Date(end).toISOString())}`,
    `SUMMARY:${summary}`,
    `LOCATION:${location}`,
    `DESCRIPTION:${description.replace(/\n/g, "\\n")}`,
    "END:VEVENT", "END:VCALENDAR",
  ].join("\r\n");
}

function googleCalendarUrl(summary, location, start, end, description) {
  const fmt = d => d.replace(/[-:T]/g, "").slice(0, 15) + "Z";
  return `https://calendar.google.com/calendar/render?` +
    new URLSearchParams({ action: "TEMPLATE", text: summary, location, dates: `${fmt(start)}/${fmt(end)}`, details: description });
}

// ─── Mock inventory ───────────────────────────────────────────────────────────

const FLIGHTS = [
  { id: "F001", airline: "ANA",    no: "NH 175", dep: "08:05", arr: "10:50+1", price: 2150, stops: "Non-stop", dur: "14h 45m", seats: 4, class: "Business", note: "Flagship carrier, excellent service, on-time record 94%" },
  { id: "F002", airline: "JAL",    no: "JL 061", dep: "11:30", arr: "14:15+1", price: 2280, stops: "Non-stop", dur: "14h 45m", seats: 2, class: "Business", note: "Premium service, last 2 seats available" },
  { id: "F003", airline: "United", no: "UA 837", dep: "14:50", arr: "18:30+1", price: 1890, stops: "1 stop",   dur: "17h 40m", seats: 6, class: "Business", note: "Cheapest option, 1 stop in SFO, longer journey" },
];
const HOTELS = [
  { id: "H001", name: "Park Hyatt Tokyo",    area: "Shinjuku",   price: 620, stars: 5, rating: 4.9, amenities: ["Sky Lounge","Spa","Michelin Restaurant"], note: "Featured in Lost in Translation, iconic views, quiet district" },
  { id: "H002", name: "Andaz Tokyo",         area: "Toranomon",  price: 480, stars: 5, rating: 4.7, amenities: ["Rooftop Bar","Fitness Center","Club Lounge"], note: "Great value, modern design, near business district" },
  { id: "H003", name: "The Peninsula Tokyo", area: "Marunouchi", price: 720, stars: 5, rating: 4.9, amenities: ["Rolls Royce Fleet","Pool","Afternoon Tea"], note: "Most expensive, ultra-luxury, Ginza/finance district" },
];
const CARD = { last4: "4242", expiry: "04/28", holder: "Alex Chen", type: "Visa Infinite" };

// ─── Session state ────────────────────────────────────────────────────────────

function newSession() {
  return {
    id: randomUUID(),
    state: "idle",
    sagaId: randomUUID(),
    conversationHistory: [],  // for multi-turn Claude context
    intent: null,
    flight: null,
    hotel: null,
    userEmail: "",
    messages: [],
    activityLog: [],
    notifications: [],
    icsData: null,
    bookingRef: null,
    humanResolvers: {},
  };
}

// flush startup buffer into the first session
let session = newSession();
_startupBuf.forEach(e => session.activityLog.push(e));
_startupBuf.length = 0;
let sseClients = [];

// ─── SSE ──────────────────────────────────────────────────────────────────────

function broadcast(type, data) {
  const line = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  sseClients.forEach(r => { try { r.write(line); } catch {} });
}

// ─── Chat / activity helpers ──────────────────────────────────────────────────

function pushChat(role, content, extra = {}) {
  const m = { id: randomUUID(), ts: Date.now(), role, content, ...extra };
  session.messages.push(m);
  // add agent messages to conversation history for multi-turn context
  if (role === "user")  session.conversationHistory.push({ role: "user",      content });
  if (role === "agent") session.conversationHistory.push({ role: "assistant", content });
  broadcast("chat", m);
  return m;
}

function pushActivity(from, to, type, summary, envelope = null) {
  const e = { id: randomUUID(), ts: Date.now(), from, to, type, summary, envelope };
  session.activityLog.push(e);
  broadcast("activity", e);
}

function pushNotification(title, body, icon = "🔔") {
  const n = { id: randomUUID(), ts: Date.now(), title, body, icon };
  session.notifications.push(n);
  broadcast("notification", n);
}

function waitForHuman(key) {
  return new Promise(resolve => { session.humanResolvers[key] = resolve; });
}

// ─── Email template ───────────────────────────────────────────────────────────

function bookingEmailHtml(f, h, total, pnr, confNo, chargeId, calUrl) {
  return `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;background:#f8fafc;margin:0;padding:24px">
<div style="max-width:600px;margin:0 auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
  <div style="background:linear-gradient(135deg,#1e3a5f,#0f2440);padding:32px;text-align:center">
    <div style="font-size:28px;font-weight:800;color:white">Aroha<span style="color:#3b82f6">.</span>io</div>
    <div style="color:rgba(255,255,255,.7);font-size:14px;margin-top:4px">Personal Agent — Booking Confirmation</div>
  </div>
  <div style="padding:32px">
    <h2 style="color:#0f172a;margin:0 0 8px">Your Tokyo trip is confirmed ✓</h2>
    <p style="color:#64748b;margin:0 0 28px">All three agents committed atomically. Safe travels!</p>
    <div style="background:#f8fafc;border-radius:12px;padding:20px;margin-bottom:16px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:12px">FLIGHT</div>
      <div style="font-size:18px;font-weight:700;color:#0f172a">${f.airline} ${f.no} — JFK → NRT</div>
      <div style="color:#64748b;margin-top:4px">May 1, 2026 · Departs ${f.dep} · ${f.class} · ${f.stops}</div>
      <div style="margin-top:8px"><span style="background:#eff6ff;color:#3b82f6;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">PNR: ${pnr}</span></div>
    </div>
    <div style="background:#f8fafc;border-radius:12px;padding:20px;margin-bottom:16px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:12px">HOTEL</div>
      <div style="font-size:18px;font-weight:700;color:#0f172a">${h.name}</div>
      <div style="color:#64748b;margin-top:4px">May 1–7, 2026 · 6 nights · ${h.area}, Tokyo</div>
      <div style="margin-top:8px"><span style="background:#f0fdf4;color:#10b981;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600">Conf# ${confNo}</span></div>
    </div>
    <div style="background:#f8fafc;border-radius:12px;padding:20px;margin-bottom:28px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:12px">PAYMENT</div>
      <div style="display:flex;justify-content:space-between;font-size:14px"><span style="color:#64748b">Flight (${f.airline})</span><span>$${f.price.toLocaleString()}</span></div>
      <div style="display:flex;justify-content:space-between;font-size:14px;margin-top:6px"><span style="color:#64748b">Hotel (6 nights)</span><span>$${h.price*6}</span></div>
      <div style="border-top:1px solid #e2e8f0;margin-top:12px;padding-top:12px;display:flex;justify-content:space-between"><span style="font-weight:700">Total</span><span style="font-weight:800;color:#3b82f6;font-size:18px">$${total.toLocaleString()}</span></div>
      <div style="color:#94a3b8;font-size:12px;margin-top:6px">Charged to Visa ···· 4242 · Charge ID: ${chargeId.slice(0,20)}</div>
    </div>
    <a href="${calUrl}" style="display:block;text-align:center;background:#3b82f6;color:white;padding:14px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">📅 Add to Google Calendar</a>
    <p style="text-align:center;color:#94a3b8;font-size:12px;margin-top:16px">Booked via Aroha Personal Agent · Ed25519-signed atomic saga · ID: ${session.sagaId.slice(0,8)}</p>
  </div>
</div></body></html>`;
}

// ─── Booking workflow ─────────────────────────────────────────────────────────

async function runBooking(parsedIntent) {
  session.state = "running";
  const sid = session.sagaId;
  broadcast("state", { state: "running" });

  // ── Discover agents ──────────────────────────────────────────────────────────
  const discEnv = await buildEnvelope("ArohaRequest", personal.did, flight.did,
    { capability: "discover", params: { capabilities: ["book-flight","book-hotel","process-payment"] } },
    sid, personal.privateKey);
  pushActivity("personal", "registry", "ArohaRequest", "queryByCapability(['book-flight','book-hotel','process-payment'])", discEnv);
  await sleep(500);
  pushActivity("registry", "personal", "ArohaResponse", "Found: flight-agent, hotel-agent, payment-agent (3 agents)");
  await chainRegistryQuery();

  // ── Parallel: search flights + hotels ────────────────────────────────────────
  const [flightEnv, hotelEnv] = await Promise.all([
    buildEnvelope("ArohaRequest", personal.did, flight.did,
      { capability: "search-flights", params: { from: "JFK", to: "NRT", date: "2026-05-01", class: "Business", pax: 1 } },
      sid, personal.privateKey),
    buildEnvelope("ArohaRequest", personal.did, hotel.did,
      { capability: "search-hotels", params: { city: "Tokyo", checkIn: "2026-05-01", checkOut: "2026-05-07", stars: 5 } },
      sid, personal.privateKey),
  ]);
  pushActivity("personal", "flight", "ArohaRequest", "search-flights JFK→NRT May 1 Business (parallel)", flightEnv);
  pushActivity("personal", "hotel",  "ArohaRequest", "search-hotels Tokyo May 1–7 5-star (parallel)", hotelEnv);

  // ── Flight agent: thinking + LLM ──────────────────────────────────────────────
  await streamThinking("flight-agent", [
    `recv  search-flights  JFK → NRT · 2026-05-01 · Business · 1 pax`,
    `inventory loaded — ${FLIGHTS.length} options`,
    ``,
    `  [F001] ANA  NH 175   $2,150  non-stop  14h 45m  dep 08:05`,
    `         on-time record 94% ✓  flagship carrier  seats avail: 4`,
    `         score  price 8.5  comfort 9.0  schedule 9.4  →  8.9`,
    ``,
    `  [F002] JAL  JL 061   $2,280  non-stop  14h 45m  dep 11:30`,
    `         ⚠ only 2 seats remaining — high availability risk`,
    `         score  price 7.8  comfort 9.0  schedule 8.0  →  8.0`,
    ``,
    `  [F003] United UA 837  $1,890  1-stop SFO  17h 40m  dep 14:50`,
    `         cheapest but +3h journey — reduces business day productivity ✗`,
    `         score  price 9.2  comfort 6.5  schedule 7.8  →  7.7`,
    ``,
    `ranked: F001 8.9 > F002 8.0 > F003 7.7`,
    `passing to LLM for natural-language reasoning...`,
  ]);
  const flightAnalysisRaw = await llm(
    "flight-agent",
    PROMPTS.flight,
    `Traveler profile: ${JSON.stringify(parsedIntent)}
Available flights: ${JSON.stringify(FLIGHTS)}
Pick the best option for this business traveler.`
  );

  // Score flights ourselves (matches thinking panel) — don't trust small model's recommendedId
  const FLIGHT_SCORES = { F001: 8.9, F002: 8.0, F003: 7.7 };
  const bestFlightId = Object.entries(FLIGHT_SCORES).sort((a,b) => b[1]-a[1])[0][0];
  let flightReasoning = `${FLIGHTS.find(f=>f.id===bestFlightId).airline} offers the best balance of price, on-time record, and non-stop service.`;
  if (flightAnalysisRaw) {
    try {
      const parsed = JSON.parse(flightAnalysisRaw.trim());
      if (parsed.reasoning) flightReasoning = parsed.reasoning;
    } catch {}
  }
  const flightAnalysis = { recommendedId: bestFlightId, reasoning: flightReasoning };

  const flightRespEnv = await buildEnvelope("ArohaResponse", flight.did, personal.did,
    { capability: "search-flights", result: { flights: FLIGHTS, recommendation: flightAnalysis } },
    sid, flight.privateKey);
  pushActivity("flight", "personal", "ArohaResponse",
    `Recommendation: ${flightAnalysis.recommendedId} — ${flightAnalysis.reasoning?.slice(0,60)}`, flightRespEnv);

  // ── Hotel agent: thinking + LLM ───────────────────────────────────────────────
  await streamThinking("hotel-agent", [
    `recv  search-hotels  Tokyo · 2026-05-01→07 · ★5 · business`,
    `inventory loaded — ${HOTELS.length} properties`,
    ``,
    `  [H001] Park Hyatt Tokyo    Shinjuku    $620/night  ★ 4.9`,
    `         Sky Lounge · Spa · Michelin restaurant`,
    `         CBD distance: 25 min  6-night total $3,720`,
    ``,
    `  [H002] Andaz Tokyo          Toranomon   $480/night  ★ 4.7  ← best value`,
    `         Rooftop Bar · Club Lounge · Fitness Center ✓`,
    `         CBD distance: walking  6-night total $2,880  ✓`,
    ``,
    `  [H003] The Peninsula Tokyo  Marunouchi  $720/night  ★ 4.9`,
    `         Rolls Royce fleet · Pool · ultra-luxury`,
    `         CBD distance: adjacent  6-night total $4,320`,
    ``,
    `business-suitability score:`,
    `  H002 9.1 > H001 8.2 > H003 8.0`,
    `passing to LLM for natural-language reasoning...`,
  ]);
  const hotelAnalysisRaw = await llm(
    "hotel-agent",
    PROMPTS.hotel,
    `Traveler profile: ${JSON.stringify(parsedIntent)}
Available hotels: ${JSON.stringify(HOTELS)}
Pick the best hotel for this business traveler.`
  );

  // Score hotels ourselves (matches thinking panel) — don't trust small model's recommendedId
  const HOTEL_SCORES = { H001: 8.2, H002: 9.1, H003: 8.0 };
  const bestHotelId = Object.entries(HOTEL_SCORES).sort((a,b) => b[1]-a[1])[0][0];
  let hotelReasoning = `${HOTELS.find(h=>h.id===bestHotelId).name} offers the best value and location for a business traveler.`;
  if (hotelAnalysisRaw) {
    try {
      const parsed = JSON.parse(hotelAnalysisRaw.trim());
      if (parsed.reasoning) hotelReasoning = parsed.reasoning;
    } catch {}
  }
  const hotelAnalysis = { recommendedId: bestHotelId, reasoning: hotelReasoning };

  const hotelRespEnv = await buildEnvelope("ArohaResponse", hotel.did, personal.did,
    { capability: "search-hotels", result: { hotels: HOTELS, recommendation: hotelAnalysis } },
    sid, hotel.privateKey);
  pushActivity("hotel", "personal", "ArohaResponse",
    `Recommendation: ${hotelAnalysis.recommendedId} — ${hotelAnalysis.reasoning?.slice(0,60)}`, hotelRespEnv);

  // ── Personal agent presents flights via Claude ────────────────────────────────
  session.state = "selecting_flight";
  broadcast("state", { state: "selecting_flight" });

  const recFlight = FLIGHTS.find(f => f.id === flightAnalysis.recommendedId) ?? FLIGHTS[0];
  const flightPresentText = `The flight agent is recommending **${recFlight.airline} ${recFlight.no}** at $${recFlight.price.toLocaleString()} — ${(flightAnalysis.reasoning ?? '').split('.')[0]}. Choose the option that works best for you:`;

  pushChat("agent", flightPresentText, { agent: "personal", card: "flights", flights: FLIGHTS, recommended: flightAnalysis.recommendedId });
  pushNotification("Flights Found", `3 Business class options · Recommended: ${recFlight.airline}`, "✈️");

  session.flight = await waitForHuman("flight");
  pushChat("user", `${session.flight.airline} ${session.flight.no} — $${session.flight.price.toLocaleString()}`);

  // ── Personal agent presents hotels ───────────────────────────────────────────
  session.state = "selecting_hotel";
  broadcast("state", { state: "selecting_hotel" });

  const recHotel = HOTELS.find(h => h.id === hotelAnalysis.recommendedId) ?? HOTELS[0];
  const hotelPresentText = `Great — flight locked in. The hotel agent is recommending **${recHotel.name}** at $${recHotel.price}/night — ${(hotelAnalysis.reasoning ?? '').split('.')[0]}. Pick your hotel:`;

  pushChat("agent", hotelPresentText, { agent: "personal", card: "hotels", hotels: HOTELS, recommended: hotelAnalysis.recommendedId });
  pushNotification("Hotels Found", `3 Tokyo 5-star options · Recommended: ${recHotel.name}`, "🏨");

  session.hotel = await waitForHuman("hotel");
  session.hotel.total = session.hotel.price * 6;
  pushChat("user", `${session.hotel.name} — $${session.hotel.total.toLocaleString()} for 6 nights`);

  // ── Payment confirmation ──────────────────────────────────────────────────────
  session.state = "confirming_payment";
  broadcast("state", { state: "confirming_payment" });
  const grandTotal = session.flight.price + session.hotel.total;

  const payPresentText = `Ready to commit \u2014 **$${grandTotal.toLocaleString()}** total for **${session.flight.airline} ${session.flight.no}** + **${session.hotel.name}** (6 nights). This is a 3-way atomic saga: all three agents commit simultaneously or none do \u2014 nothing is charged until everything confirms.`;

  pushChat("agent", payPresentText, { agent: "personal", card: "payment", flight: session.flight, hotel: session.hotel, total: grandTotal, card_info: CARD });
  pushNotification("Ready to Book", `$${grandTotal.toLocaleString()} · Tap to confirm`, "💳");

  await waitForHuman("payment");
  pushChat("user", "Confirmed — charge the card");

  // ── Saga Reserve ─────────────────────────────────────────────────────────────
  session.state = "running";
  broadcast("state", { state: "running" });
  pushChat("agent", "Running the 3-way saga — reserving seats, room, and hold on payment simultaneously…", { agent: "personal" });

  const [fRes, hRes, pRes] = await Promise.all([
    buildEnvelope("ArohaReserve", personal.did, flight.did,
      { capability: "book-flight", params: { flightId: session.flight.id }, holdDurationMs: 120000 }, sid, personal.privateKey),
    buildEnvelope("ArohaReserve", personal.did, hotel.did,
      { capability: "book-hotel", params: { hotelId: session.hotel.id, checkIn: "2026-05-01", checkOut: "2026-05-07" }, holdDurationMs: 120000 }, sid, personal.privateKey),
    buildEnvelope("ArohaReserve", personal.did, payment.did,
      { capability: "hold-payment", params: { amount: grandTotal, currency: "USD", cardToken: "tok_visa_4242" }, holdDurationMs: 120000 }, sid, personal.privateKey),
  ]);
  pushActivity("personal", "flight",   "ArohaReserve", `Hold ${session.flight.no} · saga:${sid.slice(0,8)}`, fRes);
  pushActivity("personal", "hotel",    "ArohaReserve", `Hold ${session.hotel.name} May 1–7`, hRes);
  pushActivity("personal", "payment",  "ArohaReserve", `Hold $${grandTotal.toLocaleString()} · Visa ···· 4242`, pRes);
  await chainEscrowOpen(sid, grandTotal);
  pushActivity("chain", "escrow", "⛓ ArohaEscrow.sol", `lockFunds(saga:${sid.slice(0,8)}, $${grandTotal.toLocaleString()}) → funds held · 3-party saga open`);
  await sleep(1100);

  const tok = {
    f: `FLT-${randomUUID().slice(0,8).toUpperCase()}`,
    h: `HTL-${randomUUID().slice(0,8).toUpperCase()}`,
    p: `PAY-${randomUUID().slice(0,8).toUpperCase()}`,
  };

  const [fAck, hAck, pAck] = await Promise.all([
    buildEnvelope("ArohaReserveAck", flight.did,   personal.did, { reservationToken: tok.f, expiresAt: new Date(Date.now()+120000).toISOString() }, sid, flight.privateKey),
    buildEnvelope("ArohaReserveAck", hotel.did,    personal.did, { reservationToken: tok.h, expiresAt: new Date(Date.now()+120000).toISOString() }, sid, hotel.privateKey),
    buildEnvelope("ArohaReserveAck", payment.did,  personal.did, { reservationToken: tok.p, expiresAt: new Date(Date.now()+120000).toISOString() }, sid, payment.privateKey),
  ]);
  pushActivity("flight",  "personal", "ArohaReserveAck", `Token ${tok.f} — seat held 120s`, fAck);
  pushActivity("hotel",   "personal", "ArohaReserveAck", `Token ${tok.h} — room held 120s`, hAck);
  pushActivity("payment", "personal", "ArohaReserveAck", `Token ${tok.p} — funds held 120s`, pAck);

  // ── Payment agent: thinking before commit ────────────────────────────────────
  await streamThinking("payment-agent", [
    `validating 3-party atomic commit  saga:${sid.slice(0,8)}`,
    ``,
    `reserve tokens received:`,
    `  ${tok.f}   (flight-agent)   ✓`,
    `  ${tok.h}   (hotel-agent)    ✓`,
    `  ${tok.p}   (payment-agent)  ✓`,
    ``,
    `transaction breakdown:`,
    `  flight   $${session.flight.price.toLocaleString()}   ${session.flight.airline} ${session.flight.no}`,
    `  hotel    $${session.hotel.total.toLocaleString()}   ${session.hotel.name} × 6 nights`,
    `  ─────────────────────────────────────`,
    `  total    $${(session.flight.price + session.hotel.total).toLocaleString()}`,
    ``,
    `card: Visa Infinite ···· 4242`,
    `  expiry 04/28 ✓   cardholder: Alex Chen ✓`,
    `  fraud score: 0.02 / 1.00 ✓   risk level: LOW`,
    ``,
    `all 3 parties signalled ready`,
    `broadcasting ArohaCommit to flight · hotel · payment...`,
  ]);

  // ── Saga Commit ──────────────────────────────────────────────────────────────
  await sleep(400);
  const [fCom, hCom, pCom] = await Promise.all([
    buildEnvelope("ArohaCommit", personal.did, flight.did,  { reservationToken: tok.f }, sid, personal.privateKey),
    buildEnvelope("ArohaCommit", personal.did, hotel.did,   { reservationToken: tok.h }, sid, personal.privateKey),
    buildEnvelope("ArohaCommit", personal.did, payment.did, { reservationToken: tok.p }, sid, personal.privateKey),
  ]);
  pushActivity("personal", "flight",  "ArohaCommit", tok.f, fCom);
  pushActivity("personal", "hotel",   "ArohaCommit", tok.h, hCom);
  pushActivity("personal", "payment", "ArohaCommit", tok.p, pCom);
  await sleep(800);

  const pnr    = "Aroha" + randomUUID().slice(0,6).toUpperCase();
  const confNo = "TKY"  + randomUUID().slice(0,6).toUpperCase();
  const chgId  = "ch_"  + randomUUID().slice(0,16);
  session.bookingRef = { pnr, confNo, chgId, total: grandTotal };

  const [fComAck, hComAck, pComAck] = await Promise.all([
    buildEnvelope("ArohaCommitAck", flight.did,  personal.did, { reservationToken: tok.f, result: { pnr, seat: "5A", gate: "B22" } }, sid, flight.privateKey),
    buildEnvelope("ArohaCommitAck", hotel.did,   personal.did, { reservationToken: tok.h, result: { confNo, room: "Park Suite 52F" } }, sid, hotel.privateKey),
    buildEnvelope("ArohaCommitAck", payment.did, personal.did, { reservationToken: tok.p, result: { chargeId: chgId, amount: grandTotal } }, sid, payment.privateKey),
  ]);
  pushActivity("flight",  "personal", "ArohaCommitAck", `PNR: ${pnr} · Seat 5A · Gate B22`, fComAck);
  pushActivity("hotel",   "personal", "ArohaCommitAck", `Conf# ${confNo} · Park Suite 52F`, hComAck);
  await chainEscrowRelease(sid);

  // ── Payment agent: Claude writes confirmation ────────────────────────────────
  const payConfText = await llm(
    "payment-agent",
    PROMPTS.payment,
    `Transaction details: $${grandTotal.toLocaleString()} charged to Visa ···· 4242. Charge ID: ${chgId}. Part of saga ${sid.slice(0,8)} which fully committed all three parties.`
  ) ?? `$${grandTotal.toLocaleString()} successfully charged to Visa ···· 4242. Atomic saga fully committed — all three agents confirmed.`;

  pushActivity("payment", "personal", "ArohaCommitAck", payConfText.slice(0,80), pComAck);

  // ── Calendar + email ─────────────────────────────────────────────────────────
  const calDesc = `Flight: ${session.flight.airline} ${session.flight.no} — PNR: ${pnr}\nHotel: ${session.hotel.name} — Conf: ${confNo}\nBooked via Aroha Personal Agent`;
  session.icsData = makeICS("Tokyo Business Trip", "Tokyo, Japan", "2026-05-01T08:00:00Z", "2026-05-07T23:59:00Z", calDesc);
  const calUrl    = googleCalendarUrl("Tokyo Business Trip", "Tokyo, Japan", "2026-05-01T08:00:00Z", "2026-05-07T23:59:00Z", calDesc);

  const emailTarget = session.userEmail || GMAIL_USER;
  let emailResult = { sent: false };
  if (emailTarget) {
    const html = bookingEmailHtml(session.flight, session.hotel, grandTotal, pnr, confNo, chgId, calUrl);
    pushActivity("personal", "gmail", "Email", `Sending confirmation to ${emailTarget}`);
    emailResult = await sendEmail(emailTarget, `✈️ Tokyo Confirmed — ${session.flight.airline} ${session.flight.no} + ${session.hotel.name}`, html);
    pushActivity("gmail", "personal", "Email", emailResult.sent ? `Delivered to ${emailTarget} ✓` : `Preview only (Gmail not configured)`);
  }

  // ── Personal agent: Claude writes closing message ────────────────────────────
  session.state = "done";
  broadcast("state", { state: "done" });

  const doneText = await llmStream(
    "personal-agent",
    PROMPTS.personal,
    `The Tokyo trip is fully booked. Here's what committed atomically:
- Flight: ${session.flight.airline} ${session.flight.no}, PNR ${pnr}, Seat 5A
- Hotel: ${session.hotel.name}, Conf# ${confNo}, 6 nights
- Payment: $${grandTotal.toLocaleString()} charged to Visa ···· 4242
- ${emailResult.sent ? `Confirmation email sent to ${emailTarget}` : 'Calendar file ready to download'}

Write a warm 2-sentence closing confirming everything is done and the user is all set.`
  ) ?? `Everything's confirmed — **${session.flight.airline} ${session.flight.no}** (PNR: ${pnr}) and **${session.hotel.name}** (Conf: ${confNo}) are locked in and $${grandTotal.toLocaleString()} has been charged. You're all set for Tokyo!`;

  pushChat("agent", doneText, {
    agent: "personal",
    card: "booking_complete",
    pnr, confNo, chgId,
    flight: session.flight,
    hotel: session.hotel,
    total: grandTotal,
    calUrl,
    emailSent: emailResult.sent,
    emailTarget,
  });

  pushNotification("Booking Confirmed! ✈️", `${session.flight.airline} ${session.flight.no} + ${session.hotel.name} — $${grandTotal.toLocaleString()}`, "🎉");
  if (emailResult.sent) pushNotification("Email Sent 📧", `Confirmation delivered to ${emailTarget}`, "📧");
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
    return res.end();
  }

  if (url.pathname === "/api/stream") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive" });
    res.write(": ok\n\n");
    res.write(`data: ${JSON.stringify({ type: "init", messages: session.messages, activity: session.activityLog, notifications: session.notifications, state: session.state, llmEnabled: LLM_BACKEND !== "none" && vllmReady, llmBackend: LLM_BACKEND, llmModel: LLM_BACKEND === "vllm" ? VLLM_MODEL : "claude-sonnet-4-6", vllmReady, gmail: !!GMAIL_USER })}\n\n`);
    sseClients.push(res);
    req.on("close", () => { sseClients = sseClients.filter(c => c !== res); });
    return;
  }

  if (url.pathname === "/api/message" && req.method === "POST") {
    collectBody(req, async raw => {
      const { text, email } = JSON.parse(raw);
      res.writeHead(200, json()); res.end(JSON.stringify({ ok: true }));

      if (session.state !== "idle" && session.state !== "done") return;
      if (session.state === "done") { session = newSession(); broadcast("reset", {}); }

      if (email) session.userEmail = email;
      pushChat("user", text);

      // Check vllm readiness
      if (LLM_BACKEND === "vllm" && !vllmReady) {
        pushChat("agent", "⏳ The vllm model is still loading — please wait a moment and try again.", { agent: "personal" });
        session.state = "idle"; broadcast("state", { state: "idle" });
        return;
      }

      // Parse intent via LLM
      let parsedIntent = { type: "chitchat", raw: text };
      if (LLM_BACKEND !== "none") {
        const intentRaw = await llm(
          "personal-agent",
          `You are an intent parser for a travel booking agent. Extract intent from user messages.
Return JSON: { "type": "booking"|"cancel"|"status"|"help"|"chitchat", "destination": "...", "dates": "...", "travelers": 1, "class": "Business"|"Economy", "budget": null }
For non-booking messages return { "type": "chitchat" }. Raw JSON only, no markdown.`,
          text, 200
        );
        if (intentRaw) { try { parsedIntent = JSON.parse(intentRaw.trim()); } catch {} }
      } else {
        // Rule-based fallback
        const t = text.toLowerCase();
        if (/book|trip|fly|flight|tokyo|hotel|travel|japan/.test(t)) parsedIntent = { type: "booking", destination: "Tokyo" };
        else if (/help|what can/.test(t)) parsedIntent = { type: "help" };
      }

      if (parsedIntent.type === "booking") {
        // Personal agent acknowledges via streaming
        await llmStream(
          "personal-agent",
          PROMPTS.personal,
          `User said: "${text}". Parsed intent: ${JSON.stringify(parsedIntent)}.
Acknowledge you're on it and searching now. One sentence. Mention you're querying flight and hotel agents in parallel.`
        ).then(ack => {
          if (!ack) pushChat("agent", "On it — querying flight and hotel agents in parallel now…", { agent: "personal" });
        });
        runBooking(parsedIntent).catch(e => {
          console.error("[Booking error]", e);
          pushChat("agent", "Something went wrong during booking. Please try again.", { agent: "personal" });
          session.state = "idle"; broadcast("state", { state: "idle" });
        });
        return;
      }

      // Non-booking: Personal agent responds via LLM
      const reply = await llmStream(
        "personal-agent",
        PROMPTS.personal,
        session.conversationHistory.length > 2
          ? `Conversation so far:\n${session.conversationHistory.slice(-6).map(m => `${m.role}: ${m.content}`).join("\n")}\n\nUser just said: "${text}"`
          : `User said: "${text}". If they haven't mentioned travel, invite them to ask you to book a trip.`
      );
      if (!reply) pushChat("agent", "I can help you book travel — try: *\"Book me a business trip to Tokyo May 1–7\"*", { agent: "personal" });
    });
    return;
  }

  if (url.pathname === "/api/select/flight" && req.method === "POST") {
    collectBody(req, raw => {
      const { flightId } = JSON.parse(raw);
      const f = FLIGHTS.find(x => x.id === flightId);
      if (f && session.humanResolvers["flight"]) {
        session.humanResolvers["flight"](f); delete session.humanResolvers["flight"];
        res.writeHead(200, json()); res.end(JSON.stringify({ ok: true }));
      } else { res.writeHead(400, json()); res.end(JSON.stringify({ error: "not waiting" })); }
    }); return;
  }

  if (url.pathname === "/api/select/hotel" && req.method === "POST") {
    collectBody(req, raw => {
      const { hotelId } = JSON.parse(raw);
      const h = HOTELS.find(x => x.id === hotelId);
      if (h && session.humanResolvers["hotel"]) {
        session.humanResolvers["hotel"](h); delete session.humanResolvers["hotel"];
        res.writeHead(200, json()); res.end(JSON.stringify({ ok: true }));
      } else { res.writeHead(400, json()); res.end(JSON.stringify({ error: "not waiting" })); }
    }); return;
  }

  if (url.pathname === "/api/confirm/payment" && req.method === "POST") {
    if (session.humanResolvers["payment"]) {
      session.humanResolvers["payment"](true); delete session.humanResolvers["payment"];
      res.writeHead(200, json()); res.end(JSON.stringify({ ok: true }));
    } else { res.writeHead(400, json()); res.end(JSON.stringify({ error: "not waiting" })); }
    return;
  }

  if (url.pathname === "/api/calendar.ics") {
    if (session.icsData) {
      res.writeHead(200, { "Content-Type": "text/calendar", "Content-Disposition": "attachment; filename=\"tokyo-trip.ics\"" });
      res.end(session.icsData);
    } else { res.writeHead(404); res.end("No booking"); }
    return;
  }

  if (url.pathname === "/api/email-preview") {
    if (session.bookingRef) {
      const calUrl = googleCalendarUrl("Tokyo Business Trip", "Tokyo, Japan", "2026-05-01T08:00:00Z", "2026-05-07T23:59:00Z", "");
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(bookingEmailHtml(session.flight, session.hotel, session.bookingRef.total, session.bookingRef.pnr, session.bookingRef.confNo, session.bookingRef.chgId, calUrl));
    } else { res.writeHead(404); res.end("<p>No booking yet.</p>"); }
    return;
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache" });
    res.end(HTML);
    return;
  }

  res.writeHead(404); res.end("Not found");
});

server.listen(PORT, () => console.log(`\n[Chat] Ready → http://localhost:${PORT}\n`));

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function streamThinking(agentName, lines, delayMs = 85) {
  broadcast("agent_thinking_start", { agent: agentName });
  for (const line of lines) {
    await sleep(delayMs);
    broadcast("agent_thinking_line", { agent: agentName, line });
  }
  broadcast("agent_thinking_done", { agent: agentName });
}
function json() { return { "Content-Type": "application/json" }; }
function collectBody(req, cb) {
  let d = "";
  req.on("data", c => d += c);
  req.on("end", () => {
    const result = cb(d);
    if (result && typeof result.catch === "function") {
      result.catch(err => console.error("[collectBody] unhandled error:", err));
    }
  });
}

// ─── HTML (unchanged UI, + streaming support) ─────────────────────────────────

const HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aroha Personal Agent</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Barlow:wght@400;500;600;700&family=Barlow+Condensed:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #020817;
    --surface: #080d1a;
    --surface2: #0c1424;
    --surface3: #111c30;
    --border: #1a2840;
    --border2: #243550;
    --accent: #06b6d4;
    --accent2: #8b5cf6;
    --green: #10b981;
    --yellow: #f59e0b;
    --red: #ef4444;
    --text: #e2e8f0;
    --muted: #5a7a9a;
    --dim: #2d4060;
    --personal: #06b6d4;
    --flight: #8b5cf6;
    --hotel: #10b981;
    --payment: #f59e0b;
    --llm: #ec4899;
    --aroha: #06b6d4;
    --font-display: 'Orbitron', monospace;
    --font-body: 'Barlow', system-ui, sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
    --font-data: 'Barlow Condensed', system-ui, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background-color: var(--bg);
    background-image:
      radial-gradient(ellipse 90% 40% at 50% 0%, rgba(6,182,212,0.05) 0%, transparent 65%),
      radial-gradient(ellipse 60% 30% at 85% 90%, rgba(139,92,246,0.04) 0%, transparent 60%),
      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='28'%3E%3Ccircle cx='1' cy='1' r='0.6' fill='%231a2840'/%3E%3C/svg%3E");
    background-attachment: fixed;
    color: var(--text);
    font-family: var(--font-body);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  /* ── Header ────────────────────────────────── */
  .header {
    background: rgba(8,13,26,0.97);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    height: 58px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex-shrink: 0;
    position: relative;
    backdrop-filter: blur(20px);
  }
  .header::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent 0%, var(--aroha) 35%, rgba(139,92,246,0.7) 65%, transparent 100%);
    opacity: 0.5;
  }

  .logo {
    font-family: var(--font-display);
    font-size: 15px;
    font-weight: 900;
    letter-spacing: 0.12em;
    color: var(--text);
    display: flex;
    align-items: center;
  }
  .logo span { color: var(--aroha); text-shadow: 0 0 16px rgba(6,182,212,0.7); }

  .logo-tag {
    font-family: var(--font-data);
    font-size: 9px;
    font-weight: 700;
    background: rgba(6,182,212,0.08);
    border: 1px solid rgba(6,182,212,0.2);
    color: var(--aroha);
    padding: 2px 7px;
    border-radius: 2px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
  }

  .agent-name {
    font-family: var(--font-data);
    font-size: 13px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: 0.04em;
  }
  .agent-did {
    font-family: var(--font-mono);
    font-size: 9px;
    color: var(--dim);
    margin-top: 2px;
  }

  .agent-status {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-data);
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.04em;
  }
  .status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 8px rgba(16,185,129,0.6);
    flex-shrink: 0;
  }
  .status-dot.busy {
    background: var(--yellow);
    box-shadow: 0 0 8px rgba(245,158,11,0.6);
    animation: pulse 1.2s infinite;
  }

  .llm-badge {
    background: rgba(236,72,153,0.08);
    border: 1px solid rgba(236,72,153,0.22);
    color: var(--llm);
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 2px;
    display: flex;
    align-items: center;
    gap: 6px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .llm-badge.off { background: rgba(26,40,64,0.4); border-color: var(--border); color: var(--dim); }
  .llm-dot {
    width: 5px; height: 5px;
    border-radius: 50%;
    background: var(--llm);
    box-shadow: 0 0 6px rgba(236,72,153,0.6);
    animation: pulse 1.4s infinite;
  }
  .llm-badge.off .llm-dot { background: var(--dim); animation: none; box-shadow: none; }

  .header-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
  .proto-btn {
    background: rgba(6,182,212,0.08);
    border: 1px solid rgba(6,182,212,0.25);
    color: var(--aroha);
    padding: 5px 12px;
    border-radius: 2px;
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.18s;
    display: flex; align-items: center; gap: 6px;
  }
  .proto-btn:hover { background: rgba(6,182,212,0.15); box-shadow: 0 0 16px rgba(6,182,212,0.15); }
  .proto-btn-dot { width: 5px; height: 5px; border-radius: 50%; background: var(--aroha); box-shadow: 0 0 6px var(--aroha); animation: pulse 2s infinite; }

  .sidebar-btn {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 5px 12px;
    border-radius: 2px;
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.18s;
  }
  .sidebar-btn:hover, .sidebar-btn.active {
    border-color: var(--aroha);
    color: var(--aroha);
    background: rgba(6,182,212,0.06);
  }

  .notif-btn {
    position: relative;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--muted);
    padding: 6px;
    border-radius: 6px;
    font-size: 17px;
    transition: all 0.18s;
  }
  .notif-btn:hover { color: var(--text); background: var(--surface3); }
  .notif-badge {
    position: absolute; top: 2px; right: 2px;
    min-width: 15px; height: 15px;
    background: var(--red);
    border-radius: 8px;
    font-family: var(--font-mono);
    font-size: 9px;
    font-weight: 700;
    color: white;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 0 3px;
  }
  .notif-badge.show { display: flex; }

  /* ── Layout ────────────────────────────────── */
  .body { display: flex; flex: 1; overflow: hidden; }
  .chat-col { display: flex; flex-direction: column; flex: 1; min-width: 0; }
  .messages { flex: 1; overflow-y: auto; padding: 24px 20px; display: flex; flex-direction: column; gap: 0; }

  /* ── Messages ──────────────────────────────── */
  .msg-wrap { display: flex; flex-direction: column; margin-bottom: 4px; }
  .msg-wrap.user { align-items: flex-end; }
  .msg-wrap.agent { align-items: flex-start; }
  .msg-wrap + .msg-wrap { margin-top: 14px; }

  .msg-hdr { display: flex; align-items: center; gap: 7px; margin-bottom: 5px; padding: 0 2px; }
  .msg-wrap.user .msg-hdr { flex-direction: row-reverse; }

  .avatar {
    width: 26px; height: 26px;
    border-radius: 5px;
    background: linear-gradient(135deg, var(--aroha), var(--accent2));
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    color: #020817;
    flex-shrink: 0;
    box-shadow: 0 0 12px rgba(6,182,212,0.25);
  }
  .msg-sender {
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    color: var(--muted);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .msg-time { font-family: var(--font-mono); font-size: 9px; color: var(--dim); }

  .bubble {
    max-width: 560px;
    padding: 12px 16px;
    border-radius: 8px;
    font-size: 14px;
    line-height: 1.65;
    font-weight: 400;
  }
  .msg-wrap.user .bubble {
    background: linear-gradient(135deg, #0d3d55, #092e42);
    border: 1px solid rgba(6,182,212,0.25);
    color: #d4eef7;
    border-bottom-right-radius: 2px;
  }
  .msg-wrap.agent .bubble {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 2px solid var(--aroha);
    color: var(--text);
    border-bottom-left-radius: 2px;
  }
  .bubble strong { font-weight: 700; color: var(--aroha); }
  .bubble em { opacity: 0.75; }

  .streaming-cursor::after { content: '▋'; animation: blink 0.8s infinite; color: var(--aroha); }
  @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }

  .typing-wrap { display: flex; align-items: flex-start; gap: 8px; margin-bottom: 8px; }
  .typing-dots {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 2px solid var(--aroha);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex; gap: 5px;
  }
  .typing-dots span {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--aroha);
    opacity: 0.35;
    animation: bounce 1.2s infinite;
  }
  .typing-dots span:nth-child(2) { animation-delay: .2s; }
  .typing-dots span:nth-child(3) { animation-delay: .4s; }

  @keyframes bounce { 0%,60%,100% { transform: translateY(0); opacity: 0.35; } 30% { transform: translateY(-7px); opacity: 1; } }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.25; } }

  /* ── Cards shared ──────────────────────────── */
  .card-wrap { max-width: 580px; margin-top: 8px; }
  .card-label {
    font-family: var(--font-data);
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--muted);
    margin-bottom: 10px;
    padding: 0 2px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .card-label::after { content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border), transparent); }

  /* ── Flight cards ──────────────────────────── */
  .flight-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--flight);
    border-radius: 7px;
    padding: 14px 16px;
    cursor: pointer;
    margin-bottom: 8px;
    transition: transform 0.15s, border-color 0.15s, background 0.15s, box-shadow 0.15s;
    display: flex;
    align-items: center;
    gap: 14px;
    position: relative;
  }
  .flight-card:hover {
    border-color: var(--flight);
    background: rgba(139,92,246,0.07);
    transform: translateX(3px);
    box-shadow: -3px 0 0 var(--flight), 0 4px 20px rgba(139,92,246,0.1);
  }
  .flight-card.picked { border-color: var(--flight); background: rgba(139,92,246,0.12); pointer-events: none; }
  .flight-card.recommended { box-shadow: 0 0 0 1px rgba(139,92,246,0.3), 0 6px 24px rgba(139,92,246,0.1); }

  .rec-tag {
    position: absolute; top: -9px; left: 14px;
    background: var(--flight);
    color: white;
    font-family: var(--font-data);
    font-size: 8px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 2px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .airline-tag {
    background: var(--surface3);
    border: 1px solid var(--border2);
    border-radius: 4px;
    padding: 4px 10px;
    font-family: var(--font-data);
    font-weight: 700;
    font-size: 12px;
    flex-shrink: 0;
    color: var(--text);
    letter-spacing: 0.06em;
  }
  .f-times { font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--text); flex: 1; }
  .f-meta { font-family: var(--font-data); font-size: 11px; color: var(--muted); margin-top: 4px; letter-spacing: 0.03em; }
  .f-price { font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--flight); flex-shrink: 0; }

  /* ── Hotel cards ───────────────────────────── */
  .hotel-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--hotel);
    border-radius: 7px;
    padding: 14px 16px;
    cursor: pointer;
    margin-bottom: 8px;
    transition: transform 0.15s, border-color 0.15s, background 0.15s, box-shadow 0.15s;
    position: relative;
  }
  .hotel-card:hover {
    border-color: var(--hotel);
    background: rgba(16,185,129,0.06);
    transform: translateX(3px);
    box-shadow: -3px 0 0 var(--hotel), 0 4px 20px rgba(16,185,129,0.08);
  }
  .hotel-card.picked { border-color: var(--hotel); background: rgba(16,185,129,0.12); pointer-events: none; }
  .hotel-card.recommended { box-shadow: 0 0 0 1px rgba(16,185,129,0.3), 0 6px 24px rgba(16,185,129,0.08); }

  .rec-tag-h {
    position: absolute; top: -9px; left: 14px;
    background: var(--hotel);
    color: white;
    font-family: var(--font-data);
    font-size: 8px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 2px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .h-name { font-family: var(--font-body); font-size: 15px; font-weight: 700; color: var(--text); }
  .h-area { font-family: var(--font-data); font-size: 11px; color: var(--muted); margin-top: 4px; letter-spacing: 0.04em; }
  .h-row { display: flex; align-items: center; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
  .amenity {
    font-family: var(--font-data);
    font-size: 9px;
    font-weight: 700;
    background: var(--surface3);
    border: 1px solid var(--border);
    border-radius: 2px;
    padding: 2px 8px;
    color: var(--muted);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }
  .h-price { margin-left: auto; font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--hotel); white-space: nowrap; }

  /* ── Payment card ──────────────────────────── */
  .pay-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
  }
  .pay-line { display: flex; justify-content: space-between; font-family: var(--font-body); font-size: 14px; padding: 6px 0; color: var(--text); }
  .pay-line.total {
    border-top: 1px solid var(--border2);
    margin-top: 8px;
    padding-top: 14px;
    font-weight: 700;
    font-size: 16px;
  }
  .pay-line.total .amount { font-family: var(--font-mono); color: var(--aroha); }

  .cc-strip {
    background: linear-gradient(135deg, #09172e, #0d1f3a);
    border: 1px solid var(--border2);
    border-radius: 10px;
    padding: 18px;
    margin: 16px 0;
    position: relative;
    overflow: hidden;
  }
  .cc-strip::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: radial-gradient(ellipse 80% 60% at 0% 0%, rgba(6,182,212,0.06), transparent);
    pointer-events: none;
  }
  .cc-chip {
    width: 34px; height: 26px;
    background: linear-gradient(135deg, #c9a227, #e8c547);
    border-radius: 5px;
    margin-bottom: 18px;
  }
  .cc-num { font-family: var(--font-mono); font-size: 15px; letter-spacing: 4px; margin-bottom: 14px; color: rgba(255,255,255,0.88); }
  .cc-row { display: flex; justify-content: space-between; font-family: var(--font-data); font-size: 9px; color: rgba(255,255,255,0.35); letter-spacing: 0.1em; text-transform: uppercase; }
  .cc-val { font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: white; margin-top: 3px; letter-spacing: 0.04em; }

  .btn-pay {
    width: 100%;
    background: linear-gradient(135deg, #0891b2, #06b6d4);
    color: #020817;
    border: none;
    padding: 14px;
    border-radius: 6px;
    font-family: var(--font-data);
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    cursor: pointer;
    margin-top: 4px;
    transition: all 0.18s;
    box-shadow: 0 4px 20px rgba(6,182,212,0.2);
  }
  .btn-pay:hover { box-shadow: 0 6px 28px rgba(6,182,212,0.4); transform: translateY(-1px); }
  .btn-pay:disabled { background: var(--surface3); color: var(--dim); cursor: not-allowed; box-shadow: none; transform: none; }

  /* ── Booking complete card ─────────────────── */
  .complete-card {
    background: var(--surface2);
    border: 1px solid rgba(16,185,129,0.25);
    border-left: 3px solid var(--green);
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 24px rgba(16,185,129,0.07);
  }
  .complete-header {
    font-family: var(--font-data);
    color: var(--green);
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 16px;
  }
  .ref-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
    padding: 7px 0;
    border-bottom: 1px solid var(--border);
  }
  .ref-row:last-of-type { border: none; }
  .ref-key { font-family: var(--font-data); color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
  .ref-val { font-family: var(--font-mono); font-weight: 500; font-size: 12px; color: var(--text); }

  .action-row { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
  .action-btn {
    flex: 1;
    min-width: 120px;
    padding: 9px 14px;
    border-radius: 4px;
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    cursor: pointer;
    border: 1px solid var(--border2);
    background: var(--surface3);
    color: var(--muted);
    text-align: center;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 5px;
    transition: all 0.18s;
  }
  .action-btn:hover { border-color: var(--aroha); color: var(--aroha); background: rgba(6,182,212,0.06); }
  .action-btn.primary { background: var(--aroha); border-color: var(--aroha); color: #020817; }
  .action-btn.primary:hover { box-shadow: 0 4px 20px rgba(6,182,212,0.3); }

  /* ── Input area ────────────────────────────── */
  .input-area {
    border-top: 1px solid var(--border);
    padding: 14px 20px;
    background: rgba(8,13,26,0.97);
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .input-row { display: flex; gap: 10px; align-items: flex-end; }
  .input-box {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 11px 15px;
    color: var(--text);
    font-family: var(--font-body);
    font-size: 14px;
    resize: none;
    outline: none;
    max-height: 120px;
    transition: border-color 0.18s, box-shadow 0.18s;
    min-height: 44px;
  }
  .input-box:focus { border-color: var(--aroha); box-shadow: 0 0 0 2px rgba(6,182,212,0.1); }
  .input-box::placeholder { color: var(--dim); }

  .send-btn {
    background: var(--aroha);
    border: none;
    border-radius: 7px;
    width: 44px; height: 44px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    color: #020817;
    flex-shrink: 0;
    transition: all 0.18s;
    box-shadow: 0 2px 12px rgba(6,182,212,0.25);
  }
  .send-btn:hover { box-shadow: 0 4px 22px rgba(6,182,212,0.45); transform: translateY(-1px); }
  .send-btn:disabled { background: var(--surface3); color: var(--dim); cursor: not-allowed; box-shadow: none; transform: none; }

  .email-row { display: flex; gap: 10px; align-items: center; }
  .email-input {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 7px 12px;
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 11px;
    outline: none;
    transition: border-color 0.18s;
  }
  .email-input:focus { border-color: var(--aroha); }
  .email-label {
    font-family: var(--font-data);
    font-size: 10px;
    font-weight: 700;
    color: var(--muted);
    align-self: center;
    flex-shrink: 0;
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .suggestions { display: flex; gap: 7px; flex-wrap: wrap; padding: 0 20px 14px; }
  .sug {
    background: rgba(12,20,36,0.7);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 6px 14px;
    font-family: var(--font-data);
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    color: var(--muted);
    transition: all 0.18s;
    letter-spacing: 0.03em;
  }
  .sug:hover { border-color: var(--aroha); color: var(--aroha); background: rgba(6,182,212,0.06); }

  /* ── Sidebar ───────────────────────────────── */
  .sidebar {
    width: 300px;
    border-left: 1px solid var(--border);
    display: flex; flex-direction: column;
    background: rgba(8,13,26,0.97);
    flex-shrink: 0;
    overflow: hidden;
    transition: width 0.3s;
  }
  .sidebar.hidden { width: 0; }
  .sidebar-inner { width: 300px; display: flex; flex-direction: column; height: 100%; }

  .sidebar-title {
    font-family: var(--font-data);
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.14em;
    color: var(--muted);
    padding: 10px 14px 8px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    display: flex; align-items: center; gap: 8px;
  }
  .sidebar-agents { display: flex; flex-wrap: wrap; gap: 4px; padding: 8px 14px 10px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .agent-pill {
    font-family: var(--font-data);
    font-size: 9px;
    font-weight: 700;
    padding: 3px 8px 3px 6px;
    border-radius: 2px;
    letter-spacing: 0.05em;
    display: flex; align-items: center; gap: 5px;
    border: 1px solid transparent;
  }
  .agent-pill-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
  .agent-pill.personal { background: rgba(6,182,212,0.08); border-color: rgba(6,182,212,0.2); color: var(--aroha); }
  .agent-pill.personal .agent-pill-dot { background: var(--aroha); box-shadow: 0 0 5px var(--aroha); }
  .agent-pill.flight   { background: rgba(139,92,246,0.08); border-color: rgba(139,92,246,0.2); color: #a78bfa; }
  .agent-pill.flight   .agent-pill-dot { background: #a78bfa; box-shadow: 0 0 5px #a78bfa; }
  .agent-pill.hotel    { background: rgba(16,185,129,0.08); border-color: rgba(16,185,129,0.2); color: #34d399; }
  .agent-pill.hotel    .agent-pill-dot { background: #34d399; box-shadow: 0 0 5px #34d399; }
  .agent-pill.payment  { background: rgba(245,158,11,0.08); border-color: rgba(245,158,11,0.2); color: #fbbf24; }
  .agent-pill.payment  .agent-pill-dot { background: #fbbf24; box-shadow: 0 0 5px #fbbf24; }

  .saga-bar {
    display: flex; align-items: center; gap: 5px;
    padding: 8px 14px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    font-family: var(--font-data);
    font-size: 9px; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
  }
  .saga-step { padding: 3px 8px; border-radius: 2px; border: 1px solid var(--border); color: var(--dim); }
  .saga-step.active {
    border-color: var(--yellow); color: var(--yellow);
    background: rgba(245,158,11,0.08);
    box-shadow: 0 0 8px rgba(245,158,11,0.12);
  }
  .saga-step.done { border-color: var(--green); color: var(--green); background: rgba(16,185,129,0.08); }
  .saga-arrow { color: var(--dim); }

  .activity-list { flex: 1; overflow-y: auto; padding: 8px; display: flex; flex-direction: column; gap: 4px; }
  .act-empty {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 8px; padding: 32px 16px; color: var(--dim);
    font-family: var(--font-data); font-size: 10px; letter-spacing: 0.08em;
    text-align: center;
  }
  .act-empty-icon { font-size: 22px; opacity: 0.4; }
  .act-item {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 8px 10px;
    font-size: 11px;
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }
  .act-item:hover { border-color: var(--aroha); background: rgba(6,182,212,0.04); }
  .act-chain {
    border-left: 2px solid rgba(6,182,212,0.4) !important;
    background: rgba(6,182,212,0.03) !important;
  }
  .act-chain .act-layer { background: rgba(6,182,212,0.18); color: var(--aroha); font-size: 7px; }
  .act-chain .act-type { color: var(--aroha) !important; font-family: var(--font-mono); font-size: 9px; }
  .act-chain .act-body { color: var(--aroha); opacity: 0.7; font-family: var(--font-mono); font-size: 9px; }
  .act-hdr { display: flex; align-items: center; gap: 5px; margin-bottom: 3px; }
  .act-layer {
    font-family: var(--font-display);
    font-size: 7px; font-weight: 700;
    padding: 1px 5px;
    border-radius: 2px;
    background: rgba(6,182,212,0.1);
    color: var(--aroha);
    letter-spacing: 0.08em;
    flex-shrink: 0;
  }
  .act-type { font-family: var(--font-data); font-weight: 700; font-size: 10px; letter-spacing: 0.05em; }
  .act-type.ArohaRequest  { color: var(--aroha); }
  .act-type.ArohaResponse { color: var(--accent2); }
  .act-type.ArohaReserve  { color: var(--yellow); }
  .act-type.ArohaReserveAck { color: var(--green); }
  .act-type.ArohaCommit   { color: var(--green); }
  .act-type.ArohaCommitAck { color: var(--green); }
  .act-type.ArohaCancel   { color: var(--red); }
  .act-type.ArohaCancelAck { color: var(--red); }
  .act-type.LLM   { color: var(--llm); }
  .act-type.Email { color: #f97316; }
  .act-time  { font-family: var(--font-mono); color: var(--dim); margin-left: auto; font-size: 9px; }
  .act-route { font-family: var(--font-mono); color: var(--dim); font-size: 9px; }
  .act-body  { font-family: var(--font-body); color: var(--muted); line-height: 1.4; font-size: 10px; margin-top: 3px; }
  .rbac-tag {
    display: inline-block;
    font-family: var(--font-data);
    font-size: 8px; font-weight: 700;
    letter-spacing: 0.06em; text-transform: uppercase;
    padding: 1px 6px;
    border-radius: 2px;
    border: 1px solid rgba(139,92,246,0.22);
    color: #a78bfa;
    background: rgba(139,92,246,0.07);
    margin-top: 4px;
  }

  /* ── Notification panel ────────────────────── */
  .notif-panel {
    position: fixed; top: 60px; right: 16px;
    width: 310px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    z-index: 50;
    box-shadow: 0 16px 48px rgba(0,0,0,0.7);
    display: none;
    max-height: 440px; overflow-y: auto;
  }
  .notif-panel.open { display: block; }
  .notif-panel-title {
    padding: 12px 16px 9px;
    font-family: var(--font-data);
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
  }
  .notif-clear { font-family: var(--font-data); font-size: 9px; color: var(--aroha); cursor: pointer; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
  .notif-item { display: flex; gap: 10px; padding: 10px 16px; border-bottom: 1px solid var(--border); }
  .notif-item:last-child { border: none; }
  .notif-icon { font-size: 17px; flex-shrink: 0; }
  .notif-title-t { font-family: var(--font-data); font-size: 12px; font-weight: 700; letter-spacing: 0.03em; }
  .notif-body-t  { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .notif-time-t  { font-family: var(--font-mono); font-size: 9px; color: var(--dim); margin-top: 3px; }

  /* ── Toasts ────────────────────────────────── */
  .toast-container { position: fixed; top: 72px; right: 16px; display: flex; flex-direction: column; gap: 8px; z-index: 200; pointer-events: none; }
  .toast {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 2px solid var(--aroha);
    border-radius: 6px;
    padding: 10px 14px;
    display: flex; align-items: flex-start; gap: 10px;
    max-width: 300px;
    box-shadow: 0 6px 28px rgba(0,0,0,0.55);
    animation: slideIn 0.25s ease;
    pointer-events: all;
  }
  .toast.out { animation: slideOut 0.25s ease forwards; }
  .toast-icon  { font-size: 17px; flex-shrink: 0; }
  .toast-title { font-family: var(--font-data); font-size: 12px; font-weight: 700; letter-spacing: 0.04em; }
  .toast-body  { font-size: 11px; color: var(--muted); margin-top: 1px; }
  @keyframes slideIn { from { transform: translateX(110%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(110%); opacity: 0; } }

  /* ── Modals ────────────────────────────────── */
  .modal-overlay { position: fixed; inset: 0; background: rgba(2,8,23,0.82); backdrop-filter: blur(8px); z-index: 100; display: none; align-items: center; justify-content: center; }
  .modal-overlay.open { display: flex; }
  .modal-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    max-width: 600px; width: 96vw; max-height: 80vh;
    display: flex; flex-direction: column;
    box-shadow: 0 32px 96px rgba(0,0,0,0.8);
  }
  .modal-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
  .modal-title { font-family: var(--font-data); font-weight: 700; font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); }
  .modal-close { background: none; border: none; color: var(--muted); cursor: pointer; font-size: 18px; transition: color 0.15s; }
  .modal-close:hover { color: var(--text); }
  .modal-pre {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 16px;
    font-family: var(--font-mono);
    font-size: 11px;
    white-space: pre-wrap; word-break: break-all;
    color: #7dd3fc;
    overflow-y: auto;
    flex: 1;
    line-height: 1.65;
  }
  .email-modal-box { background: white; border-radius: 10px; max-width: 640px; width: 96vw; max-height: 85vh; overflow-y: auto; }

  /* ── Scrollbars ────────────────────────────── */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }

  /* ── Protocol modal ───────────────────────── */
  .proto-modal-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    max-width: 780px; width: 96vw; max-height: 88vh;
    display: flex; flex-direction: column;
    box-shadow: 0 32px 96px rgba(0,0,0,0.85);
    overflow: hidden;
  }
  .proto-modal-hdr {
    display: flex; justify-content: space-between; align-items: center;
    padding: 20px 24px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    background: linear-gradient(90deg, rgba(6,182,212,0.04) 0%, transparent 60%);
  }
  .proto-modal-title {
    font-family: var(--font-display);
    font-size: 13px; font-weight: 900;
    letter-spacing: 0.12em;
    color: var(--aroha);
    text-shadow: 0 0 24px rgba(6,182,212,0.4);
  }
  .proto-modal-sub {
    font-family: var(--font-data);
    font-size: 10px; font-weight: 600;
    color: var(--muted);
    letter-spacing: 0.08em;
    margin-top: 3px;
  }
  .proto-modal-body { overflow-y: auto; padding: 24px; display: flex; flex-direction: column; gap: 24px; }
  .proto-section-title {
    font-family: var(--font-data);
    font-size: 9px; font-weight: 700;
    letter-spacing: 0.16em; text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 12px;
    display: flex; align-items: center; gap: 10px;
  }
  .proto-section-title::after { content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border), transparent); }
  .proto-kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .proto-kv {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
  }
  .proto-kv-label { font-family: var(--font-data); font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); margin-bottom: 5px; }
  .proto-kv-val { font-family: var(--font-body); font-size: 13px; font-weight: 600; color: var(--text); line-height: 1.5; }
  .proto-kv-val small { font-size: 11px; color: var(--muted); display: block; margin-top: 3px; font-weight: 400; }
  .proto-flow {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 20px;
    font-family: var(--font-mono);
    font-size: 11px;
    overflow-x: auto;
  }
  .proto-flow-row { display: flex; align-items: center; gap: 0; margin-bottom: 4px; }
  .proto-node {
    display: flex; align-items: center; justify-content: center;
    padding: 5px 12px;
    border-radius: 3px;
    font-family: var(--font-data);
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.06em; white-space: nowrap;
    flex-shrink: 0;
  }
  .proto-arrow { color: var(--dim); padding: 0 6px; font-size: 13px; flex-shrink: 0; }
  .proto-label { font-family: var(--font-data); font-size: 9px; color: var(--muted); padding: 0 4px; }
  .proto-chain-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-left: 3px solid var(--aroha);
    border-radius: 6px;
    padding: 14px 16px;
    margin-bottom: 8px;
  }
  .proto-chain-name { font-family: var(--font-mono); font-size: 13px; font-weight: 700; color: var(--aroha); }
  .proto-chain-desc { font-family: var(--font-body); font-size: 12px; color: var(--muted); margin-top: 5px; line-height: 1.55; }
  .proto-chain-method {
    display: inline-flex; align-items: center; gap: 6px;
    margin-top: 8px; margin-right: 6px;
    background: rgba(6,182,212,0.06);
    border: 1px solid rgba(6,182,212,0.15);
    border-radius: 3px;
    padding: 3px 8px;
    font-family: var(--font-mono);
    font-size: 10px; color: var(--aroha);
  }
  .proto-when { font-family: var(--font-data); font-size: 9px; color: var(--dim); margin-left: 4px; }
  .proto-highlight-box {
    background: linear-gradient(135deg, rgba(6,182,212,0.05), rgba(139,92,246,0.05));
    border: 1px solid rgba(6,182,212,0.15);
    border-radius: 6px;
    padding: 16px 18px;
  }
  .proto-highlight-box p { font-family: var(--font-body); font-size: 13px; line-height: 1.7; color: var(--text); }
  .proto-highlight-box strong { color: var(--aroha); font-weight: 700; }

  /* ── Agent thinking ────────────────────────── */
  .think-wrap { max-width: 580px; margin-bottom: 14px; animation: fadeUp 0.25s ease; }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  .think-hdr { display: flex; align-items: center; gap: 8px; margin-bottom: 7px; padding: 0 2px; }
  .think-avatar {
    width: 26px; height: 26px;
    border-radius: 5px;
    display: flex; align-items: center; justify-content: center;
    font-family: var(--font-display);
    font-size: 8px; font-weight: 700;
    color: #020817; flex-shrink: 0;
  }
  .think-name {
    font-family: var(--font-data);
    font-size: 10px; font-weight: 700;
    letter-spacing: 0.1em; text-transform: uppercase;
  }
  .think-status { display: flex; align-items: center; gap: 6px; font-family: var(--font-data); font-size: 9px; letter-spacing: 0.06em; }
  .think-spinner { display: flex; gap: 3px; align-items: center; }
  .think-spinner span { width: 4px; height: 4px; border-radius: 50%; background: currentColor; opacity: 0.4; animation: bounce 1.2s infinite; }
  .think-spinner span:nth-child(2) { animation-delay: .2s; }
  .think-spinner span:nth-child(3) { animation-delay: .4s; }
  .think-toggle {
    margin-left: auto;
    background: none; border: none;
    font-family: var(--font-data); font-size: 9px; font-weight: 700;
    letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--dim); cursor: pointer; transition: color 0.15s; padding: 0;
  }
  .think-toggle:hover { color: var(--muted); }
  .think-box {
    background: rgba(2,8,23,0.85);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 10.5px;
    line-height: 1.8;
    max-height: 280px;
    overflow-y: auto;
    transition: max-height 0.35s ease, padding 0.25s ease, opacity 0.2s;
  }
  .think-box.collapsed { max-height: 0; padding-top: 0; padding-bottom: 0; opacity: 0; pointer-events: none; }
  .think-line { display: block; white-space: pre; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">Aroha<span>.</span></div>
  <span class="logo-tag">Protocol v1.0</span>
  <div style="width:1px;height:20px;background:var(--border);flex-shrink:0"></div>
  <div>
    <div class="agent-name">Personal Agent</div>
    <div class="agent-did" id="agentDid">did:aroha:personal-agent</div>
  </div>
  <div style="width:1px;height:20px;background:var(--border);flex-shrink:0"></div>
  <div class="agent-status"><div class="status-dot" id="statusDot"></div><span id="statusText">Online</span></div>
  <div class="llm-badge off" id="llmBadge"><div class="llm-dot"></div><span id="llmBadgeText">LLM: off</span></div>
  <div class="header-right">
    <button class="proto-btn" onclick="$('protocolModal').classList.add('open')"><div class="proto-btn-dot"></div>Aroha Protocol</button>
    <button class="sidebar-btn active" id="sidebarToggleBtn" onclick="toggleSidebar()">Activity Log</button>
    <button class="notif-btn" onclick="toggleNotifPanel()">🔔<div class="notif-badge" id="notifBadge">0</div></button>
  </div>
</div>

<div class="body">
  <div class="chat-col">
    <div class="messages" id="messages"></div>
    <div class="suggestions" id="suggestions">
      <div class="sug" onclick="send('Book me a business trip to Tokyo May 1–7')">✈️ Book Tokyo trip</div>
      <div class="sug" onclick="send('What can you do?')">💡 What can you do?</div>
      <div class="sug" onclick="send('Hi there!')">👋 Say hi</div>
    </div>
    <div class="input-area">
      <div class="input-row">
        <textarea class="input-box" id="inputBox" placeholder="Message your Personal Agent…" rows="1" onkeydown="handleKey(event)" oninput="autoResize(this)"></textarea>
        <button class="send-btn" id="sendBtn" onclick="sendInput()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
      </div>
      <div class="email-row">
        <span class="email-label">📧 Email for confirmation:</span>
        <input class="email-input" id="emailInput" type="email" placeholder="you@example.com" />
      </div>
    </div>
  </div>

  <div class="sidebar" id="sidebar">
    <div class="sidebar-inner">
      <div class="sidebar-title">Activity Log</div>
      <div class="sidebar-agents" id="sidebarAgents">
        <span class="agent-pill personal"><span class="agent-pill-dot"></span>Personal Agent</span>
        <span class="agent-pill flight"><span class="agent-pill-dot"></span>Flight Agent</span>
        <span class="agent-pill hotel"><span class="agent-pill-dot"></span>Hotel Agent</span>
        <span class="agent-pill payment"><span class="agent-pill-dot"></span>Payment Agent</span>
      </div>
      <div class="saga-bar" id="sagaBar" style="display:none">
        <div class="saga-step" id="saga-reserve">Reserve</div>
        <div class="saga-arrow">→</div>
        <div class="saga-step" id="saga-commit">Commit</div>
        <div class="saga-arrow">→</div>
        <div class="saga-step" id="saga-done">Done</div>
      </div>
      <div class="activity-list" id="activityList">
        <div class="act-empty" id="actEmpty"><div class="act-empty-icon">⛓</div>Protocol events will appear here<br>when a booking starts</div>
      </div>
    </div>
  </div>
</div>

<div class="notif-panel" id="notifPanel">
  <div class="notif-panel-title">Notifications<span class="notif-clear" onclick="clearNotifs()">Clear all</span></div>
  <div id="notifList"></div>
</div>
<div class="toast-container" id="toastContainer"></div>

<div class="modal-overlay" id="envModal" onclick="closeModal('envModal',event)">
  <div class="modal-box">
    <div class="modal-top"><div class="modal-title">Aroha Envelope — Ed25519 Signed</div><button class="modal-close" onclick="$('envModal').classList.remove('open')">✕</button></div>
    <pre class="modal-pre" id="envPre"></pre>
  </div>
</div>

<div class="modal-overlay" id="emailModal" onclick="closeModal('emailModal',event)">
  <div class="email-modal-box" id="emailFrame"></div>
</div>

<div class="modal-overlay" id="protocolModal" onclick="closeModal('protocolModal',event)">
  <div class="proto-modal-box">
    <div class="proto-modal-hdr">
      <div>
        <div class="proto-modal-title">Aroha PROTOCOL</div>
        <div class="proto-modal-sub">Aroha Protocol &nbsp;·&nbsp; v1.0 &nbsp;·&nbsp; Open Standard</div>
      </div>
      <button class="modal-close" onclick="$('protocolModal').classList.remove('open')">✕</button>
    </div>
    <div class="proto-modal-body">

      <div class="proto-highlight-box">
        <p><strong>Aroha</strong> is the open protocol that lets AI agents from different companies, clouds, and frameworks transact with each other — autonomously, verifiably, and atomically. It's the <strong>TCP/IP layer for agentic AI</strong>: a shared language for identity, capability negotiation, signed messaging, and atomic multi-party commits backed by on-chain escrow.</p>
      </div>

      <div>
        <div class="proto-section-title">Why it matters</div>
        <div class="proto-kv-grid">
          <div class="proto-kv">
            <div class="proto-kv-label">The Problem</div>
            <div class="proto-kv-val">Agents act for people and hand work to other agents. Each hop uses its own key, so the person's limit, purpose and expiry are lost, and nobody outside can check what was done.
              <small>No signed grant = no proof of what the agent was allowed to do</small>
            </div>
          </div>
          <div class="proto-kv">
            <div class="proto-kv-label">The Solution</div>
            <div class="proto-kv-val">Aroha gives every agent a DID, a mandate chain back to the person that can only narrow, revocation every verifier sees, and a signed receipt for each action.
              <small>No agent can exceed the scope it was granted</small>
            </div>
          </div>
          <div class="proto-kv">
            <div class="proto-kv-label">Atomic Sagas (extension)</div>
            <div class="proto-kv-val">Multi-party transactions either fully commit or fully roll back — no partial states, no stuck funds.
              <small>Reserve → Commit → Settle or Compensate</small>
            </div>
          </div>
          <div class="proto-kv">
            <div class="proto-kv-label">Works with</div>
            <div class="proto-kv-val">MCP, A2A and your identity provider — Aroha adds what the caller is allowed to do and proof of what it did.
              <small>Adopt at the edge: one verify call per handler</small>
            </div>
          </div>
        </div>
      </div>

      <div>
        <div class="proto-section-title">Message flow — this demo</div>
        <div class="proto-flow">
          <div class="proto-flow-row">
            <div class="proto-node" style="background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);color:#06b6d4">User</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);color:#06b6d4">Personal Agent (PA)</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.06);border:1px solid var(--border);color:var(--muted)">ArohaRequest (L3)</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.06);border:1px solid var(--border);color:var(--muted)">On-chain Registry</div>
          </div>
          <div style="color:var(--dim);padding:4px 0 4px 20px;font-size:10px">↓ discovers flight-agent, hotel-agent, payment-agent via ArohaRegistry.sol</div>
          <div class="proto-flow-row">
            <div class="proto-node" style="background:rgba(139,92,246,0.12);border:1px solid rgba(139,92,246,0.3);color:#a78bfa">Flight Agent (FL)</div>
            <div class="proto-arrow">← ArohaRequest →</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.3);color:#06b6d4">PA</div>
            <div class="proto-arrow">← ArohaRequest →</div>
            <div class="proto-node" style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);color:#34d399">Hotel Agent (HT)</div>
          </div>
          <div style="color:var(--dim);padding:4px 0 4px 20px;font-size:10px">↓ each sub-agent runs its own LLM call · each message is Ed25519-signed</div>
          <div class="proto-flow-row">
            <div class="proto-node" style="background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.3);color:#fbbf24">Payment Agent (PY)</div>
            <div class="proto-arrow">+ FL + HT</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.06);border:1px solid var(--border);color:var(--muted)">ArohaReserve (L4)</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(6,182,212,0.06);border:1px solid var(--border);color:var(--muted)">ArohaEscrow.sol locks funds</div>
          </div>
          <div style="color:var(--dim);padding:4px 0 4px 20px;font-size:10px">↓ all three hold tokens received simultaneously</div>
          <div class="proto-flow-row">
            <div class="proto-node" style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);color:#34d399">ArohaCommit (PA → all)</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(16,185,129,0.06);border:1px solid rgba(16,185,129,0.3);color:#34d399">Escrow.release() · Reputation++</div>
            <div class="proto-arrow">→</div>
            <div class="proto-node" style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);color:#34d399">✓ Settled on-chain</div>
          </div>
        </div>
      </div>

      <div>
        <div class="proto-section-title">Smart contracts called in this demo</div>
        <div class="proto-chain-card">
          <div class="proto-chain-name">ArohaRegistry.sol</div>
          <div class="proto-chain-desc">Canonical on-chain agent directory. Stores agent DIDs, Ed25519 public keys, capability manifests (IPFS CID), stake, and reputation score. Agents must stake ETH to register — Sybil resistance by design.</div>
          <div>
            <span class="proto-chain-method">register(didHash, manifestCID, pubKey)</span><span class="proto-when">→ at boot</span>
            <span class="proto-chain-method">queryByCapability(capHash)</span><span class="proto-when">→ on discover</span>
            <span class="proto-chain-method">verify(didHash, sig)</span><span class="proto-when">→ each envelope</span>
          </div>
        </div>
        <div class="proto-chain-card" style="border-left-color:var(--yellow)">
          <div class="proto-chain-name" style="color:var(--yellow)">ArohaEscrow.sol</div>
          <div class="proto-chain-desc">Trustless payment infrastructure. Funds are locked when the saga starts (ArohaReserve) and released atomically only after all ArohaCommitAcks are received. If any step fails, funds auto-refund — no manual intervention.</div>
          <div>
            <span class="proto-chain-method" style="color:var(--yellow);border-color:rgba(245,158,11,0.2);background:rgba(245,158,11,0.06)">lockFunds(sagaId, splits)</span><span class="proto-when">→ on Reserve</span>
            <span class="proto-chain-method" style="color:var(--yellow);border-color:rgba(245,158,11,0.2);background:rgba(245,158,11,0.06)">release(sagaId)</span><span class="proto-when">→ on Commit</span>
            <span class="proto-chain-method" style="color:var(--yellow);border-color:rgba(245,158,11,0.2);background:rgba(245,158,11,0.06)">refund(sagaId)</span><span class="proto-when">→ on Cancel</span>
          </div>
        </div>
        <div class="proto-chain-card" style="border-left-color:var(--accent2)">
          <div class="proto-chain-name" style="color:var(--accent2)">ArohaReputation.sol</div>
          <div class="proto-chain-desc">On-chain reputation oracle. Every successful commit increments an agent's reputation score; failures and disputes decrement it. High-reputation agents get priority in discovery queries and lower required stake.</div>
          <div>
            <span class="proto-chain-method" style="color:#a78bfa;border-color:rgba(139,92,246,0.2);background:rgba(139,92,246,0.06)">recordSuccess(agentDid, sagaId)</span><span class="proto-when">→ post-commit</span>
            <span class="proto-chain-method" style="color:#a78bfa;border-color:rgba(139,92,246,0.2);background:rgba(139,92,246,0.06)">recordFailure(agentDid)</span><span class="proto-when">→ on timeout</span>
          </div>
        </div>
      </div>

      <div>
        <div class="proto-section-title">Protocol layers</div>
        <div class="proto-kv-grid">
          <div class="proto-kv"><div class="proto-kv-label" style="color:#a78bfa">Layer 2 — Chain</div><div class="proto-kv-val">ArohaRegistry · ArohaEscrow · ArohaReputation<small>Ethereum-compatible · EVM · IPFS for manifests</small></div></div>
          <div class="proto-kv"><div class="proto-kv-label" style="color:var(--aroha)">Layer 3 — Transport</div><div class="proto-kv-val">Ed25519-signed envelopes · DID-to-DID routing · HTTP + SSE<small>ArohaRequest · ArohaResponse · ArohaStream</small></div></div>
          <div class="proto-kv"><div class="proto-kv-label" style="color:var(--yellow)">Layer 4 — Saga</div><div class="proto-kv-val">Distributed transaction coordinator · 2-phase commit<small>Reserve → Commit → Settle (or Cancel → Compensate)</small></div></div>
          <div class="proto-kv"><div class="proto-kv-label" style="color:var(--green)">Layer 5 — RBAC</div><div class="proto-kv-val">Role-based capability enforcement · orchestrator / provider<small>Every agent action is permission-checked before execution</small></div></div>
        </div>
      </div>

    </div>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
let sidebarOpen = true, notifCount = 0;

// ─── SSE ──────────────────────────────────────────────────────────────────────
const es = new EventSource('/api/stream');
es.onmessage = e => {
  const d = JSON.parse(e.data);
  if (d.type==='init') {
    d.messages.forEach(renderMessage);
    d.activity.forEach(renderActivity);
    d.notifications.forEach(n=>{addNotifItem(n);});
    setLLMBadge(d.llmEnabled, d.llmBackend, d.llmModel);
    if (!d.messages.length) showWelcome(d.llmEnabled, d.llmBackend, d.llmModel);
  }
  if (d.type==='chat')              renderMessage(d);
  if (d.type==='activity')          renderActivity(d);
  if (d.type==='notification')      { addNotifItem(d); showToast(d); }
  if (d.type==='state')             onStateChange(d.state);
  if (d.type==='reset')             resetUI();
  if (d.type==='chat_stream_start') startStream(d.id, d.agent);
  if (d.type==='chat_stream_delta') appendStream(d.id, d.delta);
  if (d.type==='chat_stream_end')   finalizeStream(d.id, d.text);
  if (d.type==='agent_thinking_start') startThinking(d.agent);
  if (d.type==='agent_thinking_line')  addThinkLine(d.agent, d.line);
  if (d.type==='agent_thinking_done')  endThinking(d.agent);
  if (d.type==='llm_status') {
    setLLMBadge(d.ready, d.backend, d.model);
    if (!d.ready && d.msg) showToast({ title: 'LLM', body: d.msg, icon: '⏳' });
    if (d.ready)           showToast({ title: 'LLM ready', body: \`\${d.model.split('/').pop()} loaded\`, icon: '✅' });
  }
};

function setLLMBadge(on, backend, model) {
  const b = $('llmBadge');
  const t = $('llmBadgeText');
  if (on) {
    const label = backend === 'vllm' ? 'vllm: ' + (model||'').split('/').pop() : 'claude-sonnet-4-6';
    t.textContent = label;
    b.className = 'llm-badge';
  } else {
    t.textContent = backend === 'vllm' ? 'vllm: loading…' : 'LLM: off';
    b.className = 'llm-badge off';
  }
}

// ─── Welcome ──────────────────────────────────────────────────────────────────
function showWelcome(llmEnabled, backend, model) {
  let modelLabel = '';
  if (llmEnabled) {
    modelLabel = backend === 'vllm'
      ? \` powered by **\${(model||'').split('/').pop()}** (vllm)\`
      : ' powered by **claude-sonnet-4-6**';
  }
  renderMessage({ id:'welcome', ts:Date.now(), role:'agent', agent:'personal',
    content: \`Hi! I'm your Aroha Personal Agent\${modelLabel}. I coordinate a network of specialized agents — flight, hotel, and payment — each running their own LLM to make decisions.\\n\\nTry: **"Book me a business trip to Tokyo May 1–7"**\` });
}

// ─── Streaming ────────────────────────────────────────────────────────────────
const streamingBubbles = {};

function startStream(id, agent) {
  const wrap = document.createElement('div');
  wrap.className = 'msg-wrap agent';
  wrap.id = 'stream-' + id;
  const hdr = document.createElement('div');
  hdr.className = 'msg-hdr';
  hdr.innerHTML = \`<div class="avatar">PA</div><div class="msg-sender">Personal Agent</div><div class="msg-time">\${fmtTime(Date.now())}</div>\`;
  const bubble = document.createElement('div');
  bubble.className = 'bubble streaming-cursor';
  bubble.id = 'sbubble-' + id;
  wrap.appendChild(hdr); wrap.appendChild(bubble);
  $('messages').appendChild(wrap);
  streamingBubbles[id] = bubble;
  scrollDown(); hideSuggestions();
}

function appendStream(id, delta) {
  const b = streamingBubbles[id];
  if (!b) return;
  b.innerHTML = markdownish(b.dataset.raw = ((b.dataset.raw||'') + delta));
  b.classList.add('streaming-cursor');
  scrollDown();
}

function finalizeStream(id, text) {
  const b = streamingBubbles[id];
  if (b) { b.innerHTML = markdownish(text); b.classList.remove('streaming-cursor'); }
  delete streamingBubbles[id];
  // The server will follow up with a full chat message that contains card data if needed
}

// ─── Message rendering ────────────────────────────────────────────────────────
function renderMessage(m) {
  // Remove streaming bubble by exact ID match
  const existing = document.getElementById('stream-' + m.id);
  if (existing) existing.remove();
  // Also remove any finalized streaming bubbles (stream ended, no active cursor) —
  // they have a different UUID to m.id so the above won't catch them
  document.querySelectorAll('[id^="stream-"]').forEach(el => {
    if (!el.querySelector('.streaming-cursor')) el.remove();
  });

  const wrap = document.createElement('div');
  wrap.className = 'msg-wrap ' + m.role;
  wrap.id = 'msg-' + m.id;
  const hdr = document.createElement('div');
  hdr.className = 'msg-hdr';
  if (m.role==='agent') hdr.innerHTML=\`<div class="avatar">PA</div><div class="msg-sender">Personal Agent</div><div class="msg-time">\${fmtTime(m.ts)}</div>\`;
  else hdr.innerHTML=\`<div class="msg-time">\${fmtTime(m.ts)}</div><div class="msg-sender">You</div>\`;
  wrap.appendChild(hdr);
  if (m.content && !m.card) { const b=document.createElement('div'); b.className='bubble'; b.innerHTML=markdownish(m.content); wrap.appendChild(b); }
  if (m.content && m.card)  { const b=document.createElement('div'); b.className='bubble'; b.innerHTML=markdownish(m.content); wrap.appendChild(b); }
  if (m.card==='flights')          wrap.appendChild(makeFlightCard(m.flights, m.recommended));
  if (m.card==='hotels')           wrap.appendChild(makeHotelCard(m.hotels,   m.recommended));
  if (m.card==='payment')          wrap.appendChild(makePayCard(m.flight, m.hotel, m.total, m.card_info));
  if (m.card==='booking_complete') wrap.appendChild(makeCompleteCard(m));
  $('messages').appendChild(wrap);
  scrollDown(); hideSuggestions();
}

// ─── Cards ────────────────────────────────────────────────────────────────────
function makeFlightCard(flights, recId) {
  const w = document.createElement('div'); w.className='card-wrap';
  w.innerHTML = '<div class="card-label">✈ Choose your flight</div>';
  flights.forEach(f => {
    const el = document.createElement('div');
    el.className = 'flight-card' + (f.id===recId?' recommended':'');
    el.id = 'fc-'+f.id;
    el.innerHTML = \`
      \${f.id===recId?'<div class="rec-tag">Agent Recommended</div>':''}
      <div class="airline-tag">\${f.airline}</div>
      <div style="flex:1"><div class="f-times">\${f.dep} → \${f.arr}</div><div class="f-meta">\${f.no} · \${f.stops} · \${f.dur} · \${f.class}</div></div>
      <div class="f-price">$\${f.price.toLocaleString()}</div>
    \`;
    el.onclick = () => { fetch('/api/select/flight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({flightId:f.id})}); document.querySelectorAll('.flight-card').forEach(c=>c.classList.remove('picked')); el.classList.add('picked'); };
    w.appendChild(el);
  });
  return w;
}

function makeHotelCard(hotels, recId) {
  const w = document.createElement('div'); w.className='card-wrap';
  w.innerHTML = '<div class="card-label">🏨 Choose your hotel</div>';
  hotels.forEach(h => {
    const el = document.createElement('div');
    el.className = 'hotel-card' + (h.id===recId?' recommended':'');
    el.id = 'hc-'+h.id;
    el.innerHTML = \`
      \${h.id===recId?'<div class="rec-tag-h">Agent Recommended</div>':''}
      <div class="h-name">\${h.name}</div>
      <div class="h-area">⭐ \${h.stars} · \${h.area} · \${h.rating}/5</div>
      <div class="h-row">\${h.amenities.map(a=>\`<span class="amenity">\${a}</span>\`).join('')}<div class="h-price">$\${h.price}<small>/night</small></div></div>
    \`;
    el.onclick = () => { fetch('/api/select/hotel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hotelId:h.id})}); document.querySelectorAll('.hotel-card').forEach(c=>c.classList.remove('picked')); el.classList.add('picked'); };
    w.appendChild(el);
  });
  return w;
}

function makePayCard(f, h, total, card) {
  const w = document.createElement('div'); w.className='card-wrap';
  w.innerHTML = '<div class="card-label">💳 Confirm & Commit Saga</div>';
  const el = document.createElement('div'); el.className='pay-card';
  el.innerHTML = \`
    <div class="pay-line"><span>✈ \${f.airline} \${f.no}</span><span>$\${f.price.toLocaleString()}</span></div>
    <div class="pay-line"><span>🏨 \${h.name} (6 nights)</span><span>$\${h.total.toLocaleString()}</span></div>
    <div class="pay-line total"><span>Total</span><span class="amount">$\${total.toLocaleString()}</span></div>
    <div class="cc-strip">
      <div class="cc-chip"></div>
      <div class="cc-num">4242 4242 4242 4242</div>
      <div class="cc-row">
        <div><div>CARDHOLDER</div><div class="cc-val">\${card.holder.toUpperCase()}</div></div>
        <div><div>EXPIRES</div><div class="cc-val">\${card.expiry}</div></div>
        <div style="font-size:16px;font-weight:800;color:#f59e0b">\${card.type.split(' ')[0]}</div>
      </div>
    </div>
    <button class="btn-pay" id="payBtn" onclick="this.disabled=true;this.textContent='Processing…';fetch('/api/confirm/payment',{method:'POST'})">🔐 Authorize $\${total.toLocaleString()} — Commit Atomic Saga</button>
  \`;
  w.appendChild(el); return w;
}

function makeCompleteCard(m) {
  const w = document.createElement('div'); w.className='card-wrap';
  const el = document.createElement('div'); el.className='complete-card';
  el.innerHTML = \`
    <div class="complete-header">✓ Booking Confirmed — 3-Agent Saga Committed</div>
    <div class="ref-row"><span class="ref-key">Flight PNR</span><span class="ref-val">\${m.pnr}</span></div>
    <div class="ref-row"><span class="ref-key">Hotel Conf#</span><span class="ref-val">\${m.confNo}</span></div>
    <div class="ref-row"><span class="ref-key">Charge ID</span><span class="ref-val">\${m.chgId.slice(0,22)}</span></div>
    <div class="ref-row"><span class="ref-key">Total</span><span class="ref-val" style="color:var(--accent)">$\${m.total.toLocaleString()}</span></div>
    <div class="action-row">
      <a href="/api/calendar.ics" class="action-btn" download="tokyo-trip.ics">📥 .ics File</a>
      <a href="\${m.calUrl}" target="_blank" class="action-btn primary">📅 Google Calendar</a>
      \${m.emailSent
        ? \`<span class="action-btn" style="color:var(--green);border-color:var(--green);pointer-events:none">📧 Sent to \${m.emailTarget?.split('@')[0]} ✓</span>\`
        : \`<span class="action-btn" onclick="showEmailPreview()" style="cursor:pointer">📧 Preview email</span>\`
      }
    </div>
  \`;
  w.appendChild(el); return w;
}

// ─── Activity sidebar ─────────────────────────────────────────────────────────
const LAYER_MAP = {
  ArohaRequest:'L3', ArohaResponse:'L3', ArohaStream:'L3',
  ArohaReserve:'L4', ArohaReserveAck:'L4', ArohaCommit:'L4', ArohaCommitAck:'L4',
  ArohaCancel:'L4', ArohaCancelAck:'L4', ArohaDelegate:'L4',
  LLM:'AI', Email:'OUT', Boot:'SYS',
};
function getLayer(a) {
  if (a.from === 'chain') return 'L2';
  return LAYER_MAP[a.type] || 'L?';
}
const RBAC_MAP = {
  'personal-agent':'orchestrator', 'flight-agent':'provider',
  'hotel-agent':'provider', 'payment-agent':'provider'
};

function renderActivity(a) {
  const el = document.createElement('div');
  el.className = a.from === 'chain' ? 'act-item act-chain' : 'act-item';
  el.onclick=()=>{ if(a.envelope){$('envPre').textContent=JSON.stringify(a.envelope,null,2);$('envModal').classList.add('open');} };
  const cls = a.type.replace(/[^a-zA-Z]/g,'');
  const layer = getLayer(a);
  const fromRole = RBAC_MAP[a.from] || '';
  const hdr = document.createElement('div'); hdr.className='act-hdr';
  hdr.innerHTML = '<span class="act-layer">' + layer + '</span><span class="act-type ' + cls + '">' + a.type + '</span><span class="act-time">' + fmtTime(a.ts) + '</span>';
  const route = document.createElement('div'); route.className='act-route';
  route.textContent = shorten(a.from) + ' \u2192 ' + shorten(a.to);
  const body = document.createElement('div'); body.className='act-body';
  body.textContent = a.summary;
  el.appendChild(hdr); el.appendChild(route); el.appendChild(body);
  if(fromRole) {
    const rbac = document.createElement('span'); rbac.className='rbac-tag';
    rbac.textContent = fromRole + ' \u2022 Ed25519';
    el.appendChild(rbac);
  }
  $('activityList').appendChild(el);
  const empty = $('actEmpty'); if (empty) empty.remove();
  $('activityList').parentElement.scrollTop=$('activityList').scrollHeight;
  updateSagaBar(a.type);
}

function updateSagaBar(type) {
  const bar = $('sagaBar');
  if(type==='ArohaReserve'||type==='ArohaReserveAck') { bar.style.display='flex'; $('saga-reserve').className='saga-step active'; }
  if(type==='ArohaCommit') { $('saga-commit').className='saga-step active'; }
  if(type==='ArohaCommitAck') { $('saga-commit').className='saga-step done'; $('saga-reserve').className='saga-step done'; }
  if(type==='ArohaCancelAck') { $('saga-done').className='saga-step done'; $('saga-done').textContent='Settled'; }
  if(type==='ArohaCommitAck' && document.querySelectorAll('.saga-step.done').length>=2) { $('saga-done').className='saga-step done'; }
}

function shorten(s){ return s.length>20?s.split(':').pop().slice(0,14):s; }

// ─── Notifications ────────────────────────────────────────────────────────────
function addNotifItem(n) {
  notifCount++; $('notifBadge').textContent=notifCount; $('notifBadge').classList.add('show');
  const el=document.createElement('div'); el.className='notif-item';
  el.innerHTML=\`<div class="notif-icon">\${n.icon}</div><div><div class="notif-title-t">\${n.title}</div><div class="notif-body-t">\${n.body}</div><div class="notif-time-t">\${fmtTime(n.ts)}</div></div>\`;
  $('notifList').prepend(el);
  if(Notification.permission==='granted') new Notification(n.title,{body:n.body});
}
function showToast(n) {
  const el=document.createElement('div'); el.className='toast';
  el.innerHTML=\`<div class="toast-icon">\${n.icon}</div><div><div class="toast-title">\${n.title}</div><div class="toast-body">\${n.body}</div></div>\`;
  $('toastContainer').appendChild(el);
  setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),300);},4000);
}
function toggleNotifPanel(){ $('notifPanel').classList.toggle('open'); if($('notifPanel').classList.contains('open')){notifCount=0;$('notifBadge').classList.remove('show');} }
function clearNotifs(){ $('notifList').innerHTML=''; notifCount=0; $('notifBadge').classList.remove('show'); }

// ─── State ────────────────────────────────────────────────────────────────────
function onStateChange(state) {
  const busy=state!=='idle'&&state!=='done';
  $('statusDot').className='status-dot'+(busy?' busy':'');
  $('statusText').textContent={idle:'Online',done:'Online',running:'Agents working…',selecting_flight:'Waiting for you',selecting_hotel:'Waiting for you',confirming_payment:'Waiting for you'}[state]??'Working…';
  if(state==='running'&&Notification.permission==='default') Notification.requestPermission();
}
function resetUI(){ $('messages').innerHTML=''; $('activityList').innerHTML=''; showSuggestions(); }

// ─── Input ────────────────────────────────────────────────────────────────────
function send(text){
  const email=$('emailInput').value.trim();
  fetch('/api/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,email})});
  $('inputBox').value=''; autoResize($('inputBox'));
}
function sendInput(){ const t=$('inputBox').value.trim(); if(t) send(t); }
function handleKey(e){ if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendInput();} }
function autoResize(el){ el.style.height='auto'; el.style.height=Math.min(el.scrollHeight,120)+'px'; }

// ─── Email preview ────────────────────────────────────────────────────────────
function showEmailPreview(){ fetch('/api/email-preview').then(r=>r.text()).then(html=>{ $('emailFrame').innerHTML=html; $('emailModal').classList.add('open'); }); }

// ─── Misc ─────────────────────────────────────────────────────────────────────
function scrollDown(){ const el=$('messages'); el.scrollTop=el.scrollHeight; }
function fmtTime(ts){ return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}); }
function markdownish(t){ return (t||'').replace(/[*][*](.+?)[*][*]/g,'<strong>$1</strong>').replace(/[*](.+?)[*]/g,'<em>$1</em>').replace(/\\n/g,'<br>'); }
function toggleSidebar(){ sidebarOpen=!sidebarOpen; $('sidebar').classList.toggle('hidden',!sidebarOpen); $('sidebarToggleBtn').classList.toggle('active',sidebarOpen); }
function hideSuggestions(){ $('suggestions').style.display='none'; }
function showSuggestions(){ $('suggestions').style.display='flex'; }
function closeModal(id,e){ if(e.target.classList.contains('modal-overlay')) $(id).classList.remove('open'); }
document.addEventListener('click',e=>{ if(!e.target.closest('#notifPanel')&&!e.target.closest('.notif-btn')) $('notifPanel').classList.remove('open'); });

// ── Agent thinking ──────────────────────────────────────────────────────────
const AGENT_META = {
  'flight-agent':  { label: 'Flight Agent',   abbr: 'FL', color: '#8b5cf6' },
  'hotel-agent':   { label: 'Hotel Agent',    abbr: 'HT', color: '#10b981' },
  'payment-agent': { label: 'Payment Agent',  abbr: 'PY', color: '#f59e0b' },
  'personal-agent':{ label: 'Personal Agent', abbr: 'PA', color: '#06b6d4' },
};
const activeThinking = {};

function startThinking(agent) {
  const m = AGENT_META[agent] || { label: agent, abbr: '??', color: 'var(--muted)' };
  // remove old thinking panel for this agent if re-running
  const old = document.getElementById('think-' + agent);
  if (old) old.remove();
  const wrap = document.createElement('div');
  wrap.className = 'think-wrap';
  wrap.id = 'think-' + agent;
  wrap.innerHTML =
    '<div class="think-hdr">' +
      '<div class="think-avatar" style="background:' + m.color + '">' + m.abbr + '</div>' +
      '<div class="think-name" style="color:' + m.color + '">' + m.label + '</div>' +
      '<div class="think-status" id="think-status-' + agent + '" style="color:' + m.color + '">' +
        '<div class="think-spinner"><span></span><span></span><span></span></div>' +
        '<span>thinking\u2026</span>' +
      '</div>' +
      '<button class="think-toggle" data-agent="' + agent + '" onclick="toggleThink(this.dataset.agent)">&#9660; hide</button>' +
    '</div>' +
    '<div class="think-box" id="think-box-' + agent + '" style="border-left:2px solid ' + m.color + '40"></div>';
  $('messages').appendChild(wrap);
  activeThinking[agent] = document.getElementById('think-box-' + agent);
  scrollDown();
}

function addThinkLine(agent, line) {
  const box = activeThinking[agent];
  if (!box) return;
  const m = AGENT_META[agent];
  const span = document.createElement('span');
  span.className = 'think-line';
  if (line === '') {
    span.textContent = '\u00a0';
    span.style.color = 'transparent';
  } else if (line.startsWith('  ')) {
    span.textContent = line;
    span.style.color = 'var(--text)';
  } else {
    span.textContent = line;
    span.style.color = m ? m.color : 'var(--muted)';
  }
  box.appendChild(span);
  box.scrollTop = box.scrollHeight;
  scrollDown();
}

function endThinking(agent) {
  const statusEl = document.getElementById('think-status-' + agent);
  if (statusEl) statusEl.innerHTML = '<span style="color:var(--green);font-family:var(--font-data);font-size:9px;font-weight:700;letter-spacing:0.08em">✓ done</span>';
  delete activeThinking[agent];
}

function toggleThink(agent) {
  const box = document.getElementById('think-box-' + agent);
  const btn = document.querySelector('#think-' + agent + ' .think-toggle');
  if (!box || !btn) return;
  const collapsed = box.classList.toggle('collapsed');
  btn.innerHTML = collapsed ? '&#9654; show' : '&#9660; hide';
}
</script>
</body>
</html>`;
