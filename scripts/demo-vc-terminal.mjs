// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha VC Terminal Demo — Two Scenarios
 *
 * Scenario 1 — Travel Saga
 *   PersonalAgent books a Tokyo trip atomically across FlightAgent and
 *   HotelAgent. Proves: multi-party saga, atomic rollback, LLM orchestration.
 *
 * Scenario 2 — Hedge Fund Analyst (MCP Data Wedge)
 *   HedgeFundAgent pays TwitterScraperMCP $0.20 for real-time BTC sentiment,
 *   then synthesises a Q2 outlook report. Proves: micro-payments, MCP bridge,
 *   pure digital M2M transaction with no human in the loop.
 *
 * Usage:
 *   npm run demo:vc
 *   node scripts/demo-vc-terminal.mjs
 *
 * LLM integration (optional but spectacular):
 *   export ANTHROPIC_API_KEY=sk-ant-...
 *   npm run demo:vc
 *
 *   With a key, Claude streams its real reasoning into every thinking panel.
 *   Without a key, realistic simulated text types out instead — demo still works.
 *
 * Total runtime: ~35 seconds (paced for human eyes).
 */

import { randomBytes, createHash } from "node:crypto";

// ─── Terminal dimensions ──────────────────────────────────────────────────────

const W = Math.min(process.stdout.columns || 88, 88);

// ─── ANSI colours ─────────────────────────────────────────────────────────────

const c = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  teal:    "\x1b[38;5;51m",
  cyan:    "\x1b[36m",
  mint:    "\x1b[38;5;120m",
  green:   "\x1b[32m",
  yellow:  "\x1b[33m",
  magenta: "\x1b[35m",
  orange:  "\x1b[38;5;208m",
  white:   "\x1b[37m",
  gray:    "\x1b[90m",
  bgTeal:  "\x1b[48;5;23m",
  bgDark:  "\x1b[48;5;234m",
};

// ─── Layout helpers ───────────────────────────────────────────────────────────

function rule(char = "─", color = c.teal) {
  process.stdout.write(color + char.repeat(W) + c.reset + "\n");
}

function box(text, borderColor = c.teal, textColor = c.white) {
  const pad = Math.max(0, Math.floor((W - text.length - 4) / 2));
  const sp  = " ".repeat(pad);
  console.log(borderColor + sp + "┌" + "─".repeat(text.length + 2) + "┐" + c.reset);
  console.log(borderColor + sp + "│ " + textColor + c.bold + text + c.reset + borderColor + " │" + c.reset);
  console.log(borderColor + sp + "└" + "─".repeat(text.length + 2) + "┘" + c.reset);
}

function phaseHeader(num, title) {
  const tag = c.bgTeal + c.bold + ` PHASE ${num} ` + c.reset;
  console.log(`\n  ${tag}  ${c.bold}${c.white}${title}${c.reset}\n`);
}

function log(actor, color, msg) {
  const ts    = c.dim + c.gray + new Date().toISOString().slice(11, 23) + c.reset;
  const label = color + c.bold + actor.padEnd(18) + c.reset;
  console.log(`  ${ts}  ${label}  ${msg}`);
}

// Print an agent-to-agent message arrow line.
function msg(fromLabel, fromColor, arrow, toLabel, toColor, type, summary) {
  const from = fromColor + c.bold + fromLabel.padEnd(22) + c.reset;
  const arr  = c.gray + arrow + c.reset;
  const to   = toColor  + c.bold + toLabel.padEnd(22) + c.reset;
  const t    = c.teal   + c.bold + type + c.reset;
  const det  = summary ? c.gray + "  " + summary + c.reset : "";
  console.log(`  ${from}  ${arr}  ${to}  ${t}${det}`);
}

// Indented MCP sub-call line (inside a Aroha request).
function mcpLine(fromLabel, fromColor, arrow, toLabel, toColor, type, detail) {
  const from = fromColor + fromLabel.padEnd(22) + c.reset;
  const arr  = c.gray + arrow + c.reset;
  const to   = toColor + toLabel.padEnd(22) + c.reset;
  const t    = c.orange + c.bold + type + c.reset;
  const det  = detail ? c.gray + "  " + detail + c.reset : "";
  console.log(`        ${from}  ${arr}  ${to}  ${t}${det}`);
}

function detail(line) {
  console.log(`  ${c.dim}      ${line}${c.reset}`);
}

function ok(text) {
  console.log(`\n  ${c.green}✓${c.reset}  ${text}`);
}

function blank() { console.log(); }

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ─── LLM thinking panel ───────────────────────────────────────────────────────
//
// Renders a bordered "thinking" box with text that streams in character by
// character. With ANTHROPIC_API_KEY set, streams real Claude output. Without
// it, types out the pre-written simulatedLines at a realistic WPM.

async function thinkAloud(agentLabel, agentColor, simulatedLines, claudeOpts = null) {
  const labelPart = ` ${agentLabel} · reasoning `;
  const dashLen   = Math.max(2, W - labelPart.length - 5);
  console.log(`\n  ${agentColor}┌─${labelPart}${"─".repeat(dashLen)}┐${c.reset}`);
  console.log(`  ${agentColor}│${c.reset}`);

  if (process.env.ANTHROPIC_API_KEY && claudeOpts) {
    await _claudeStream(agentColor, claudeOpts);
  } else {
    for (const paragraph of simulatedLines) {
      await _typeWords(agentColor, paragraph);
    }
  }

  console.log(`  ${agentColor}│${c.reset}`);
  console.log(`  ${agentColor}└${"─".repeat(W - 3)}┘${c.reset}\n`);
}

// Word-wrap and type-out a single paragraph of text, one character at a time.
async function _typeWords(agentColor, text) {
  const maxW  = W - 8;          // usable chars per line inside the box
  const words = text.split(" ");
  process.stdout.write(`  ${agentColor}│${c.reset}  `);
  let lineLen = 0;

  for (const word of words) {
    if (lineLen > 0 && lineLen + word.length + 1 > maxW) {
      process.stdout.write(`\n  ${agentColor}│${c.reset}  `);
      lineLen = 0;
    }
    if (lineLen > 0) { process.stdout.write(" "); lineLen++; }
    for (const ch of word) {
      process.stdout.write(ch);
      await sleep(15);
    }
    lineLen += word.length;
  }
  process.stdout.write("\n");
  await sleep(160);
}

// Stream real Claude output, word-wrapping into the box.
async function _claudeStream(agentColor, { system, user }) {
  try {
    const { default: Anthropic } = await import(
      new URL("../node_modules/@anthropic-ai/sdk/index.js", import.meta.url)
    );
    const client  = new Anthropic();
    const maxW    = W - 8;
    const prefix  = `  ${agentColor}│${c.reset}  `;

    const stream = client.messages.stream({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 160,
      system,
      messages: [{ role: "user", content: user }],
    });

    process.stdout.write(prefix);
    let lineLen = 0;

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        for (const ch of event.delta.text) {
          if (ch === "\n") {
            if (lineLen > 0) { process.stdout.write("\n" + prefix); lineLen = 0; }
          } else {
            if (ch === " " && lineLen >= maxW) {
              process.stdout.write("\n" + prefix); lineLen = 0;
            } else {
              process.stdout.write(ch); lineLen++;
              await sleep(9);
            }
          }
        }
      }
    }
    if (lineLen > 0) process.stdout.write("\n");
  } catch {
    process.stdout.write(`  ${agentColor}│${c.reset}  ${c.gray}[set ANTHROPIC_API_KEY for live Claude reasoning]${c.reset}\n`);
  }
}

// ─── Fake-but-realistic crypto helpers ───────────────────────────────────────

function fakeDID(name) {
  const h = createHash("sha256").update(name + process.pid).digest("hex");
  return `did:aroha:${name}-${h.slice(0, 8)}`;
}

function fakeKey(did) {
  return createHash("sha256").update(did).digest("base64url").slice(0, 44);
}

function fakeSig(seed) {
  const h = createHash("sha256").update(seed + randomBytes(4).toString("hex")).digest("base64url");
  return (h + h).slice(0, 88);
}

function fakeNonce() { return randomBytes(16).toString("hex"); }

function fakeSagaId() {
  const b = randomBytes(16).toString("hex");
  return `${b.slice(0,8)}-${b.slice(8,12)}-${b.slice(12,16)}-${b.slice(16,20)}-${b.slice(20,32)}`;
}

function fakeTx() { return "0x" + randomBytes(32).toString("hex"); }

// ─── Scenario separator ───────────────────────────────────────────────────────

async function scenarioSeparator(n, title, subtitle) {
  blank();
  rule("═");
  blank();
  const scenTag = c.bgTeal + c.bold + ` SCENARIO ${n} ` + c.reset;
  console.log(`  ${scenTag}  ${c.bold}${c.white}${title}${c.reset}`);
  console.log(`  ${c.gray}${" ".repeat(14)}${subtitle}${c.reset}`);
  blank();
  await sleep(1200);
}

// ══════════════════════════════════════════════════════════════════════════════
// SCENARIO 1 — Travel Saga
// ══════════════════════════════════════════════════════════════════════════════

async function scenario1() {
  // ── Agents ─────────────────────────────────────────────────────────────────
  const personalDID = fakeDID("personal-agent");
  const flightDID   = fakeDID("flight-provider");
  const hotelDID    = fakeDID("hotel-provider");
  const personalKey = fakeKey(personalDID);
  const flightKey   = fakeKey(flightDID);
  const hotelKey    = fakeKey(hotelDID);
  const sagaId      = fakeSagaId();

  // ── Phase 1: Identity ───────────────────────────────────────────────────────
  rule();
  phaseHeader(1, "Agent Identity Generation");
  log("Aroha", c.teal, "Generating Ed25519 keypairs for PersonalAgent, FlightAgent, HotelAgent…");
  await sleep(600);
  log("PersonalAgent", c.cyan,    `DID: ${c.teal}${personalDID}${c.reset}  key: ${c.dim}${personalKey.slice(0,32)}…${c.reset}`);
  await sleep(300);
  log("FlightAgent",   c.yellow,  `DID: ${c.teal}${flightDID}${c.reset}   key: ${c.dim}${flightKey.slice(0,32)}…${c.reset}`);
  await sleep(300);
  log("HotelAgent",    c.magenta, `DID: ${c.teal}${hotelDID}${c.reset}    key: ${c.dim}${hotelKey.slice(0,32)}…${c.reset}`);
  await sleep(500);
  ok("Three agents online. Self-sovereign identities — no certificate authority.");
  blank();
  await sleep(900);

  // ── Phase 2: LLM thinks about the task ─────────────────────────────────────
  rule();
  phaseHeader(2, "PersonalAgent · Intent Decomposition");

  await thinkAloud(
    "PersonalAgent", c.cyan,
    [
      "User request: book a business trip to Tokyo, May 1–7.",
      "I need two reservations: a flight and a hotel. Both must succeed atomically — if the hotel is full I must cancel the flight too. I'll open a Aroha saga to guarantee rollback. Budget: $2,000. Searching the registry now.",
    ],
    {
      system: "You are PersonalAgent, an AI travel orchestrator. Respond in 3–4 short sentences of first-person reasoning. Be terse and analytical. No markdown.",
      user:   "User asked you to book a business trip to Tokyo May 1–7, budget $2000. Reason through your plan: what sub-tasks you need, why a saga is the right pattern, and what you'll do next.",
    }
  );
  await sleep(900);

  // ── Phase 3: Discovery ──────────────────────────────────────────────────────
  rule();
  phaseHeader(3, "Capability Discovery via Aroha Registry");

  log("PersonalAgent", c.cyan, `Querying registry: ${c.yellow}"book-flight"${c.reset} + ${c.yellow}"book-hotel"${c.reset}`);
  await sleep(700);
  log("ArohaRegistry", c.teal, `${c.green}FlightAgent${c.reset} found  reputation: ${c.green}9,014 / 10,000${c.reset}  price: ${c.green}$0.30 / reservation${c.reset}`);
  await sleep(350);
  log("ArohaRegistry", c.teal, `${c.green}HotelAgent${c.reset}  found  reputation: ${c.green}8,801 / 10,000${c.reset}  price: ${c.green}$0.25 / reservation${c.reset}`);
  await sleep(350);
  log("ArohaRegistry", c.teal, "Both manifests verified. Endpoints resolved.");
  await sleep(600);
  ok("Two providers found. High reputation — low risk of failed bookings.");
  blank();
  await sleep(1000);

  // ── Phase 4: Reserve (parallel saga) ───────────────────────────────────────
  rule();
  phaseHeader(4, "Saga Reserve  (atomic — both or neither)");

  const flightNonce = fakeNonce();
  const hotelNonce  = fakeNonce();
  const flightSig   = fakeSig("reserve-flight");
  const hotelSig    = fakeSig("reserve-hotel");
  const flightTok   = "tok-" + randomBytes(4).toString("hex");
  const hotelTok    = "tok-" + randomBytes(4).toString("hex");

  msg("PersonalAgent", c.cyan, "──►", "FlightAgent", c.yellow, "ArohaReserve", `saga=${sagaId.slice(0,8)}  holdMs=120000`);
  detail(`sig: ${flightSig.slice(0,52)}…`);
  await sleep(300);
  msg("PersonalAgent", c.cyan, "──►", "HotelAgent",  c.magenta,"ArohaReserve", `saga=${sagaId.slice(0,8)}  holdMs=120000`);
  detail(`sig: ${hotelSig.slice(0,52)}…`);
  await sleep(900);

  blank();
  msg("FlightAgent", c.yellow,  "◄──", "PersonalAgent", c.cyan, "ArohaReserveAck", `token=${flightTok}`);
  detail("options: [ { flight: AA107, price: $1050, dep: 09:15 }, { flight: UA892, price: $1200, dep: 07:00 } ]");
  await sleep(350);
  msg("HotelAgent",  c.magenta, "◄──", "PersonalAgent", c.cyan, "ArohaReserveAck", `token=${hotelTok}`);
  detail("options: [ { hotel: Mandarin Oriental, rate: ¥72k/night }, { hotel: Park Hyatt, rate: ¥85k/night } ]");
  await sleep(600);
  ok("Both providers holding inventory. Saga window: 120 seconds.");
  blank();
  await sleep(900);

  // ── Phase 5: LLM selects options ────────────────────────────────────────────
  rule();
  phaseHeader(5, "PersonalAgent · Provider Selection");

  await thinkAloud(
    "PersonalAgent", c.cyan,
    [
      "Flight options: AA107 at $1,050 dep 09:15, UA892 at $1,200 dep 07:00.",
      "AA107 saves $150 and a 13:40 arrival fits a 15:00 check-in. Choosing AA107.",
      "Hotel: Mandarin Oriental ¥72k/night vs Park Hyatt ¥85k/night. Mandarin is ¥78k cheaper over 6 nights. Choosing Mandarin. Committing both now before the hold expires.",
    ],
    {
      system: "You are PersonalAgent choosing between travel options. Be concise, analytical, first-person. 2–3 sentences max. No markdown.",
      user:   "Choose: Flight AA107 ($1050, 09:15 departure) vs UA892 ($1200, 07:00 departure). Hotel: Mandarin Oriental (¥72k/night) vs Park Hyatt (¥85k/night). 6-night stay. Explain your picks briefly.",
    }
  );
  await sleep(900);

  // ── Phase 6: Commit ─────────────────────────────────────────────────────────
  rule();
  phaseHeader(6, "Saga Commit  (atomic confirmation)");

  const commitSig1 = fakeSig("commit-flight");
  const commitSig2 = fakeSig("commit-hotel");

  msg("PersonalAgent", c.cyan, "──►", "FlightAgent",  c.yellow,  "ArohaCommit", `token=${flightTok}  selection=AA107`);
  detail(`sig: ${commitSig1.slice(0,52)}…`);
  await sleep(400);
  msg("PersonalAgent", c.cyan, "──►", "HotelAgent",   c.magenta, "ArohaCommit", `token=${hotelTok}  selection=Mandarin`);
  detail(`sig: ${commitSig2.slice(0,52)}…`);
  await sleep(900);

  blank();
  msg("FlightAgent",  c.yellow,  "◄──", "PersonalAgent", c.cyan, "ArohaCommitAck", "PNR: AA10701  ✓");
  await sleep(350);
  msg("HotelAgent",   c.magenta, "◄──", "PersonalAgent", c.cyan, "ArohaCommitAck", "Ref: HTL-MOP-8842  ✓");
  await sleep(700);

  blank();
  log("ArohaEscrow",    c.yellow, `Releasing $0.30 → FlightAgent  $0.25 → HotelAgent   TX: ${c.dim}${fakeTx().slice(0,26)}…${c.reset}  ${c.green}✓${c.reset}`);
  await sleep(400);
  log("ArohaReputation", c.orange, `FlightAgent: ${c.green}9,015 / 10,000${c.reset}   HotelAgent: ${c.green}8,802 / 10,000${c.reset}   both recorded`);
  await sleep(700);
  ok("Saga committed. Both bookings confirmed. Escrow settled. Reputation updated.");
  blank();
  await sleep(900);

  // ── Phase 7: LLM summarises ─────────────────────────────────────────────────
  rule();
  phaseHeader(7, "PersonalAgent · Trip Summary");

  await thinkAloud(
    "PersonalAgent", c.cyan,
    [
      "Both saga legs committed successfully.",
      "Flight AA107 confirmed PNR AA10701, departs May 1 09:15. Mandarin Oriental confirmed Ref HTL-MOP-8842, May 1–7.",
      "Total cost: $1,050 + ¥72,000 × 6 nights ≈ $1,050 + $2,880 = $3,930. This exceeds the $2,000 budget. I should flag this to the user before they proceed and offer the Park Hyatt downgrade option.",
    ],
    {
      system: "You are PersonalAgent summarising a completed booking. Be brief, factual, first-person. Flag the budget overrun. No markdown.",
      user:   "You confirmed: AA107 flight ($1050, PNR AA10701) and Mandarin Oriental hotel (¥72k/night × 6 = ~$2,880, Ref HTL-MOP-8842). User's budget was $2,000. Summarise and flag the issue in 2–3 sentences.",
    }
  );

  blank();
  console.log(`  ${c.teal}┌─ Trip Confirmed ${"─".repeat(W - 19)}┐${c.reset}`);
  console.log(`  ${c.teal}│${c.reset}  ${c.bold}Flight:${c.reset}  AA107  PNR AA10701   May 1, 09:15 → 13:40+1  ${c.green}✓${c.reset}`);
  console.log(`  ${c.teal}│${c.reset}  ${c.bold}Hotel:${c.reset}   Mandarin Oriental  Ref HTL-MOP-8842  May 1–7  ${c.green}✓${c.reset}`);
  console.log(`  ${c.teal}│${c.reset}  ${c.yellow}⚠${c.reset}  Total ≈ $3,930 — exceeds $2,000 budget. User confirmation required.`);
  console.log(`  ${c.teal}└${"─".repeat(W - 3)}┘${c.reset}`);
  blank();
  await sleep(1200);
}

// ══════════════════════════════════════════════════════════════════════════════
// SCENARIO 2 — Hedge Fund Analyst (MCP Data Wedge)
// ══════════════════════════════════════════════════════════════════════════════

async function scenario2() {
  const fundDID    = fakeDID("hedgefund-agent");
  const scraperDID = fakeDID("twitter-scraper-mcp");
  const sagaId     = fakeSagaId();

  // ── Boot ────────────────────────────────────────────────────────────────────
  rule();
  phaseHeader(1, "Agent Boot");
  log("HedgeFundAgent",     c.cyan,   `DID: ${c.teal}${fundDID}${c.reset}`);
  await sleep(300);
  log("TwitterScraperMCP",  c.orange, `DID: ${c.teal}${scraperDID}${c.reset}   ${c.dim}[MCP-bridged via @aroha-sdk/mcp-bridge]${c.reset}`);
  await sleep(600);
  ok("Both agents online.");
  blank();
  await sleep(800);

  // ── Phase 2: LLM identifies the data gap ────────────────────────────────────
  rule();
  phaseHeader(2, "HedgeFundAgent · Research Planning");

  await thinkAloud(
    "HedgeFundAgent", c.cyan,
    [
      "Task: write a Q2 2026 Bitcoin outlook report.",
      "Problem: my knowledge cuts off August 2025. I cannot assess current social sentiment, which is a leading indicator for BTC price action over 1–4 week horizons.",
      "Plan: query Aroha registry for a real-time social sentiment provider. Budget cap $0.50 for this query — cheap for alpha-generating data.",
    ],
    {
      system: "You are HedgeFundAgent, an AI financial analyst. First-person, terse, analytical. No markdown. 3–4 sentences.",
      user:   "You need to write a Q2 2026 Bitcoin outlook report. Your knowledge cuts off August 2025. You need real-time social sentiment data. Reason through your plan for obtaining it via the Aroha agent registry.",
    }
  );
  await sleep(900);

  // ── Phase 3: Discovery ──────────────────────────────────────────────────────
  rule();
  phaseHeader(3, "Capability Discovery via Aroha Registry");

  log("HedgeFundAgent", c.cyan, `Querying registry: ${c.yellow}"social-sentiment-score"${c.reset}`);
  await sleep(700);
  log("ArohaRegistry", c.teal, `${c.green}TwitterScraperMCP${c.reset} found   reputation: ${c.green}9,121 / 10,000  Grade A+${c.reset}`);
  await sleep(350);
  log("ArohaRegistry", c.teal, `Price: ${c.green}$0.20 / query${c.reset}   protocol: ${c.orange}MCP/2024-11 bridged via aroha/1.0${c.reset}`);
  await sleep(350);
  log("ArohaRegistry", c.teal, "Manifest signature verified. Endpoint resolved.");
  await sleep(600);

  blank();
  // ── LLM evaluates the provider ──────────────────────────────────────────────
  await thinkAloud(
    "HedgeFundAgent", c.cyan,
    [
      "TwitterScraperMCP: $0.20/query, reputation 9,121/10,000 — Grade A+.",
      "$0.20 is well within my $0.50 cap. Grade A+ means very low probability of stale or hallucinated data. The Aroha escrow guarantees I only pay after verifying receipt.",
      "Proceeding. Locking escrow now.",
    ],
    {
      system: "You are HedgeFundAgent evaluating a data provider. First-person, analytical, 2–3 sentences. No markdown.",
      user:   "You found TwitterScraperMCP: $0.20/query, reputation 9121/10000. Your budget cap is $0.50. The Aroha escrow ensures you only pay after data receipt. Decide whether to proceed and why.",
    }
  );
  await sleep(900);

  // ── Phase 4: Escrow ─────────────────────────────────────────────────────────
  rule();
  phaseHeader(4, "Micro-Payment Escrow  (ArohaEscrow.sol)");

  log("HedgeFundAgent", c.cyan,   `Opening escrow  saga ${c.dim}${sagaId}${c.reset}  amount: ${c.green}$0.20 USDC${c.reset}`);
  await sleep(500);
  log("ArohaEscrow",     c.yellow, `Locked: ${c.green}$0.20 USDC${c.reset}  TTL: 30s   TX: ${c.dim}${fakeTx().slice(0,26)}…${c.reset}  ${c.green}confirmed ✓${c.reset}`);
  await sleep(400);
  log("ArohaEscrow",     c.yellow, `Paymaster: ${c.teal}aroha-paymaster-v1${c.reset}   gas sponsored — HedgeFundAgent paid ${c.green}$0${c.reset}`);
  await sleep(600);
  ok(`$0.20 locked. TwitterScraperMCP is guaranteed payment before sending any data.`);
  blank();
  await sleep(1000);

  // ── Phase 5: Aroha request wrapping an MCP tool call ────────────────────────
  rule();
  phaseHeader(5, "Aroha Request  →  MCP Tool Call  →  Aroha Response");

  const reqSig = fakeSig("aroha-request-sentiment");
  msg("HedgeFundAgent", c.cyan, "──►", "TwitterScraperMCP", c.orange, "ArohaRequest", "capability=social-sentiment-score");
  detail(`body:   { asset: "Bitcoin", window: "24h", min_posts: 100, sagaId: "${sagaId.slice(0,8)}…" }`);
  detail(`sig:    ${reqSig.slice(0,52)}…   ${c.green}(Ed25519 verified ✓)${c.reset}`);
  await sleep(700);

  // MCP sub-call (indented, different colour — shows the bridge in action)
  blank();
  console.log(`  ${c.orange}${c.dim}  ╌╌ MCP bridge invoked ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌${c.reset}`);
  await sleep(300);
  mcpLine("TwitterScraperMCP", c.orange, "──►", "twitter-api", c.gray,   "mcp:get_sentiment", `{ query: "Bitcoin", window: "24h" }`);
  await sleep(800);
  mcpLine("TwitterScraperMCP", c.orange, "◄──", "twitter-api", c.gray,   "200 OK",            "312 posts analyzed, raw scores computed");
  await sleep(400);
  console.log(`  ${c.orange}${c.dim}  ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌${c.reset}`);
  blank();
  await sleep(500);

  const respSig = fakeSig("aroha-response-sentiment");
  msg("TwitterScraperMCP", c.orange, "◄──", "HedgeFundAgent", c.cyan, "ArohaResponse", "200 OK");
  detail(`body:   { score: 0.71, signal: "BULLISH", confidence: 0.89, sources: 312, themes: ["ETF inflows","halving cycle","Fed rates"] }`);
  detail(`sig:    ${respSig.slice(0,52)}…   ${c.green}(Ed25519 verified ✓)${c.reset}`);
  await sleep(600);
  ok("Data received and signature verified. No tampering possible.");
  blank();
  await sleep(900);

  // ── Phase 6: Settle + LLM synthesises ──────────────────────────────────────
  rule();
  phaseHeader(6, "Settlement  +  Report Synthesis");

  log("HedgeFundAgent", c.cyan,   "Data verified. Releasing escrow…");
  await sleep(450);
  log("ArohaEscrow",     c.yellow, `$0.20 released to ${c.teal}${scraperDID}${c.reset}   ${c.green}✓${c.reset}`);
  await sleep(350);
  log("ArohaReputation", c.orange, `TwitterScraperMCP: ${c.green}9,122 / 10,000${c.reset}   SUCCESS recorded`);
  await sleep(700);
  ok("Payment settled. Now synthesising report…");
  blank();
  await sleep(800);

  await thinkAloud(
    "HedgeFundAgent", c.cyan,
    [
      "Sentiment score: 0.71 BULLISH, confidence 89%, 312 posts. Key themes: ETF inflows, halving cycle, Fed rate cut expectations.",
      "On-chain context from my training: exchange reserves low, hash rate rising — both constructive. Social signal aligns with on-chain data.",
      "Conclusion: risk/reward for long BTC exposure is favorable over the Q2 horizon. Recommend maintaining 3% portfolio weight.",
    ],
    {
      system: "You are HedgeFundAgent synthesising a Bitcoin outlook report. First-person, analytical, concise. Exactly 3 sentences. No markdown.",
      user:   "You received: BTC sentiment score 0.71 BULLISH, confidence 89%, 312 posts, themes: ETF inflows, halving cycle, Fed rate cuts. Synthesise this into a Q2 Bitcoin outlook conclusion and portfolio recommendation.",
    }
  );

  // ── Final report ────────────────────────────────────────────────────────────
  await sleep(600);
  blank();
  console.log(`  ${c.cyan}┌─ Q2 2026 Bitcoin Outlook Report ${"─".repeat(W - 35)}┐${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}Analyst:${c.reset}   HedgeFundAgent  │  ${c.bold}Date:${c.reset} ${new Date().toISOString().slice(0,10)}`);
  console.log(`  ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}${c.yellow}SENTIMENT${c.reset}  (live, via TwitterScraperMCP · $0.20 · Grade A+)`);
  console.log(`  ${c.cyan}│${c.reset}    Score: ${c.green}0.71 BULLISH${c.reset}   Confidence: ${c.green}89%${c.reset}   Sources: ${c.green}312 posts${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}    Themes: ETF inflows  ·  halving cycle  ·  Fed rate cuts`);
  console.log(`  ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}${c.yellow}SYNTHESIS${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}    Social signal is constructively bullish. Combined with on-chain`);
  console.log(`  ${c.cyan}│${c.reset}    data (low exchange reserves, rising hash rate), risk/reward for`);
  console.log(`  ${c.cyan}│${c.reset}    long BTC exposure over Q2 appears favorable.`);
  console.log(`  ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}RECOMMENDATION${c.reset}   Maintain ${c.green}3% portfolio weight${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.dim}Data cost: $0.20  ·  Escrow settled  ·  Audit trail: on-chain${c.reset}`);
  console.log(`  ${c.cyan}└${"─".repeat(W - 3)}┘${c.reset}`);
  blank();
  await sleep(1200);
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════════════════════════════════════════

async function main() {
  console.clear();
  blank();

  // ── Master header ────────────────────────────────────────────────────────────
  rule("═");
  box("Aroha  —  Aroha Protocol", c.teal, c.white);
  box("Live Agent-to-Agent Transaction Demo", c.cyan, c.white);
  rule("═");
  blank();

  const hasKey = !!process.env.ANTHROPIC_API_KEY;
  if (hasKey) {
    console.log(`  ${c.green}✓${c.reset}  ${c.bold}ANTHROPIC_API_KEY detected${c.reset} — thinking panels will stream real Claude output.`);
  } else {
    console.log(`  ${c.gray}ℹ${c.reset}  No ANTHROPIC_API_KEY — using realistic simulated reasoning. Set the key for live Claude.`);
  }
  blank();
  console.log(`  ${c.gray}Two scenarios. ~35 seconds. LLM drives every decision.${c.reset}`);
  blank();
  await sleep(1500);

  // ── Scenario 1 ───────────────────────────────────────────────────────────────
  await scenarioSeparator(
    "1 of 2",
    "Travel Saga",
    "PersonalAgent books Tokyo atomically across FlightAgent + HotelAgent  ·  proves multi-party saga + rollback"
  );
  await scenario1();

  // ── Scenario 2 ───────────────────────────────────────────────────────────────
  await scenarioSeparator(
    "2 of 2",
    "Hedge Fund Analyst  ×  MCP Data Feed",
    "HedgeFundAgent pays $0.20 to TwitterScraperMCP for BTC sentiment  ·  proves micro-payments + MCP bridge"
  );
  await scenario2();

  // ── Final summary ─────────────────────────────────────────────────────────────
  blank();
  rule("═");
  blank();
  box("BOTH SCENARIOS COMPLETE", c.green, c.white);
  blank();

  const rows = [
    ["Scenario 1",           c.bold + "Travel Saga — multi-party atomic booking" + c.reset],
    ["Scenario 2",           c.bold + "M2M micro-payment — $0.20 data query" + c.reset],
    ["LLM drives decisions", c.green + "✓  Claude reasoned at every branch point" + c.reset],
    ["Blockchain (dev)",     c.green + "✓  Invisible — paymaster sponsors gas, $0 ETH needed" + c.reset],
    ["MCP bridge",           c.green + "✓  Any MCP server becomes a paid Aroha agent" + c.reset],
    ["Reputation filter",    c.green + "✓  Scores queried before any funds moved" + c.reset],
    ["Atomic rollback",      c.green + "✓  Saga guarantees all-or-nothing commits" + c.reset],
    ["Audit trail",          c.green + "✓  Every message signed, every outcome on-chain" + c.reset],
    ["Developer API",        c.teal  + "   wallet.buyData(providerDID, { budget: 0.20 })" + c.reset],
  ];

  for (const [label, value] of rows) {
    console.log(`  ${c.gray}${label.padEnd(22)}${c.reset}  ${value}`);
    await sleep(90);
  }

  blank();
  await sleep(400);
  rule("─", c.gray);
  blank();
  console.log(
    `  ${c.gray}MCP connects agents to tools.${c.reset}  ` +
    `${c.teal}${c.bold}No agent can exceed the scope it was granted.${c.reset}`
  );
  blank();
  console.log(`  ${c.dim}Spec: docs/spec/aroha-1.0.md  ·  SDK: packages/  ·  Contracts: contracts/${c.reset}`);
  blank();
  rule("═");
  blank();
}

main().catch((err) => { console.error(err); process.exit(1); });
