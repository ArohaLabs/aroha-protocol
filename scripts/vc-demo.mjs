// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Protocol — multi-agent demo server (vc-demo)
 *
 * Two end-to-end demo scenarios:
 *
 * Scenario 1 — Travel Booking (4 agents)
 *   Personal, Flight, Hotel, Payment agents book a Tokyo business trip
 *   atomically. Real Ed25519 signed Aroha envelopes. Human-in-the-loop
 *   flight/hotel selection and payment confirmation.
 *
 * Scenario 2 — Enterprise IT: Incident Response (3 agents)
 *   DevOps Agent detects an API latency spike. Uses InMemoryRegistry
 *   (no blockchain) to discover GitHub and Jira agents. Atomically
 *   creates a Jira incident ticket + GitHub tracking issue in a saga.
 *   HITL approval gate pauses execution before committing a production
 *   rollback — human must click Approve before anything commits.
 *
 * Both scenarios use:
 *   - Real Ed25519-signed Aroha envelopes
 *   - Saga Reserve → Commit (or Cancel on rejection)
 *   - SSE real-time streaming to browser
 *   - Post-execution decision explorer
 *
 * Usage:
 *   node scripts/vc-demo.mjs
 *   PORT=3040 node scripts/vc-demo.mjs
 */

import { createServer } from "http";
import { randomUUID } from "crypto";
import { generateDID, buildEnvelope, validateEnvelope } from "@aroha-sdk/core";

const PORT = parseInt(process.env.PORT ?? "3040");

// ─── Agent boot ───────────────────────────────────────────────────────────────

console.log("[VC-Demo] Generating agent identities…");
const [personal, flight, hotel, payment, devops, githubAgent, jiraAgent] = await Promise.all([
  generateDID("personal-agent",  `http://localhost:${PORT}/aroha/v1/personal`),
  generateDID("flight-agent",    `http://localhost:${PORT}/aroha/v1/flight`),
  generateDID("hotel-agent",     `http://localhost:${PORT}/aroha/v1/hotel`),
  generateDID("payment-agent",   `http://localhost:${PORT}/aroha/v1/payment`),
  generateDID("devops-agent",    `http://localhost:${PORT}/aroha/v1/devops`),
  generateDID("github-agent",    `http://localhost:${PORT}/aroha/v1/github`),
  generateDID("jira-agent",      `http://localhost:${PORT}/aroha/v1/jira`),
]);
console.log("[VC-Demo] Personal :", personal.did);
console.log("[VC-Demo] Flight   :", flight.did);
console.log("[VC-Demo] Hotel    :", hotel.did);
console.log("[VC-Demo] Payment  :", payment.did);
console.log("[VC-Demo] DevOps   :", devops.did);
console.log("[VC-Demo] GitHub   :", githubAgent.did);
console.log("[VC-Demo] Jira     :", jiraAgent.did);

const knownKeys = new Map([
  [personal.did,    personal.publicKey],
  [flight.did,      flight.publicKey],
  [hotel.did,       hotel.publicKey],
  [payment.did,     payment.publicKey],
  [devops.did,      devops.publicKey],
  [githubAgent.did, githubAgent.publicKey],
  [jiraAgent.did,   jiraAgent.publicKey],
]);

// ─── Workflow state machine ───────────────────────────────────────────────────

let workflowState = "idle";

const messageLog   = [];
const agentDecisions = {
  personal: [], flight: [], hotel: [], payment: [],
  devops: [], github: [], jira: [],
};
const sagaTokens = {};

let humanResolvers = {};
let selectedFlight = null;
let selectedHotel  = null;
let sseClients     = [];

// ─── Enterprise scenario state ────────────────────────────────────────────────

let enterpriseWorkflowState = "idle";
const enterpriseMessageLog  = [];
const enterpriseDecisions   = { devops: [], github: [], jira: [] };
let enterpriseHumanResolvers = {};

// ─── Mock data ────────────────────────────────────────────────────────────────

const FLIGHTS = [
  { id: "F001", airline: "ANA",    flight: "NH 175",  depart: "08:05", arrive: "10:50+1", class: "Business", price: 2150, stops: "Non-stop", duration: "14h 45m", seats: 4 },
  { id: "F002", airline: "JAL",    flight: "JL 061",  depart: "11:30", arrive: "14:15+1", class: "Business", price: 2280, stops: "Non-stop", duration: "14h 45m", seats: 2 },
  { id: "F003", airline: "United", flight: "UA 837",  depart: "14:50", arrive: "18:30+1", class: "Business", price: 1890, stops: "1 stop",   duration: "17h 40m", seats: 6 },
];

const HOTELS = [
  { id: "H001", name: "Park Hyatt Tokyo",    stars: 5, area: "Shinjuku",   price: 620, rating: 4.9, amenities: ["Sky Lounge","Spa","Michelin Restaurant"] },
  { id: "H002", name: "Andaz Tokyo",         stars: 5, area: "Toranomon",  price: 480, rating: 4.7, amenities: ["Rooftop Bar","Fitness Center","Club Lounge"] },
  { id: "H003", name: "The Peninsula Tokyo", stars: 5, area: "Marunouchi", price: 720, rating: 4.9, amenities: ["Fleet of Rolls Royce","Pool","Afternoon Tea"] },
];

const CARD = { number: "4242 4242 4242 4242", expiry: "04/28", cvv: "123", holder: "ALEX CHEN", type: "Visa Infinite" };

// ─── SSE helpers ─────────────────────────────────────────────────────────────

function broadcast(type, data) {
  const payload = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  sseClients.forEach(res => { try { res.write(payload); } catch {} });
}

function step(id, label, agent, status = "running") {
  broadcast("step", { id, label, agent, status });
}

function msg(from, to, msgType, summary, envelope = null) {
  const entry = { id: randomUUID(), ts: Date.now(), from, to, msgType, summary, envelope };
  messageLog.push(entry);
  broadcast("message", entry);
}

function decision(agent, action, detail, data = {}) {
  const entry = { id: randomUUID(), ts: Date.now(), action, detail, ...data };
  agentDecisions[agent].push(entry);
  broadcast("decision", { agent, ...entry });
}

function waitForHuman(step) {
  return new Promise(resolve => { humanResolvers[step] = resolve; });
}

// ─── Core workflow ────────────────────────────────────────────────────────────

async function runWorkflow() {
  try {
    workflowState = "intent";
    broadcast("state", { state: workflowState });

    // ── Step 0: Intent parsed ─────────────────────────────────────────────────
    step("s0", "Parse intent", "personal", "running");
    await sleep(800);
    const intent = { destination: "Tokyo", dates: "May 1–7, 2026", travelers: 1, class: "Business", budget: 8000 };
    decision("personal", "Intent decomposed", "Tokyo business trip May 1–7", { intent });
    step("s0", "Parse intent", "personal", "done");

    // ── Step 1: Discover agents ───────────────────────────────────────────────
    step("s1", "Discover agents", "personal", "running");
    await sleep(600);
    const sagaId = randomUUID();
    const flightQuery = await buildEnvelope(
      "ArohaRequest", personal.did, flight.did,
      { capability: "discover-agents", params: { capability: "book-flight" } },
      sagaId, personal.privateKey
    );
    msg("personal", "registry", "ArohaRequest", "queryByCapability('book-flight')", flightQuery);
    await sleep(400);
    msg("registry", "personal", "ArohaResponse", `Found: flight-agent (${flight.did.slice(0,20)}…), 2 others`);
    decision("personal", "Agents discovered", `Flight: ${flight.did.slice(0,26)}…  Hotel: ${hotel.did.slice(0,26)}…  Payment: ${payment.did.slice(0,26)}…`);
    step("s1", "Discover agents", "personal", "done");

    // ── Step 2: Search flights (parallel) ────────────────────────────────────
    workflowState = "searching";
    broadcast("state", { state: workflowState });
    step("s2", "Search flights", "flight", "running");

    const flightReq = await buildEnvelope(
      "ArohaRequest", personal.did, flight.did,
      { capability: "search-flights", params: { from: "JFK", to: "NRT", date: "2026-05-01", class: "Business", pax: 1 } },
      sagaId, personal.privateKey
    );
    msg("personal", "flight", "ArohaRequest", "search-flights JFK→NRT May 1 Business", flightReq);
    await sleep(1200);

    const flightResp = await buildEnvelope(
      "ArohaResponse", flight.did, personal.did,
      { capability: "search-flights", result: { flights: FLIGHTS } },
      sagaId, flight.privateKey
    );
    msg("flight", "personal", "ArohaResponse", `Returning ${FLIGHTS.length} flight options`, flightResp);
    decision("flight", "Inventory queried", `ANA $2,150 · JAL $2,280 · United $1,890`, { flights: FLIGHTS });
    step("s2", "Search flights", "flight", "done");

    // ── Step 3: Human selects flight ─────────────────────────────────────────
    workflowState = "select_flight";
    broadcast("state", { state: workflowState });
    step("s3", "Select flight", "personal", "waiting");
    broadcast("human_input", { step: "flight", flights: FLIGHTS });

    selectedFlight = await waitForHuman("flight");
    decision("personal", "Human selected flight", `${selectedFlight.airline} ${selectedFlight.flight} — $${selectedFlight.price}`, { flight: selectedFlight });
    step("s3", "Select flight", "personal", "done");

    // ── Step 4: Search hotels (parallel while flight decided) ─────────────────
    step("s4", "Search hotels", "hotel", "running");
    const hotelReq = await buildEnvelope(
      "ArohaRequest", personal.did, hotel.did,
      { capability: "search-hotels", params: { city: "Tokyo", checkIn: "2026-05-01", checkOut: "2026-05-07", guests: 1, stars: 5 } },
      sagaId, personal.privateKey
    );
    msg("personal", "hotel", "ArohaRequest", "search-hotels Tokyo May 1–7 5-star", hotelReq);
    await sleep(900);
    const hotelResp = await buildEnvelope(
      "ArohaResponse", hotel.did, personal.did,
      { capability: "search-hotels", result: { hotels: HOTELS } },
      sagaId, hotel.privateKey
    );
    msg("hotel", "personal", "ArohaResponse", `Returning ${HOTELS.length} hotel options`, hotelResp);
    decision("hotel", "Availability queried", `Park Hyatt $620/n · Andaz $480/n · Peninsula $720/n`, { hotels: HOTELS });
    step("s4", "Search hotels", "hotel", "done");

    // ── Step 5: Human selects hotel ───────────────────────────────────────────
    workflowState = "select_hotel";
    broadcast("state", { state: workflowState });
    step("s5", "Select hotel", "personal", "waiting");
    broadcast("human_input", { step: "hotel", hotels: HOTELS });

    selectedHotel = await waitForHuman("hotel");
    const nights = 6;
    selectedHotel.totalPrice = selectedHotel.price * nights;
    decision("personal", "Human selected hotel", `${selectedHotel.name} — $${selectedHotel.totalPrice} (${nights} nights)`, { hotel: selectedHotel });
    step("s5", "Select hotel", "personal", "done");

    // ── Step 6: Payment confirmation ──────────────────────────────────────────
    workflowState = "payment";
    broadcast("state", { state: workflowState });
    step("s6", "Confirm payment", "payment", "waiting");
    const totalAmount = selectedFlight.price + selectedHotel.totalPrice;
    broadcast("human_input", { step: "payment", flight: selectedFlight, hotel: selectedHotel, total: totalAmount, card: CARD });

    await waitForHuman("payment");
    decision("payment", "Payment authorized", `$${totalAmount.toLocaleString()} charged to Visa •••• 4242`, { amount: totalAmount });
    step("s6", "Confirm payment", "payment", "done");

    // ── Step 7: Saga Reserve (3-way parallel) ─────────────────────────────────
    workflowState = "reserving";
    broadcast("state", { state: workflowState });
    step("s7", "Reserve all (saga)", "personal", "running");

    // Reserve flight
    const flightReserve = await buildEnvelope(
      "ArohaReserve", personal.did, flight.did,
      { capability: "book-flight", params: { flightId: selectedFlight.id, pax: 1 }, holdDurationMs: 120000 },
      sagaId, personal.privateKey
    );
    msg("personal", "flight", "ArohaReserve", `Hold ${selectedFlight.flight} for 120s`, flightReserve);

    // Reserve hotel
    const hotelReserve = await buildEnvelope(
      "ArohaReserve", personal.did, hotel.did,
      { capability: "book-hotel", params: { hotelId: selectedHotel.id, checkIn: "2026-05-01", checkOut: "2026-05-07" }, holdDurationMs: 120000 },
      sagaId, personal.privateKey
    );
    msg("personal", "hotel", "ArohaReserve", `Hold ${selectedHotel.name} May 1–7 for 120s`, hotelReserve);

    // Reserve payment
    const payReserve = await buildEnvelope(
      "ArohaReserve", personal.did, payment.did,
      { capability: "hold-payment", params: { amount: selectedFlight.price + selectedHotel.totalPrice, currency: "USD", cardToken: "tok_visa_4242" }, holdDurationMs: 120000 },
      sagaId, personal.privateKey
    );
    msg("personal", "payment", "ArohaReserve", `Hold $${(selectedFlight.price + selectedHotel.totalPrice).toLocaleString()} for 120s`, payReserve);

    await sleep(1400);

    sagaTokens.flight  = `FLT-${randomUUID().slice(0, 8).toUpperCase()}`;
    sagaTokens.hotel   = `HTL-${randomUUID().slice(0, 8).toUpperCase()}`;
    sagaTokens.payment = `PAY-${randomUUID().slice(0, 8).toUpperCase()}`;

    const flightAck = await buildEnvelope(
      "ArohaReserveAck", flight.did, personal.did,
      { reservationToken: sagaTokens.flight, expiresAt: new Date(Date.now() + 120000).toISOString() },
      sagaId, flight.privateKey
    );
    msg("flight", "personal", "ArohaReserveAck", `Token: ${sagaTokens.flight}`, flightAck);
    decision("flight", "Reservation held", `Token ${sagaTokens.flight} — seat locked for 120s`);

    const hotelAck = await buildEnvelope(
      "ArohaReserveAck", hotel.did, personal.did,
      { reservationToken: sagaTokens.hotel, expiresAt: new Date(Date.now() + 120000).toISOString() },
      sagaId, hotel.privateKey
    );
    msg("hotel", "personal", "ArohaReserveAck", `Token: ${sagaTokens.hotel}`, hotelAck);
    decision("hotel", "Reservation held", `Token ${sagaTokens.hotel} — room locked for 120s`);

    const payAck = await buildEnvelope(
      "ArohaReserveAck", payment.did, personal.did,
      { reservationToken: sagaTokens.payment, expiresAt: new Date(Date.now() + 120000).toISOString() },
      sagaId, payment.privateKey
    );
    msg("payment", "personal", "ArohaReserveAck", `Token: ${sagaTokens.payment}`, payAck);
    decision("payment", "Funds held", `Token ${sagaTokens.payment} — $${(selectedFlight.price + selectedHotel.totalPrice).toLocaleString()} captured`);

    step("s7", "Reserve all (saga)", "personal", "done");

    // ── Step 8: Saga Commit (3-way parallel) ──────────────────────────────────
    workflowState = "committing";
    broadcast("state", { state: workflowState });
    step("s8", "Commit saga", "personal", "running");

    const pnr = "Aroha" + randomUUID().slice(0,6).toUpperCase();
    const confNo = "TKY" + randomUUID().slice(0,6).toUpperCase();
    const chargeId = "ch_" + randomUUID().slice(0,16);

    const fc = await buildEnvelope("ArohaCommit", personal.did, flight.did,   { reservationToken: sagaTokens.flight },  sagaId, personal.privateKey);
    msg("personal", "flight", "ArohaCommit", sagaTokens.flight, fc);
    const hc = await buildEnvelope("ArohaCommit", personal.did, hotel.did,    { reservationToken: sagaTokens.hotel },   sagaId, personal.privateKey);
    msg("personal", "hotel", "ArohaCommit", sagaTokens.hotel, hc);
    const pc = await buildEnvelope("ArohaCommit", personal.did, payment.did,  { reservationToken: sagaTokens.payment }, sagaId, personal.privateKey);
    msg("personal", "payment", "ArohaCommit", sagaTokens.payment, pc);

    await sleep(900);

    const fca = await buildEnvelope("ArohaCommitAck", flight.did,  personal.did, { reservationToken: sagaTokens.flight,  result: { pnr, seat: "5A", gate: "B22" } },                                              sagaId, flight.privateKey);
    msg("flight",  "personal", "ArohaCommitAck", `PNR: ${pnr} · Seat 5A`, fca);
    decision("flight", "Booking confirmed", `PNR: ${pnr} · Seat 5A · Gate B22`);

    const hca = await buildEnvelope("ArohaCommitAck", hotel.did,   personal.did, { reservationToken: sagaTokens.hotel,   result: { confirmationNo: confNo, room: "Park Suite 52F", earlyCheckin: true } },         sagaId, hotel.privateKey);
    msg("hotel",   "personal", "ArohaCommitAck", `Conf# ${confNo} · Park Suite 52F`, hca);
    decision("hotel", "Booking confirmed", `Confirmation: ${confNo} · Room: Park Suite 52F · Early check-in`);

    const pca = await buildEnvelope("ArohaCommitAck", payment.did, personal.did, { reservationToken: sagaTokens.payment, result: { chargeId, amount: selectedFlight.price + selectedHotel.totalPrice, currency: "USD" } }, sagaId, payment.privateKey);
    msg("payment", "personal", "ArohaCommitAck", `Charged $${(selectedFlight.price + selectedHotel.totalPrice).toLocaleString()} to Visa •••• 4242`, pca);
    decision("payment", "Payment captured", `$${(selectedFlight.price + selectedHotel.totalPrice).toLocaleString()} charged · Visa •••• 4242`);

    step("s8", "Commit saga", "personal", "done");

    // ── Done ──────────────────────────────────────────────────────────────────
    workflowState = "complete";
    broadcast("state", { state: workflowState });
    broadcast("complete", {
      summary: {
        flight: { airline: selectedFlight.airline, flightNo: selectedFlight.flight, depart: selectedFlight.depart, price: selectedFlight.price },
        hotel:  { name: selectedHotel.name, checkIn: "May 1", checkOut: "May 7", price: selectedHotel.totalPrice },
        total:  selectedFlight.price + selectedHotel.totalPrice,
        messages: messageLog.length,
        agents: 4,
      },
      decisions: agentDecisions,
    });
    console.log("[VC-Demo] Workflow complete.");
  } catch (err) {
    workflowState = "error";
    broadcast("state", { state: "error" });
    broadcast("error", { message: err.message });
    console.error("[VC-Demo] Workflow error:", err);
  }
}

// ─── Enterprise broadcast helpers ────────────────────────────────────────────

function estep(id, label, agent, status = "running") {
  broadcast("estep", { id, label, agent, status });
}

function emsg(from, to, msgType, summary, envelope = null) {
  const entry = { id: randomUUID(), ts: Date.now(), from, to, msgType, summary, envelope };
  enterpriseMessageLog.push(entry);
  broadcast("emessage", entry);
}

function edecision(agent, action, detail, data = {}) {
  const entry = { id: randomUUID(), ts: Date.now(), action, detail, ...data };
  enterpriseDecisions[agent].push(entry);
  broadcast("edecision", { agent, ...entry });
}

// ─── Enterprise workflow ──────────────────────────────────────────────────────

async function runEnterpriseWorkflow() {
  try {
    enterpriseWorkflowState = "intent";
    broadcast("estate", { state: enterpriseWorkflowState });

    // ── Step 0: Alert parsed ──────────────────────────────────────────────────
    estep("es0", "Alert received", "devops", "running");
    await sleep(700);
    const alert = { service: "checkout-service", metric: "p99_latency_ms", value: 3210, threshold: 2000, severity: "HIGH" };
    edecision("devops", "Alert parsed", `checkout-service p99 latency: 3,210ms (threshold: 2,000ms) — severity HIGH`, { alert });
    estep("es0", "Alert received", "devops", "done");

    // ── Step 1: Discover via InMemoryRegistry ─────────────────────────────────
    estep("es1", "Discover agents (InMemoryRegistry)", "devops", "running");
    await sleep(500);
    const regQuery = await buildEnvelope(
      "ArohaRequest", devops.did, "did:aroha:registry",
      { capability: "discover-agents", params: { capabilityIds: ["create-issue", "transition-issue"] } },
      randomUUID(), devops.privateKey
    );
    emsg("devops", "registry", "ArohaRequest", "queryByCapability(['create-issue', 'transition-issue'])", regQuery);
    await sleep(300);
    emsg("registry", "devops", "ArohaResponse", `Found: jira-agent (${jiraAgent.did.slice(0,22)}…), github-agent (${githubAgent.did.slice(0,22)}…) — InMemoryRegistry (no blockchain)`);
    edecision("devops", "Agents discovered", `Jira: ${jiraAgent.did.slice(0,28)}…  GitHub: ${githubAgent.did.slice(0,28)}…`, { note: "InMemoryRegistry — no blockchain required" });
    estep("es1", "Discover agents (InMemoryRegistry)", "devops", "done");

    // ── Step 2: Reserve Jira ticket + GitHub issue (parallel) ─────────────────
    enterpriseWorkflowState = "reserving";
    broadcast("estate", { state: enterpriseWorkflowState });
    estep("es2", "Reserve: Jira incident + GitHub issue (saga)", "devops", "running");

    const sagaId = randomUUID();

    const jiraReserve = await buildEnvelope(
      "ArohaReserve", devops.did, jiraAgent.did,
      { capability: "create-issue", params: { projectKey: "OPS", summary: `[P0] checkout-service latency spike — ${new Date().toISOString()}`, issueType: "Incident", priority: "Critical" }, holdDurationMs: 120000 },
      sagaId, devops.privateKey
    );
    emsg("devops", "jira", "ArohaReserve", "Hold: create OPS incident ticket for 120s", jiraReserve);

    const githubReserve = await buildEnvelope(
      "ArohaReserve", devops.did, githubAgent.did,
      { capability: "create-issue", params: { owner: "acme-corp", repo: "checkout-service", title: `[Incident] p99 latency spike ${new Date().toISOString().slice(0,10)}`, labels: ["incident", "production"] }, holdDurationMs: 120000 },
      sagaId, devops.privateKey
    );
    emsg("devops", "github", "ArohaReserve", "Hold: create GitHub incident issue for 120s", githubReserve);

    await sleep(900);

    const jiraToken  = `JIRA-${randomUUID().slice(0,8).toUpperCase()}`;
    const githubToken = `GH-${randomUUID().slice(0,8).toUpperCase()}`;

    const jiraAck = await buildEnvelope(
      "ArohaReserveAck", jiraAgent.did, devops.did,
      { reservationToken: jiraToken, expiresAt: new Date(Date.now() + 120000).toISOString() },
      sagaId, jiraAgent.privateKey
    );
    emsg("jira", "devops", "ArohaReserveAck", `Token: ${jiraToken}`, jiraAck);
    edecision("jira", "Reservation held", `Token ${jiraToken} — create-issue reserved for 120s`);

    const githubAck = await buildEnvelope(
      "ArohaReserveAck", githubAgent.did, devops.did,
      { reservationToken: githubToken, expiresAt: new Date(Date.now() + 120000).toISOString() },
      sagaId, githubAgent.privateKey
    );
    emsg("github", "devops", "ArohaReserveAck", `Token: ${githubToken}`, githubAck);
    edecision("github", "Reservation held", `Token ${githubToken} — create-issue reserved for 120s`);

    estep("es2", "Reserve: Jira incident + GitHub issue (saga)", "devops", "done");

    // ── Step 3: HITL — Approve rollback ───────────────────────────────────────
    enterpriseWorkflowState = "awaiting_approval";
    broadcast("estate", { state: enterpriseWorkflowState });
    estep("es3", "Human approval: rollback to v2.1.3", "devops", "waiting");
    broadcast("enterprise_human_input", { step: "rollback", alert, rollbackVersion: "v2.1.3" });

    const rollbackApproved = await new Promise(resolve => { enterpriseHumanResolvers["rollback"] = resolve; });

    if (!rollbackApproved) {
      // Rejected — compensate
      edecision("devops", "Rollback REJECTED", "Human rejected the rollback — compensating saga");
      const jiraCancel = await buildEnvelope("ArohaCancel", devops.did, jiraAgent.did, { reservationToken: jiraToken, reason: "Human rejected rollback" }, sagaId, devops.privateKey);
      emsg("devops", "jira", "ArohaCancel", `Cancel ${jiraToken}`, jiraCancel);
      const githubCancel = await buildEnvelope("ArohaCancel", devops.did, githubAgent.did, { reservationToken: githubToken, reason: "Human rejected rollback" }, sagaId, devops.privateKey);
      emsg("devops", "github", "ArohaCancel", `Cancel ${githubToken}`, githubCancel);
      estep("es3", "Human approval: rollback to v2.1.3", "devops", "done");
      enterpriseWorkflowState = "rejected";
      broadcast("estate", { state: "rejected" });
      broadcast("enterprise_complete", { approved: false, decisions: enterpriseDecisions });
      return;
    }

    edecision("devops", "Rollback APPROVED", "Human approved rollback to v2.1.3 — proceeding to commit");
    estep("es3", "Human approval: rollback to v2.1.3", "devops", "done");

    // ── Step 4: Commit saga ───────────────────────────────────────────────────
    enterpriseWorkflowState = "committing";
    broadcast("estate", { state: enterpriseWorkflowState });
    estep("es4", "Commit saga: Jira + GitHub atomically", "devops", "running");

    const jiraCommit = await buildEnvelope("ArohaCommit", devops.did, jiraAgent.did, { reservationToken: jiraToken }, sagaId, devops.privateKey);
    emsg("devops", "jira", "ArohaCommit", jiraToken, jiraCommit);
    const githubCommit = await buildEnvelope("ArohaCommit", devops.did, githubAgent.did, { reservationToken: githubToken }, sagaId, devops.privateKey);
    emsg("devops", "github", "ArohaCommit", githubToken, githubCommit);

    await sleep(800);

    const jiraKey    = `OPS-${Math.floor(Math.random() * 900 + 100)}`;
    const githubNum  = Math.floor(Math.random() * 900 + 100);

    const jiraCa = await buildEnvelope("ArohaCommitAck", jiraAgent.did, devops.did, { reservationToken: jiraToken, result: { key: jiraKey, url: `https://acme.atlassian.net/browse/${jiraKey}`, status: "Open" } }, sagaId, jiraAgent.privateKey);
    emsg("jira", "devops", "ArohaCommitAck", `Jira ticket created: ${jiraKey}`, jiraCa);
    edecision("jira", "Ticket created", `${jiraKey} — [P0] checkout-service latency spike`);

    const ghCa = await buildEnvelope("ArohaCommitAck", githubAgent.did, devops.did, { reservationToken: githubToken, result: { number: githubNum, url: `https://github.com/acme-corp/checkout-service/issues/${githubNum}` } }, sagaId, githubAgent.privateKey);
    emsg("github", "devops", "ArohaCommitAck", `GitHub issue created: #${githubNum}`, ghCa);
    edecision("github", "Issue created", `#${githubNum} — [Incident] p99 latency spike · labels: incident, production`);

    estep("es4", "Commit saga: Jira + GitHub atomically", "devops", "done");

    // ── Done ──────────────────────────────────────────────────────────────────
    enterpriseWorkflowState = "complete";
    broadcast("estate", { state: "ecomplete" });
    broadcast("enterprise_complete", {
      approved: true,
      summary: {
        jiraKey, githubIssue: githubNum,
        rollbackVersion: "v2.1.3",
        messages: enterpriseMessageLog.length,
        agents: 3,
        registryType: "InMemoryRegistry (no blockchain)",
      },
      decisions: enterpriseDecisions,
    });
    console.log("[VC-Demo] Enterprise workflow complete.");
  } catch (e) {
    enterpriseWorkflowState = "error";
    broadcast("estate", { state: "error" });
    console.error("[VC-Demo] Enterprise workflow error:", e);
  }
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // SSE stream
  if (url.pathname === "/api/stream") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Connection": "keep-alive", "Access-Control-Allow-Origin": "*" });
    res.write(": ok\n\n");
    sseClients.push(res);
    req.on("close", () => { sseClients = sseClients.filter(c => c !== res); });
    return;
  }

  // Start workflow
  if (url.pathname === "/api/start" && req.method === "POST") {
    if (workflowState !== "idle") {
      // Reset for re-run
      workflowState = "idle";
      messageLog.length = 0;
      agentDecisions.personal.length = 0;
      agentDecisions.flight.length   = 0;
      agentDecisions.hotel.length    = 0;
      agentDecisions.payment.length  = 0;
      humanResolvers = {};
      selectedFlight = null;
      selectedHotel  = null;
    }
    res.writeHead(200, jsonHeaders());
    res.end(JSON.stringify({ ok: true }));
    runWorkflow();
    return;
  }

  // Human selects flight
  if (url.pathname === "/api/select/flight" && req.method === "POST") {
    collectBody(req, body => {
      const { flightId } = JSON.parse(body);
      const f = FLIGHTS.find(x => x.id === flightId);
      if (f && humanResolvers["flight"]) {
        humanResolvers["flight"](f);
        delete humanResolvers["flight"];
        res.writeHead(200, jsonHeaders());
        res.end(JSON.stringify({ ok: true, flight: f }));
      } else {
        res.writeHead(400, jsonHeaders());
        res.end(JSON.stringify({ error: "not waiting for flight selection" }));
      }
    });
    return;
  }

  // Human selects hotel
  if (url.pathname === "/api/select/hotel" && req.method === "POST") {
    collectBody(req, body => {
      const { hotelId } = JSON.parse(body);
      const h = HOTELS.find(x => x.id === hotelId);
      if (h && humanResolvers["hotel"]) {
        humanResolvers["hotel"](h);
        delete humanResolvers["hotel"];
        res.writeHead(200, jsonHeaders());
        res.end(JSON.stringify({ ok: true, hotel: h }));
      } else {
        res.writeHead(400, jsonHeaders());
        res.end(JSON.stringify({ error: "not waiting for hotel selection" }));
      }
    });
    return;
  }

  // Human confirms payment
  if (url.pathname === "/api/confirm/payment" && req.method === "POST") {
    if (humanResolvers["payment"]) {
      humanResolvers["payment"](true);
      delete humanResolvers["payment"];
      res.writeHead(200, jsonHeaders());
      res.end(JSON.stringify({ ok: true }));
    } else {
      res.writeHead(400, jsonHeaders());
      res.end(JSON.stringify({ error: "not waiting for payment" }));
    }
    return;
  }

  // Start enterprise workflow
  if (url.pathname === "/api/enterprise/start" && req.method === "POST") {
    enterpriseWorkflowState = "idle";
    enterpriseMessageLog.length = 0;
    enterpriseDecisions.devops.length = 0;
    enterpriseDecisions.github.length = 0;
    enterpriseDecisions.jira.length   = 0;
    enterpriseHumanResolvers = {};
    res.writeHead(200, jsonHeaders());
    res.end(JSON.stringify({ ok: true }));
    runEnterpriseWorkflow();
    return;
  }

  // Enterprise HITL: approve or reject rollback
  if (url.pathname === "/api/enterprise/approve" && req.method === "POST") {
    collectBody(req, body => {
      const { approved } = JSON.parse(body);
      if (enterpriseHumanResolvers["rollback"]) {
        enterpriseHumanResolvers["rollback"](!!approved);
        delete enterpriseHumanResolvers["rollback"];
        res.writeHead(200, jsonHeaders());
        res.end(JSON.stringify({ ok: true }));
      } else {
        res.writeHead(400, jsonHeaders());
        res.end(JSON.stringify({ error: "not waiting for rollback approval" }));
      }
    });
    return;
  }

  // Message log
  if (url.pathname === "/api/log") {
    res.writeHead(200, jsonHeaders());
    res.end(JSON.stringify(messageLog));
    return;
  }

  // Agent decisions
  if (url.pathname === "/api/decisions") {
    res.writeHead(200, jsonHeaders());
    res.end(JSON.stringify(agentDecisions));
    return;
  }

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
    res.end();
    return;
  }

  // Main UI
  if (url.pathname === "/" || url.pathname === "/index.html") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(HTML);
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`\n[VC-Demo] Ready → http://localhost:${PORT}\n`);
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function jsonHeaders() { return { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }; }
function collectBody(req, cb) {
  let data = "";
  req.on("data", c => data += c);
  req.on("end", () => cb(data));
}

// ─── HTML UI ──────────────────────────────────────────────────────────────────

const HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aroha Protocol — Live Demo</title>
<style>
  :root {
    --bg: #0a0e1a;
    --surface: #111827;
    --surface2: #1a2236;
    --border: #1e2d45;
    --accent: #3b82f6;
    --accent2: #8b5cf6;
    --green: #10b981;
    --yellow: #f59e0b;
    --red: #ef4444;
    --text: #e2e8f0;
    --muted: #64748b;
    --personal: #3b82f6;
    --flight: #8b5cf6;
    --hotel: #10b981;
    --payment: #f59e0b;
    --devops: #f97316;
    --github: #e2e8f0;
    --jira: #2684ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }

  /* Layout */
  .header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 16px; }
  .logo { font-size: 20px; font-weight: 800; letter-spacing: -0.5px; }
  .logo span { color: var(--accent); }
  .badge { font-size: 11px; background: var(--accent); color: white; padding: 2px 8px; border-radius: 20px; font-weight: 600; }
  .tagline { color: var(--muted); font-size: 13px; margin-left: auto; }
  .main { display: grid; grid-template-columns: 320px 1fr 320px; gap: 0; height: calc(100vh - 57px); overflow: hidden; }

  /* Panels */
  .panel { overflow-y: auto; border-right: 1px solid var(--border); }
  .panel:last-child { border-right: none; border-left: 1px solid var(--border); }
  .panel-title { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); padding: 14px 16px 8px; position: sticky; top: 0; background: var(--bg); z-index: 1; }

  /* Agent Network (center) */
  .center { background: var(--bg); overflow: auto; display: flex; flex-direction: column; }
  .network-wrap { flex: 0 0 260px; padding: 16px; display: flex; flex-direction: column; align-items: center; }
  .network-title { font-size: 12px; color: var(--muted); margin-bottom: 12px; text-align: center; }
  svg.network { width: 100%; max-width: 480px; height: 200px; }

  /* Steps */
  .steps-wrap { padding: 0 16px 16px; }
  .steps-label { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); margin-bottom: 10px; }
  .steps { display: flex; flex-direction: column; gap: 4px; }
  .step { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 8px; background: var(--surface2); border: 1px solid var(--border); transition: all 0.3s; }
  .step.running { border-color: var(--accent); background: rgba(59,130,246,0.08); }
  .step.waiting { border-color: var(--yellow); background: rgba(245,158,11,0.08); }
  .step.done    { border-color: var(--green);  background: rgba(16,185,129,0.06); }
  .step-icon { width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; flex-shrink: 0; }
  .step.pending .step-icon  { background: var(--surface); border: 1px solid var(--border); }
  .step.running .step-icon  { background: var(--accent);  animation: pulse 1s infinite; }
  .step.waiting .step-icon  { background: var(--yellow); }
  .step.done    .step-icon  { background: var(--green); }
  .step-label { font-size: 13px; flex: 1; }
  .step-agent { font-size: 11px; color: var(--muted); }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }

  /* Message log */
  .msg-list { display: flex; flex-direction: column; gap: 4px; padding: 0 12px 12px; }
  .msg-item { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; font-size: 11px; cursor: pointer; transition: border-color 0.2s; }
  .msg-item:hover { border-color: var(--accent); }
  .msg-header { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
  .msg-type { font-weight: 700; color: var(--accent); font-size: 10px; letter-spacing: 0.04em; }
  .msg-time { color: var(--muted); margin-left: auto; font-size: 10px; }
  .msg-route { color: var(--muted); font-size: 10px; }
  .msg-summary { color: var(--text); margin-top: 2px; line-height: 1.4; }
  .msg-type.reserve  { color: var(--yellow); }
  .msg-type.commit   { color: var(--green); }
  .msg-type.cancel   { color: var(--red); }
  .msg-type.response { color: var(--accent2); }
  .msg-type.ack      { color: var(--green); }

  /* Decision log (right panel) */
  .dec-list { display: flex; flex-direction: column; gap: 6px; padding: 0 12px 12px; }
  .dec-item { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; font-size: 11px; }
  .dec-agent { display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 7px; border-radius: 20px; margin-bottom: 4px; }
  .dec-agent.personal { background: rgba(59,130,246,0.2);  color: var(--personal); }
  .dec-agent.flight   { background: rgba(139,92,246,0.2);  color: var(--flight); }
  .dec-agent.hotel    { background: rgba(16,185,129,0.2);  color: var(--hotel); }
  .dec-agent.payment  { background: rgba(245,158,11,0.2);  color: var(--payment); }
  .dec-action { font-weight: 600; color: var(--text); }
  .dec-detail { color: var(--muted); margin-top: 2px; line-height: 1.4; }

  /* Modals */
  .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); z-index: 100; display: flex; align-items: center; justify-content: center; display: none; }
  .modal-overlay.active { display: flex; }
  .modal { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 28px; width: 560px; max-width: 96vw; max-height: 80vh; overflow-y: auto; }
  .modal-title { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
  .modal-sub { color: var(--muted); font-size: 13px; margin-bottom: 20px; }

  /* Flight cards */
  .flight-card { background: var(--surface2); border: 2px solid var(--border); border-radius: 12px; padding: 16px; cursor: pointer; margin-bottom: 10px; transition: all 0.2s; }
  .flight-card:hover { border-color: var(--accent); background: rgba(59,130,246,0.05); }
  .flight-card.selected { border-color: var(--accent); background: rgba(59,130,246,0.12); }
  .flight-row { display: flex; align-items: center; gap: 12px; }
  .airline-badge { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 4px 12px; font-weight: 700; font-size: 13px; }
  .flight-info { flex: 1; }
  .flight-times { font-size: 20px; font-weight: 700; }
  .flight-meta { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .flight-price { text-align: right; }
  .price-big { font-size: 22px; font-weight: 800; color: var(--accent); }
  .price-class { font-size: 11px; color: var(--muted); }

  /* Hotel cards */
  .hotel-card { background: var(--surface2); border: 2px solid var(--border); border-radius: 12px; padding: 16px; cursor: pointer; margin-bottom: 10px; transition: all 0.2s; }
  .hotel-card:hover { border-color: var(--green); background: rgba(16,185,129,0.05); }
  .hotel-card.selected { border-color: var(--green); background: rgba(16,185,129,0.12); }
  .hotel-name { font-size: 16px; font-weight: 700; }
  .hotel-area { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .hotel-row { display: flex; align-items: center; gap: 8px; margin-top: 10px; }
  .amenity { font-size: 11px; background: var(--bg); border: 1px solid var(--border); border-radius: 20px; padding: 2px 8px; color: var(--muted); }
  .stars { color: var(--yellow); font-size: 13px; }
  .hotel-price { margin-left: auto; font-size: 18px; font-weight: 700; color: var(--green); }

  /* Payment modal */
  .pay-summary { background: var(--surface2); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 20px; }
  .pay-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; font-size: 14px; }
  .pay-row.total { border-top: 1px solid var(--border); margin-top: 8px; padding-top: 14px; font-weight: 700; font-size: 16px; }
  .card-mock { background: linear-gradient(135deg, #1e3a5f, #0f2440); border: 1px solid var(--border); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card-chip { width: 36px; height: 28px; background: linear-gradient(135deg, #c9a227, #e8c547); border-radius: 6px; margin-bottom: 20px; }
  .card-number { font-family: 'Courier New', monospace; font-size: 18px; letter-spacing: 3px; color: var(--text); margin-bottom: 16px; }
  .card-row { display: flex; justify-content: space-between; font-size: 11px; color: rgba(255,255,255,0.6); }
  .card-name { font-size: 14px; font-weight: 600; color: var(--text); }
  .card-type { font-size: 16px; font-weight: 800; color: var(--yellow); }

  /* Buttons */
  .btn { display: inline-flex; align-items: center; gap: 6px; padding: 10px 20px; border-radius: 8px; font-weight: 600; font-size: 14px; border: none; cursor: pointer; transition: all 0.2s; }
  .btn-primary { background: var(--accent); color: white; }
  .btn-primary:hover { background: #2563eb; }
  .btn-success { background: var(--green); color: white; width: 100%; justify-content: center; padding: 14px; border-radius: 10px; font-size: 15px; }
  .btn-success:hover { background: #059669; }
  .btn-start { background: linear-gradient(135deg, var(--accent), var(--accent2)); color: white; padding: 14px 32px; font-size: 16px; border-radius: 12px; border: none; cursor: pointer; font-weight: 700; transition: all 0.2s; }
  .btn-start:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(59,130,246,0.4); }
  .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }

  /* Start screen */
  .start-screen { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; gap: 16px; text-align: center; padding: 40px; }
  .start-screen h2 { font-size: 28px; font-weight: 800; }
  .start-screen p { color: var(--muted); max-width: 420px; line-height: 1.6; }
  .itinerary-badge { background: var(--surface2); border: 1px solid var(--border); border-radius: 12px; padding: 16px 24px; font-size: 14px; color: var(--muted); }
  .itinerary-badge strong { color: var(--text); display: block; font-size: 18px; margin-bottom: 4px; }

  /* Complete screen */
  .complete-screen { padding: 24px; display: none; }
  .complete-screen.active { display: block; }
  .success-banner { background: rgba(16,185,129,0.1); border: 1px solid var(--green); border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 20px; }
  .success-banner h3 { color: var(--green); font-size: 20px; margin-bottom: 6px; }
  .success-banner p { color: var(--muted); font-size: 14px; }
  .summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
  .summary-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
  .summary-card h4 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 8px; }
  .summary-card .value { font-size: 15px; font-weight: 700; }
  .summary-card .sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .explorer-tabs { display: flex; gap: 4px; margin-bottom: 12px; flex-wrap: wrap; }
  .tab { padding: 6px 14px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); transition: all 0.2s; }
  .tab.active { border-color: var(--accent); background: rgba(59,130,246,0.15); color: var(--text); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* Envelope modal */
  .env-modal { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; max-width: 680px; width: 96vw; max-height: 85vh; overflow-y: auto; }
  .env-modal pre { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-size: 11px; white-space: pre-wrap; word-break: break-all; }
  .env-modal-header { display:flex; align-items:center; gap:10px; margin-bottom:14px; }
  .env-type-badge { font-size:11px; font-weight:700; padding:3px 9px; border-radius:20px; }
  .env-type-badge.reserve  { background:rgba(249,115,22,0.2);  color:var(--devops); }
  .env-type-badge.commit   { background:rgba(34,197,94,0.2);   color:var(--green); }
  .env-type-badge.cancel   { background:rgba(239,68,68,0.2);   color:var(--red); }
  .env-type-badge.request  { background:rgba(59,130,246,0.2);  color:var(--accent); }
  .env-type-badge.response { background:rgba(6,182,212,0.2);   color:#22d3ee; }
  .env-type-badge.ack      { background:rgba(34,197,94,0.15);  color:#86efac; }
  .env-meta { font-size:11px; color:var(--muted); margin-bottom:12px; }
  /* JSON syntax highlight */
  .json-key    { color:#94a3b8; }
  .json-str    { color:#7dd3fc; }
  .json-num    { color:#86efac; }
  .json-bool   { color:#c084fc; }
  .json-null   { color:#f87171; }
  .json-proof  { color:#fbbf24; font-weight:600; }
  /* Live envelope stream */
  .env-stream-header { font-size:11px; font-weight:700; color:var(--muted); letter-spacing:.06em; text-transform:uppercase; padding:10px 0 6px; border-top:1px solid var(--border); margin-top:8px; display:flex; align-items:center; gap:6px; }
  .env-stream-dot { width:6px; height:6px; border-radius:50%; background:var(--accent); animation:pulse 1.5s ease-in-out infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  .env-card { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:8px 10px; margin-bottom:5px; cursor:pointer; transition:border-color .15s; font-size:11px; }
  .env-card:hover { border-color:var(--accent); }
  .env-card-header { display:flex; align-items:center; gap:6px; margin-bottom:3px; }
  .env-card-route { color:var(--muted); font-size:10px; }
  .env-card-time  { margin-left:auto; color:var(--muted); font-size:10px; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

  /* Agent dot colors */
  .dot-personal { fill: var(--personal); }
  .dot-flight   { fill: var(--flight); }
  .dot-hotel    { fill: var(--hotel); }
  .dot-payment  { fill: var(--payment); }
  .dot-devops   { fill: var(--devops); }
  .dot-github   { fill: var(--github); }
  .dot-jira     { fill: var(--jira); }
  .dot-registry { fill: var(--muted); }
  .dec-agent.devops { background: rgba(249,115,22,0.2);  color: var(--devops); }
  .dec-agent.github { background: rgba(226,232,240,0.15); color: var(--github); }
  .dec-agent.jira   { background: rgba(38,132,255,0.2);  color: var(--jira); }

  /* Scenario selector */
  .scenario-bar { background: var(--surface); border-bottom: 1px solid var(--border); display: flex; gap: 0; }
  .scenario-tab { flex: 1; padding: 10px 20px; font-size: 13px; font-weight: 600; cursor: pointer; border: none; background: none; color: var(--muted); border-bottom: 2px solid transparent; transition: all 0.2s; }
  .scenario-tab.active { color: var(--text); border-bottom-color: var(--accent); background: rgba(59,130,246,0.05); }
  .scenario-tab:hover:not(.active) { color: var(--text); background: rgba(255,255,255,0.03); }
  .scenario-content { display: none; }
  .scenario-content.active { display: contents; }

  /* HITL approval modal */
  .approval-banner { background: rgba(249,115,22,0.1); border: 1px solid var(--devops); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
  .approval-banner h4 { color: var(--devops); font-size: 15px; margin-bottom: 6px; }
  .approval-banner p  { color: var(--muted); font-size: 13px; line-height: 1.5; }
  .approval-detail { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 16px; font-size: 12px; }
  .approval-detail .row { display: flex; justify-content: space-between; padding: 3px 0; }
  .approval-detail .row .label { color: var(--muted); }
  .approval-detail .row .value { font-weight: 600; }
  .btn-approve { background: var(--green); color: white; flex: 1; justify-content: center; padding: 12px; font-size: 14px; border-radius: 8px; border: none; cursor: pointer; font-weight: 700; transition: all 0.2s; }
  .btn-approve:hover { background: #059669; }
  .btn-reject  { background: transparent; color: var(--red); border: 1px solid var(--red); flex: 1; justify-content: center; padding: 12px; font-size: 14px; border-radius: 8px; cursor: pointer; font-weight: 700; transition: all 0.2s; }
  .btn-reject:hover { background: rgba(239,68,68,0.1); }
  .line-active  { stroke: var(--accent); stroke-dasharray: 4 3; animation: dash 1s linear infinite; }
  .line-done    { stroke: var(--green); }
  .line-idle    { stroke: var(--border); }
  @keyframes dash { to { stroke-dashoffset: -14; } }
</style>
</head>
<body>
<div class="header">
  <div class="logo">Aroha<span>.</span>io</div>
  <div class="badge">LIVE DEMO</div>
  <div class="tagline">Bounded, verifiable authority for every agent in the chain</div>
</div>

<div class="scenario-bar">
  <button class="scenario-tab active" id="tab-travel"     onclick="switchScenario('travel')">✈ Scenario 1 — Travel Booking (4 agents)</button>
  <button class="scenario-tab"        id="tab-enterprise" onclick="switchScenario('enterprise')">🏢 Scenario 2 — Enterprise IT: Incident Response (3 agents · HITL · InMemoryRegistry)</button>
</div>

<div class="main">
  <!-- LEFT: Message Log -->
  <div class="panel" id="msgPanel">
    <div class="panel-title">Protocol Messages</div>
    <div class="msg-list" id="msgList"></div>
  </div>

  <!-- CENTER: Network + Steps + Complete -->
  <div class="center">
    <!-- Agent Network SVG -->
    <div class="network-wrap">
      <div class="network-title">Agent Network — Ed25519 Signed Aroha Envelopes</div>
      <svg class="network" viewBox="0 0 480 200" id="networkSvg">
        <!-- Lines -->
        <line id="ln-p-f" x1="240" y1="100" x2="100" y2="60"  stroke-width="1.5" class="line-idle"/>
        <line id="ln-p-h" x1="240" y1="100" x2="380" y2="60"  stroke-width="1.5" class="line-idle"/>
        <line id="ln-p-pay" x1="240" y1="100" x2="380" y2="145" stroke-width="1.5" class="line-idle"/>
        <line id="ln-p-r"  x1="240" y1="100" x2="100" y2="145" stroke-width="1.5" class="line-idle"/>
        <!-- Nodes -->
        <circle cx="240" cy="100" r="28" class="dot-personal" opacity="0.15"/>
        <circle cx="240" cy="100" r="20" class="dot-personal"/>
        <text x="240" y="104" text-anchor="middle" font-size="10" font-weight="700" fill="white">PERSONAL</text>

        <circle cx="100" cy="60" r="22" class="dot-flight" opacity="0.15"/>
        <circle cx="100" cy="60" r="16" class="dot-flight"/>
        <text x="100" y="64" text-anchor="middle" font-size="9" font-weight="700" fill="white">FLIGHT</text>

        <circle cx="380" cy="60" r="22" class="dot-hotel" opacity="0.15"/>
        <circle cx="380" cy="60" r="16" class="dot-hotel"/>
        <text x="380" y="64" text-anchor="middle" font-size="9" font-weight="700" fill="white">HOTEL</text>

        <circle cx="380" cy="145" r="22" class="dot-payment" opacity="0.15"/>
        <circle cx="380" cy="145" r="16" class="dot-payment"/>
        <text x="380" y="149" text-anchor="middle" font-size="9" font-weight="700" fill="white">PAYMENT</text>

        <circle cx="100" cy="145" r="18" class="dot-registry" opacity="0.2"/>
        <circle cx="100" cy="145" r="13" class="dot-registry"/>
        <text x="100" y="149" text-anchor="middle" font-size="8" font-weight="700" fill="white">REGISTRY</text>
      </svg>
    </div>

    <!-- Enterprise Network SVG (hidden until enterprise scenario active) -->
    <div class="network-wrap" id="enterpriseNetworkWrap" style="display:none">
      <div class="network-title">Agent Network — InMemoryRegistry · Ed25519 Signed · HITL Approval Gate</div>
      <svg class="network" viewBox="0 0 480 200" id="enterpriseNetworkSvg">
        <line id="eln-d-j"  x1="240" y1="110" x2="100" y2="60"  stroke-width="1.5" class="line-idle"/>
        <line id="eln-d-g"  x1="240" y1="110" x2="380" y2="60"  stroke-width="1.5" class="line-idle"/>
        <line id="eln-d-r"  x1="240" y1="110" x2="240" y2="165" stroke-width="1.5" class="line-idle"/>
        <!-- DevOps orchestrator -->
        <circle cx="240" cy="110" r="28" class="dot-devops" opacity="0.15"/>
        <circle cx="240" cy="110" r="20" class="dot-devops"/>
        <text x="240" y="106" text-anchor="middle" font-size="9" font-weight="700" fill="white">DEV</text>
        <text x="240" y="118" text-anchor="middle" font-size="9" font-weight="700" fill="white">OPS</text>
        <!-- Jira agent -->
        <circle cx="100" cy="60" r="22" class="dot-jira" opacity="0.15"/>
        <circle cx="100" cy="60" r="16" class="dot-jira"/>
        <text x="100" y="64" text-anchor="middle" font-size="9" font-weight="700" fill="white">JIRA</text>
        <!-- GitHub agent -->
        <circle cx="380" cy="60" r="22" class="dot-github" opacity="0.15"/>
        <circle cx="380" cy="60" r="16" class="dot-github"/>
        <text x="380" y="64" text-anchor="middle" font-size="8" font-weight="700" fill="#0a0e1a">GITHUB</text>
        <!-- InMemoryRegistry badge -->
        <rect x="170" y="155" width="140" height="24" rx="6" fill="#1a2236" stroke="#1e2d45"/>
        <text x="240" y="171" text-anchor="middle" font-size="9" fill="#64748b">InMemoryRegistry — no blockchain</text>
      </svg>
    </div>

    <!-- Start screen (travel) -->
    <div class="start-screen" id="startScreen">
      <div class="itinerary-badge">
        <strong>Business Trip: JFK → Tokyo</strong>
        May 1–7, 2026 · 1 traveler · Business class · Budget $8,000
      </div>
      <h2>Watch 4 AI Agents Collaborate</h2>
      <p>Real Ed25519-signed Aroha envelopes. Atomic saga transactions. Human-in-the-loop approvals. Everything verifiable on-chain.</p>
      <button class="btn-start" onclick="startDemo()">▶ Start Demo</button>
    </div>

    <!-- Start screen (enterprise) -->
    <div class="start-screen" id="enterpriseStartScreen" style="display:none">
      <div class="itinerary-badge">
        <strong>Production Alert: checkout-service</strong>
        p99 latency 3,210ms · threshold 2,000ms · severity HIGH
      </div>
      <h2>DevOps Agent + GitHub + Jira</h2>
      <p>InMemoryRegistry — no blockchain. HITL approval gate — human must approve the rollback before the saga commits. Atomic: both Jira ticket and GitHub issue are created together or not at all.</p>
      <button class="btn-start" onclick="startEnterpriseDemo()">▶ Start Enterprise Demo</button>
    </div>

    <!-- Steps (shown during travel run) -->
    <div class="steps-wrap" id="stepsWrap" style="display:none">
      <div class="steps-label">Workflow Steps</div>
      <div class="steps" id="stepsList">
        <div class="step pending" id="step-s0"><div class="step-icon">○</div><div class="step-label">Parse intent</div><div class="step-agent">personal</div></div>
        <div class="step pending" id="step-s1"><div class="step-icon">○</div><div class="step-label">Discover agents via registry</div><div class="step-agent">personal</div></div>
        <div class="step pending" id="step-s2"><div class="step-icon">○</div><div class="step-label">Search flights</div><div class="step-agent">flight</div></div>
        <div class="step pending" id="step-s3"><div class="step-icon">○</div><div class="step-label">Human selects flight</div><div class="step-agent">personal</div></div>
        <div class="step pending" id="step-s4"><div class="step-icon">○</div><div class="step-label">Search hotels</div><div class="step-agent">hotel</div></div>
        <div class="step pending" id="step-s5"><div class="step-icon">○</div><div class="step-label">Human selects hotel</div><div class="step-agent">personal</div></div>
        <div class="step pending" id="step-s6"><div class="step-icon">○</div><div class="step-label">Payment confirmation</div><div class="step-agent">payment</div></div>
        <div class="step pending" id="step-s7"><div class="step-icon">○</div><div class="step-label">Saga: Reserve (3-way parallel)</div><div class="step-agent">personal</div></div>
        <div class="step pending" id="step-s8"><div class="step-icon">○</div><div class="step-label">Saga: Commit atomically</div><div class="step-agent">personal</div></div>
      </div>
    </div>

    <!-- Enterprise steps (shown during enterprise run) -->
    <div class="steps-wrap" id="enterpriseStepsWrap" style="display:none">
      <div class="steps-label">Enterprise Workflow Steps</div>
      <div class="steps" id="enterpriseStepsList">
        <div class="step pending" id="step-es0"><div class="step-icon">○</div><div class="step-label">Parse production alert</div><div class="step-agent">devops</div></div>
        <div class="step pending" id="step-es1"><div class="step-icon">○</div><div class="step-label">Discover agents — InMemoryRegistry</div><div class="step-agent">devops</div></div>
        <div class="step pending" id="step-es2"><div class="step-icon">○</div><div class="step-label">Saga: Reserve Jira + GitHub (parallel)</div><div class="step-agent">devops</div></div>
        <div class="step pending" id="step-es3"><div class="step-icon">○</div><div class="step-label">⏸ HITL: Approve rollback to v2.1.3</div><div class="step-agent">devops</div></div>
        <div class="step pending" id="step-es4"><div class="step-icon">○</div><div class="step-label">Saga: Commit atomically</div><div class="step-agent">devops</div></div>
      </div>
    </div>

    <!-- Enterprise complete screen -->
    <div class="complete-screen" id="enterpriseCompleteScreen">
      <div id="enterpriseSuccessBanner"></div>
      <div class="summary-grid" id="enterpriseSummaryGrid"></div>
      <div class="steps-label" style="margin-bottom:12px">Explore Agent Decisions</div>
      <div class="explorer-tabs">
        <div class="tab active" onclick="showETab('devops')">DevOps Agent</div>
        <div class="tab" onclick="showETab('github')">GitHub Agent</div>
        <div class="tab" onclick="showETab('jira')">Jira Agent</div>
        <div class="tab" onclick="showETab('emessages')">All Messages</div>
      </div>
      <div id="etab-devops"   class="tab-content active"></div>
      <div id="etab-github"   class="tab-content"></div>
      <div id="etab-jira"     class="tab-content"></div>
      <div id="etab-emessages" class="tab-content"></div>
      <div style="margin-top:16px">
        <button class="btn btn-primary" onclick="startEnterpriseDemo()">↺ Run Again</button>
      </div>
    </div>

    <!-- Complete screen (travel) -->
    <div class="complete-screen" id="completeScreen">
      <div class="success-banner">
        <h3>✓ Tokyo Trip Booked — Atomically</h3>
        <p>3-party saga committed. All agents signed. Payment captured.</p>
      </div>
      <div class="summary-grid" id="summaryGrid"></div>
      <div class="steps-label" style="margin-bottom:12px">Explore Agent Decisions</div>
      <div class="explorer-tabs">
        <div class="tab active" onclick="showTab('personal')">Personal Agent</div>
        <div class="tab" onclick="showTab('flight')">Flight Agent</div>
        <div class="tab" onclick="showTab('hotel')">Hotel Agent</div>
        <div class="tab" onclick="showTab('payment')">Payment Agent</div>
        <div class="tab" onclick="showTab('messages')">All Messages</div>
      </div>
      <div id="tab-personal" class="tab-content active"></div>
      <div id="tab-flight"   class="tab-content"></div>
      <div id="tab-hotel"    class="tab-content"></div>
      <div id="tab-payment"  class="tab-content"></div>
      <div id="tab-messages" class="tab-content"></div>
      <div style="margin-top:16px">
        <button class="btn btn-primary" onclick="startDemo()">↺ Run Again</button>
      </div>
    </div>
  </div>

  <!-- RIGHT: Decision Log + Live Envelope Stream -->
  <div class="panel" id="decPanel">
    <div class="panel-title">Agent Decisions</div>
    <div class="dec-list" id="decList"></div>
    <div class="env-stream-header"><div class="env-stream-dot"></div>Live Envelopes</div>
    <div id="envStream"></div>
  </div>
</div>

<!-- Flight Selection Modal -->
<div class="modal-overlay" id="flightModal">
  <div class="modal">
    <div class="modal-title">✈ Select a Flight</div>
    <div class="modal-sub">JFK → NRT · May 1, 2026 · Business Class · 1 Pax</div>
    <div id="flightCards"></div>
    <div class="modal-actions">
      <button class="btn btn-primary" id="flightConfirmBtn" disabled onclick="confirmFlight()">Confirm Selection →</button>
    </div>
  </div>
</div>

<!-- Hotel Selection Modal -->
<div class="modal-overlay" id="hotelModal">
  <div class="modal">
    <div class="modal-title">🏨 Select a Hotel</div>
    <div class="modal-sub">Tokyo · May 1–7, 2026 · 6 nights · 5-star</div>
    <div id="hotelCards"></div>
    <div class="modal-actions">
      <button class="btn btn-primary" id="hotelConfirmBtn" disabled onclick="confirmHotel()">Confirm Selection →</button>
    </div>
  </div>
</div>

<!-- Payment Modal -->
<div class="modal-overlay" id="paymentModal">
  <div class="modal">
    <div class="modal-title">💳 Confirm Payment</div>
    <div class="modal-sub">Review your booking and authorize payment</div>
    <div id="paymentSummary"></div>
    <div class="card-mock">
      <div class="card-chip"></div>
      <div class="card-number">4242 4242 4242 4242</div>
      <div class="card-row">
        <div>
          <div style="margin-bottom:2px">CARDHOLDER</div>
          <div class="card-name">ALEX CHEN</div>
        </div>
        <div>
          <div style="margin-bottom:2px">EXPIRES</div>
          <div class="card-name">04/28</div>
        </div>
        <div class="card-type">VISA</div>
      </div>
    </div>
    <button class="btn-success" onclick="confirmPayment()">🔐 Authorize $<span id="payTotal">0</span> — Charge Card</button>
  </div>
</div>

<!-- Rollback Approval Modal (HITL) -->
<div class="modal-overlay" id="rollbackModal">
  <div class="modal">
    <div class="modal-title">⚠ Human Approval Required</div>
    <div class="modal-sub">The DevOps Agent is requesting authorization to execute a production rollback</div>
    <div class="approval-banner">
      <h4>🔴 Production Alert: checkout-service</h4>
      <p id="rollbackAlertDetail">p99 latency spike detected. DevOps Agent recommends rollback to last known-good version.</p>
    </div>
    <div class="approval-detail" id="rollbackDetail">
      <div class="row"><span class="label">Service</span><span class="value">checkout-service</span></div>
      <div class="row"><span class="label">Action</span><span class="value">Rollback → v2.1.3</span></div>
      <div class="row"><span class="label">Creates</span><span class="value">Jira incident ticket + GitHub tracking issue</span></div>
      <div class="row"><span class="label">Registry</span><span class="value" style="color:var(--green)">InMemoryRegistry (no blockchain)</span></div>
    </div>
    <p style="font-size:12px;color:var(--muted);margin-bottom:16px">Both actions are reserved but NOT committed. Rejecting will cancel both reservations — nothing changes in Jira or GitHub.</p>
    <div style="display:flex;gap:10px">
      <button class="btn-reject" onclick="resolveRollback(false)">✕ Reject Rollback</button>
      <button class="btn-approve" onclick="resolveRollback(true)">✓ Approve Rollback</button>
    </div>
  </div>
</div>

<!-- Envelope Viewer Modal -->
<div class="modal-overlay" id="envModal" onclick="closeEnvModal(event)">
  <div class="env-modal">
    <div class="env-modal-header">
      <div id="envTypeBadge" class="env-type-badge"></div>
      <div style="font-weight:700;flex:1">Aroha Envelope</div>
      <button onclick="document.getElementById('envModal').classList.remove('active')" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px">✕</button>
    </div>
    <div class="env-meta" id="envMeta"></div>
    <pre id="envContent"></pre>
  </div>
</div>

<script>
const api = (path, opts) => fetch(path, opts).then(r => r.json());

let selectedFlightId = null;
let selectedHotelId  = null;
let allMessages      = [];

// ─── SSE ──────────────────────────────────────────────────────────────────────

let currentScenario = 'travel';

const es = new EventSource('/api/stream');
es.onmessage = e => {
  const data = JSON.parse(e.data);
  handle(data);
};

function handle(data) {
  switch (data.type) {
    case 'step':     updateStep(data);     break;
    case 'estep':    updateStep(data, true); break;
    case 'message':  appendMessage(data);  break;
    case 'emessage': appendMessage(data, true); break;
    case 'decision': appendDecision(data); break;
    case 'edecision': appendDecision(data, true); break;
    case 'state':    onStateChange(data.state); break;
    case 'estate':   onEnterpriseStateChange(data.state); break;
    case 'human_input': onHumanInput(data); break;
    case 'enterprise_human_input': onEnterpriseHumanInput(data); break;
    case 'complete': onComplete(data);     break;
    case 'enterprise_complete': onEnterpriseComplete(data); break;
    case 'error':    console.error('Demo error:', data.message); break;
  }
}

// ─── Scenario switching ───────────────────────────────────────────────────────

function switchScenario(scenario) {
  currentScenario = scenario;
  document.getElementById('tab-travel').classList.toggle('active', scenario === 'travel');
  document.getElementById('tab-enterprise').classList.toggle('active', scenario === 'enterprise');

  // Network SVGs
  document.querySelector('.network-wrap:not(#enterpriseNetworkWrap)').style.display = scenario === 'travel' ? '' : 'none';
  document.getElementById('enterpriseNetworkWrap').style.display = scenario === 'enterprise' ? '' : 'none';

  // Start screens
  document.getElementById('startScreen').style.display = scenario === 'travel' ? 'flex' : 'none';
  document.getElementById('enterpriseStartScreen').style.display = scenario === 'enterprise' ? 'flex' : 'none';

  // Steps panels
  document.getElementById('stepsWrap').style.display = 'none';
  document.getElementById('enterpriseStepsWrap').style.display = 'none';
  document.getElementById('completeScreen').classList.remove('active');
  document.getElementById('enterpriseCompleteScreen').classList.remove('active');
  document.getElementById('msgList').innerHTML = '';
  document.getElementById('decList').innerHTML = '';
}

// ─── Steps ────────────────────────────────────────────────────────────────────

function updateStep({ id, label, agent, status }, enterprise = false) {
  const prefix = enterprise ? 'step-' : 'step-';
  const el = document.getElementById(prefix + id);
  if (!el) return;
  el.className = 'step ' + status;
  const icon = el.querySelector('.step-icon');
  icon.textContent = status === 'done' ? '✓' : status === 'running' ? '⟳' : status === 'waiting' ? '⏸' : '○';
}

// ─── Network graph animation ──────────────────────────────────────────────────

function animateLine(id, status) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = status === 'active' ? 'line-active' : status === 'done' ? 'line-done' : 'line-idle';
}

function onStateChange(state) {
  // Reset lines
  ['ln-p-f','ln-p-h','ln-p-pay','ln-p-r'].forEach(id => animateLine(id, 'idle'));
  if (state === 'searching') { animateLine('ln-p-f', 'active'); animateLine('ln-p-h', 'active'); }
  if (state === 'select_flight') animateLine('ln-p-f', 'active');
  if (state === 'select_hotel')  animateLine('ln-p-h', 'active');
  if (state === 'payment')   { animateLine('ln-p-pay', 'active'); }
  if (state === 'reserving') { animateLine('ln-p-f', 'active'); animateLine('ln-p-h', 'active'); animateLine('ln-p-pay', 'active'); }
  if (state === 'committing') { animateLine('ln-p-f', 'active'); animateLine('ln-p-h', 'active'); animateLine('ln-p-pay', 'active'); }
  if (state === 'complete')  { animateLine('ln-p-f', 'done'); animateLine('ln-p-h', 'done'); animateLine('ln-p-pay', 'done'); animateLine('ln-p-r', 'done'); }
}

// ─── Enterprise state ─────────────────────────────────────────────────────────

function onEnterpriseStateChange(state) {
  ['eln-d-j','eln-d-g','eln-d-r'].forEach(id => animateLine(id, 'idle'));
  if (state === 'reserving')          { animateLine('eln-d-j', 'active'); animateLine('eln-d-g', 'active'); }
  if (state === 'awaiting_approval')  { animateLine('eln-d-j', 'active'); animateLine('eln-d-g', 'active'); animateLine('eln-d-r', 'active'); }
  if (state === 'committing')         { animateLine('eln-d-j', 'active'); animateLine('eln-d-g', 'active'); }
  if (state === 'ecomplete')          { animateLine('eln-d-j', 'done');   animateLine('eln-d-g', 'done');   animateLine('eln-d-r', 'done'); }
}

function onEnterpriseHumanInput({ step, alert, rollbackVersion }) {
  if (step === 'rollback') {
    document.getElementById('rollbackAlertDetail').textContent =
      \`p99 latency: \${alert.value.toLocaleString()}ms (threshold: \${alert.threshold.toLocaleString()}ms). Rollback target: \${rollbackVersion}.\`;
    document.getElementById('rollbackModal').classList.add('active');
  }
}

function resolveRollback(approved) {
  document.getElementById('rollbackModal').classList.remove('active');
  api('/api/enterprise/approve', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ approved }) });
}

function onEnterpriseComplete({ approved, summary, decisions }) {
  document.getElementById('enterpriseStepsWrap').style.display = 'none';
  const cs = document.getElementById('enterpriseCompleteScreen');
  cs.classList.add('active');

  document.getElementById('enterpriseSuccessBanner').innerHTML = approved
    ? \`<div class="success-banner"><h3>✓ Incident Response Committed — Atomically</h3><p>Jira ticket and GitHub issue created together. Rollback authorized by human.</p></div>\`
    : \`<div class="success-banner" style="background:rgba(239,68,68,0.1);border-color:var(--red)"><h3 style="color:var(--red)">✕ Rollback Rejected — Saga Compensated</h3><p>Human rejected the rollback. Both reservations cancelled — nothing was created in Jira or GitHub.</p></div>\`;

  if (approved && summary) {
    document.getElementById('enterpriseSummaryGrid').innerHTML = \`
      <div class="summary-card">
        <h4>Jira Ticket</h4>
        <div class="value">\${summary.jiraKey}</div>
        <div class="sub">[P0] checkout-service latency spike</div>
      </div>
      <div class="summary-card">
        <h4>GitHub Issue</h4>
        <div class="value">#\${summary.githubIssue}</div>
        <div class="sub">Incident tracking issue · acme-corp/checkout-service</div>
      </div>
      <div class="summary-card">
        <h4>Protocol Activity</h4>
        <div class="value">\${summary.messages} messages</div>
        <div class="sub">\${summary.agents} agents · Ed25519 signed</div>
      </div>
      <div class="summary-card">
        <h4>Registry</h4>
        <div class="value" style="color:var(--green);font-size:13px">InMemoryRegistry</div>
        <div class="sub">No blockchain required</div>
      </div>
    \`;
  }

  ['devops','github','jira'].forEach(agent => {
    const el = document.getElementById('etab-' + agent);
    const items = decisions[agent] ?? [];
    if (items.length === 0) { el.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:8px">No decisions recorded.</div>'; return; }
    el.innerHTML = items.map(d => \`
      <div class="dec-item" style="margin-bottom:6px">
        <div class="dec-action">\${d.action}</div>
        <div class="dec-detail">\${d.detail}</div>
        \${d.ts ? \`<div style="font-size:10px;color:var(--muted);margin-top:4px">\${new Date(d.ts).toLocaleTimeString()}</div>\` : ''}
      </div>
    \`).join('');
  });

  const em = document.getElementById('etab-emessages');
  const eMsgs = document.querySelectorAll('#msgList .msg-item');
  em.innerHTML = Array.from(eMsgs).map(m => m.outerHTML).join('');
}

function showETab(name) {
  document.querySelectorAll('#enterpriseCompleteScreen .tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('#enterpriseCompleteScreen .tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(\`#enterpriseCompleteScreen .tab[onclick="showETab('\${name}')"]\`).classList.add('active');
  document.getElementById('etab-' + name).classList.add('active');
}

// ─── Messages ─────────────────────────────────────────────────────────────────

function msgTypeClass(t) {
  if (t.includes('Reserve')) return 'reserve';
  if (t.includes('Commit') && t.includes('Ack')) return 'ack';
  if (t.includes('Commit')) return 'commit';
  if (t.includes('Cancel')) return 'cancel';
  if (t.includes('Response')) return 'response';
  return '';
}

function appendMessage(data, enterprise = false) {
  allMessages.push(data);
  const list = document.getElementById('msgList');
  const el = document.createElement('div');
  el.className = 'msg-item';
  el.onclick = () => showEnvelope(data.envelope);
  el.innerHTML = \`
    <div class="msg-header">
      <span class="msg-type \${msgTypeClass(data.msgType)}">\${data.msgType}</span>
      <span class="msg-time">\${new Date(data.ts).toLocaleTimeString()}</span>
    </div>
    <div class="msg-route">\${data.from.split(':').pop()?.slice(0,10) ?? data.from} → \${data.to.split(':').pop()?.slice(0,10) ?? data.to}</div>
    <div class="msg-summary">\${data.summary}</div>
  \`;
  list.appendChild(el);
  list.parentElement.scrollTop = list.parentElement.scrollHeight;
  pushEnvelopeCard(data);
}

// ─── Decisions ────────────────────────────────────────────────────────────────

function appendDecision(data, enterprise = false) {
  const list = document.getElementById('decList');
  const el = document.createElement('div');
  el.className = 'dec-item';
  el.innerHTML = \`
    <span class="dec-agent \${data.agent}">\${data.agent}</span>
    <div class="dec-action">\${data.action}</div>
    <div class="dec-detail">\${data.detail}</div>
  \`;
  list.appendChild(el);
  list.parentElement.scrollTop = list.parentElement.scrollHeight;
}

// ─── Human input handlers ─────────────────────────────────────────────────────

function onHumanInput({ step, flights, hotels, flight, hotel, total, card }) {
  if (step === 'flight') showFlightModal(flights);
  if (step === 'hotel')  showHotelModal(hotels);
  if (step === 'payment') showPaymentModal(flight, hotel, total, card);
}

function showFlightModal(flights) {
  const c = document.getElementById('flightCards');
  c.innerHTML = '';
  flights.forEach(f => {
    const el = document.createElement('div');
    el.className = 'flight-card';
    el.id = 'fc-' + f.id;
    el.onclick = () => selectFlightCard(f.id);
    el.innerHTML = \`
      <div class="flight-row">
        <div class="airline-badge">\${f.airline}</div>
        <div class="flight-info">
          <div class="flight-times">\${f.depart} → \${f.arrive}</div>
          <div class="flight-meta">\${f.flight} · \${f.stops} · \${f.duration}</div>
        </div>
        <div class="flight-price">
          <div class="price-big">$\${f.price.toLocaleString()}</div>
          <div class="price-class">\${f.class} · \${f.seats} seats left</div>
        </div>
      </div>
    \`;
    c.appendChild(el);
  });
  document.getElementById('flightModal').classList.add('active');
}

function selectFlightCard(id) {
  selectedFlightId = id;
  document.querySelectorAll('.flight-card').forEach(el => el.classList.remove('selected'));
  document.getElementById('fc-' + id).classList.add('selected');
  document.getElementById('flightConfirmBtn').disabled = false;
}

function confirmFlight() {
  if (!selectedFlightId) return;
  document.getElementById('flightModal').classList.remove('active');
  api('/api/select/flight', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ flightId: selectedFlightId }) });
}

function showHotelModal(hotels) {
  const c = document.getElementById('hotelCards');
  c.innerHTML = '';
  hotels.forEach(h => {
    const el = document.createElement('div');
    el.className = 'hotel-card';
    el.id = 'hc-' + h.id;
    el.onclick = () => selectHotelCard(h.id);
    el.innerHTML = \`
      <div class="hotel-name">\${h.name}</div>
      <div class="hotel-area">⭐ \${h.stars} · \${h.area}, Tokyo · Rating: \${h.rating}/5</div>
      <div class="hotel-row">
        \${h.amenities.map(a => \`<span class="amenity">\${a}</span>\`).join('')}
        <div class="hotel-price">$\${h.price}<small style="font-weight:400;font-size:12px">/night</small></div>
      </div>
    \`;
    c.appendChild(el);
  });
  document.getElementById('hotelModal').classList.add('active');
}

function selectHotelCard(id) {
  selectedHotelId = id;
  document.querySelectorAll('.hotel-card').forEach(el => el.classList.remove('selected'));
  document.getElementById('hc-' + id).classList.add('selected');
  document.getElementById('hotelConfirmBtn').disabled = false;
}

function confirmHotel() {
  if (!selectedHotelId) return;
  document.getElementById('hotelModal').classList.remove('active');
  api('/api/select/hotel', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ hotelId: selectedHotelId }) });
}

function showPaymentModal(flight, hotel, total, card) {
  document.getElementById('payTotal').textContent = total.toLocaleString();
  document.getElementById('paymentSummary').innerHTML = \`
    <div class="pay-summary">
      <div class="pay-row"><span>✈ \${flight?.airline ?? ''} \${flight?.flight ?? ''}</span><span>$\${(flight?.price ?? 0).toLocaleString()}</span></div>
      <div class="pay-row"><span>🏨 \${hotel?.name ?? ''} (6 nights)</span><span>$\${(hotel?.totalPrice ?? 0).toLocaleString()}</span></div>
      <div class="pay-row total"><span>Total</span><span style="color:var(--accent)">$\${total.toLocaleString()}</span></div>
    </div>
  \`;
  document.getElementById('paymentModal').classList.add('active');
}

function confirmPayment() {
  document.getElementById('paymentModal').classList.remove('active');
  api('/api/confirm/payment', { method: 'POST' });
}

// ─── Complete ─────────────────────────────────────────────────────────────────

function onComplete({ summary, decisions }) {
  document.getElementById('stepsWrap').style.display = 'none';
  const cs = document.getElementById('completeScreen');
  cs.classList.add('active');

  // Summary grid
  document.getElementById('summaryGrid').innerHTML = \`
    <div class="summary-card">
      <h4>Flight</h4>
      <div class="value">\${summary.flight.airline} \${summary.flight.flightNo}</div>
      <div class="sub">Departs \${summary.flight.depart} · $\${summary.flight.price.toLocaleString()}</div>
    </div>
    <div class="summary-card">
      <h4>Hotel</h4>
      <div class="value">\${summary.hotel.name}</div>
      <div class="sub">May 1–7 · $\${summary.hotel.price.toLocaleString()}</div>
    </div>
    <div class="summary-card">
      <h4>Total Charged</h4>
      <div class="value" style="color:var(--accent)">$\${summary.total.toLocaleString()}</div>
      <div class="sub">Visa •••• 4242</div>
    </div>
    <div class="summary-card">
      <h4>Protocol Activity</h4>
      <div class="value">\${summary.messages} messages</div>
      <div class="sub">\${summary.agents} agents · Ed25519 signed</div>
    </div>
  \`;

  // Explorer tabs
  ['personal','flight','hotel','payment'].forEach(agent => {
    const el = document.getElementById('tab-' + agent);
    const items = decisions[agent] ?? [];
    if (items.length === 0) { el.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:8px">No decisions recorded.</div>'; return; }
    el.innerHTML = items.map(d => \`
      <div class="dec-item" style="margin-bottom:6px">
        <div class="dec-action">\${d.action}</div>
        <div class="dec-detail">\${d.detail}</div>
        \${d.ts ? \`<div style="font-size:10px;color:var(--muted);margin-top:4px">\${new Date(d.ts).toLocaleTimeString()}</div>\` : ''}
      </div>
    \`).join('');
  });

  // Messages tab
  const msgTab = document.getElementById('tab-messages');
  msgTab.innerHTML = allMessages.map(m => \`
    <div class="msg-item" onclick='showEnvelope(\${JSON.stringify(m.envelope ?? null)})' style="margin-bottom:4px">
      <div class="msg-header">
        <span class="msg-type \${msgTypeClass(m.msgType)}">\${m.msgType}</span>
        <span class="msg-time">\${new Date(m.ts).toLocaleTimeString()}</span>
      </div>
      <div class="msg-route">\${m.from.split(':').pop()?.slice(0,12) ?? m.from} → \${m.to.split(':').pop()?.slice(0,12) ?? m.to}</div>
      <div class="msg-summary">\${m.summary}</div>
    </div>
  \`).join('');
}

function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(\`.tab[onclick="showTab('\${name}')"]\`).classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

// ─── Envelope viewer ──────────────────────────────────────────────────────────

function msgTypeCssClass(type) {
  if (!type) return '';
  const t = type.toLowerCase();
  if (t.includes('reserve') && t.includes('ack')) return 'ack';
  if (t.includes('commit')  && t.includes('ack')) return 'ack';
  if (t.includes('cancel')  && t.includes('ack')) return 'ack';
  if (t.includes('reserve')) return 'reserve';
  if (t.includes('commit'))  return 'commit';
  if (t.includes('cancel'))  return 'cancel';
  if (t.includes('response')) return 'response';
  if (t.includes('request')) return 'request';
  return '';
}

function syntaxHighlight(obj) {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    match => {
      let cls = 'json-num';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'json-key';
        } else {
          // Highlight Ed25519 signature specifically
          const isProof = match.length > 80 && /^"[A-Za-z0-9+/=]{60,}"/.test(match);
          cls = isProof ? 'json-proof' : 'json-str';
        }
      } else if (/true|false/.test(match)) {
        cls = 'json-bool';
      } else if (/null/.test(match)) {
        cls = 'json-null';
      }
      return \`<span class="\${cls}">\${match.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</span>\`;
    }
  );
}

function showEnvelope(env) {
  if (!env) return;
  const type = env.type ?? '';
  const cssClass = msgTypeCssClass(type);

  const badge = document.getElementById('envTypeBadge');
  badge.textContent = type || 'Envelope';
  badge.className = 'env-type-badge ' + cssClass;

  const from = env.from ? env.from.split(':').pop()?.slice(0, 16) : '?';
  const to   = env.to   ? env.to.split(':').pop()?.slice(0, 16)   : '?';
  const ts   = env.issuedAt ? new Date(env.issuedAt).toLocaleTimeString() : '';
  document.getElementById('envMeta').textContent =
    (from && to ? \`\${from} → \${to}\` : '') + (ts ? \`  ·  \${ts}\` : '');

  document.getElementById('envContent').innerHTML = syntaxHighlight(env);
  document.getElementById('envModal').classList.add('active');
}

function closeEnvModal(e) {
  if (e.target === document.getElementById('envModal')) {
    document.getElementById('envModal').classList.remove('active');
  }
}

// ─── Live envelope stream ─────────────────────────────────────────────────────

const MAX_STREAM_CARDS = 12;

function pushEnvelopeCard(data) {
  if (!data.envelope) return;
  const stream = document.getElementById('envStream');
  if (!stream) return;
  const env = data.envelope;
  const type = env.type ?? data.msgType ?? '';
  const cssClass = msgTypeCssClass(type);
  const from = env.from ? env.from.split(':').pop()?.slice(0, 12) : data.from ?? '';
  const to   = env.to   ? env.to.split(':').pop()?.slice(0, 12)   : data.to ?? '';
  const ts   = new Date(data.ts).toLocaleTimeString();

  const card = document.createElement('div');
  card.className = 'env-card';
  card.onclick = () => showEnvelope(env);
  card.innerHTML = \`
    <div class="env-card-header">
      <span class="env-type-badge \${cssClass}" style="font-size:10px;padding:2px 7px">\${type}</span>
      <span class="env-card-time">\${ts}</span>
    </div>
    <div class="env-card-route">\${from} → \${to}</div>
  \`;

  stream.insertBefore(card, stream.firstChild);
  while (stream.children.length > MAX_STREAM_CARDS) {
    stream.removeChild(stream.lastChild);
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

function startDemo() {
  selectedFlightId = null;
  selectedHotelId  = null;
  allMessages      = [];
  document.getElementById('msgList').innerHTML  = '';
  document.getElementById('decList').innerHTML  = '';
  document.getElementById('envStream').innerHTML = '';
  document.getElementById('startScreen').style.display  = 'none';
  document.getElementById('completeScreen').classList.remove('active');
  document.getElementById('stepsWrap').style.display = 'block';
  document.querySelectorAll('#stepsList .step').forEach(s => {
    s.className = 'step pending';
    s.querySelector('.step-icon').textContent = '○';
  });
  ['ln-p-f','ln-p-h','ln-p-pay','ln-p-r'].forEach(id => animateLine(id, 'idle'));
  api('/api/start', { method: 'POST' });
}

function startEnterpriseDemo() {
  allMessages = [];
  document.getElementById('msgList').innerHTML  = '';
  document.getElementById('decList').innerHTML  = '';
  document.getElementById('envStream').innerHTML = '';
  document.getElementById('enterpriseStartScreen').style.display = 'none';
  document.getElementById('enterpriseCompleteScreen').classList.remove('active');
  document.getElementById('enterpriseStepsWrap').style.display = 'block';
  document.querySelectorAll('#enterpriseStepsList .step').forEach(s => {
    s.className = 'step pending';
    s.querySelector('.step-icon').textContent = '○';
  });
  ['eln-d-j','eln-d-g','eln-d-r'].forEach(id => animateLine(id, 'idle'));
  api('/api/enterprise/start', { method: 'POST' });
}
</script>
</body>
</html>`;
