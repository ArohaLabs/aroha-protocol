// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Fintech Vertical Demo — Loan Disbursement Saga
 *
 * Demonstrates the Aroha saga pattern for a multi-party financial transaction:
 *   1. CreditScoreAgent — pulls borrower credit profile
 *   2. LoanApprovalAgent — approves/rejects based on credit + terms
 *   3. DisbursementAgent — transfers funds on approval
 *   4. NotificationAgent — sends confirmation to borrower
 *
 * If any step fails, Aroha cancels all prior steps (atomic rollback).
 * This is the pattern that eliminates partial-state incidents in fintech.
 *
 *
 * Usage:
 *   npm run demo:fintech
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

ed.etc.sha512Sync = (...m) => sha512(...m);

const CYAN = "\x1b[36m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function log(prefix, msg) { console.log(`${prefix}${msg}${RESET}`); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ─── Simulated agents ─────────────────────────────────────────────────────────

const AGENTS = {
  orchestrator: { did: "did:aroha:loan-orchestrator", name: "LoanOrchestrator" },
  credit:       { did: "did:aroha:credit-score-v2",   name: "CreditScoreAgent" },
  approval:     { did: "did:aroha:loan-approval",     name: "LoanApprovalAgent" },
  disburse:     { did: "did:aroha:disbursement",      name: "DisbursementAgent" },
  notify:       { did: "did:aroha:notifier",          name: "NotificationAgent" },
};

// ─── Saga simulation ──────────────────────────────────────────────────────────

async function runSaga(borrower, amount, simulateFailure = false) {
  const sagaId = `saga-fintech-${Date.now()}`;
  const steps = [
    {
      agent: AGENTS.credit,
      capability: "get-credit-profile",
      params: { borrowerDID: borrower.did, purpose: "loan-application" },
    },
    {
      agent: AGENTS.approval,
      capability: "approve-loan",
      params: { amount, currency: "USD", purpose: "business-expansion" },
    },
    {
      agent: AGENTS.disburse,
      capability: "disburse-funds",
      params: { amount, currency: "USD", recipientDID: borrower.did },
    },
    {
      agent: AGENTS.notify,
      capability: "send-confirmation",
      params: { borrowerDID: borrower.did, amount, sagaId },
    },
  ];

  log(BOLD, `\n${"─".repeat(60)}`);
  log(BOLD, `Loan Disbursement Saga`);
  log(BOLD, `${"─".repeat(60)}`);
  log(DIM, `Saga ID:   ${sagaId}`);
  log(DIM, `Borrower:  ${borrower.name} (${borrower.did})`);
  log(DIM, `Amount:    $${amount.toLocaleString()} USD`);
  log(BOLD, `${"─".repeat(60)}\n`);

  const reservationTokens = [];

  // ── Phase 1: RESERVE ────────────────────────────────────────────────────────
  log(CYAN, "▶ Phase 1: RESERVE (locking resources across all agents)\n");

  for (const step of steps) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaReserve(${step.capability})`);
    await sleep(400 + Math.random() * 200);

    const failHere = simulateFailure && step.agent.did === AGENTS.disburse.did;

    if (failHere) {
      console.log(`  ${RED}✗ ArohaError: INSUFFICIENT_FUNDS — reserve rejected${RESET}`);
      log(RED, `\n✗ Reserve failed at ${step.agent.name}. Initiating LIFO rollback...\n`);
      return await rollback(sagaId, steps, reservationTokens);
    }

    const token = `tok-${step.agent.name.toLowerCase()}-${Date.now()}`;
    reservationTokens.push({ step, token });
    console.log(`  ${GREEN}✓ ArohaReserveAck (token: ${token.slice(0, 20)}...)${RESET}`);
  }

  log(GREEN, "\n✓ All agents reserved. Proceeding to COMMIT.\n");

  // ── Phase 2: COMMIT ─────────────────────────────────────────────────────────
  log(CYAN, "▶ Phase 2: COMMIT\n");

  const results = {};
  for (const { step, token } of reservationTokens) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaCommit(${token.slice(0, 20)}...)`);
    await sleep(300 + Math.random() * 200);

    if (step.capability === "get-credit-profile") {
      results.creditScore = 742;
      results.riskTier = "A";
      console.log(`  ${GREEN}✓ score=742 risk=A${RESET}`);
    } else if (step.capability === "approve-loan") {
      results.approved = true;
      results.interestRate = "4.75%";
      console.log(`  ${GREEN}✓ approved=true rate=4.75%${RESET}`);
    } else if (step.capability === "disburse-funds") {
      results.txId = `TXN-${Date.now()}`;
      console.log(`  ${GREEN}✓ txId=${results.txId}${RESET}`);
    } else {
      console.log(`  ${GREEN}✓ confirmed${RESET}`);
    }
  }

  log(GREEN, `\n${"═".repeat(60)}`);
  log(GREEN, `✓ SAGA COMMITTED — Loan disbursement complete`);
  log(GREEN, `${"═".repeat(60)}`);
  log(DIM, `  Credit score:   ${results.creditScore} (${results.riskTier})`);
  log(DIM, `  Approved:       ${results.approved} at ${results.interestRate}`);
  log(DIM, `  Transaction:    ${results.txId}`);
  log(DIM, `  Signed envelopes: ${steps.length * 2} (Reserve + Commit per agent)`);
  log(DIM, `  Partial state:  IMPOSSIBLE (saga pattern enforces all-or-nothing)\n`);
}

async function rollback(sagaId, steps, reservedSteps) {
  log(YELLOW, "▶ Phase 3: CANCEL (LIFO — last reserved, first cancelled)\n");

  const toCancel = [...reservedSteps].reverse();
  for (const { step, token } of toCancel) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaCancel(${token.slice(0, 20)}...)`);
    await sleep(250);
    console.log(`  ${YELLOW}✓ ArohaCancelAck — resources released${RESET}`);
  }

  log(RED, `\n${"═".repeat(60)}`);
  log(RED, `✗ SAGA ROLLED BACK — No partial state created`);
  log(RED, `${"═".repeat(60)}`);
  log(DIM, `  Rolled back: ${toCancel.length} agent(s)`);
  log(DIM, `  Financial exposure: $0 (no funds moved)`);
  log(DIM, `  Incident report: not required — saga handled atomically\n`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const borrower = { name: "Acme Corp", did: "did:aroha:acme-corp" };

log(BOLD, "\n╔══════════════════════════════════════════════════════════╗");
log(BOLD, "║  Aroha Protocol — Fintech Vertical Demo                  ║");
log(BOLD, "║  Loan Disbursement Saga with Atomic Rollback             ║");
log(BOLD, "╚══════════════════════════════════════════════════════════╝");

log(DIM, "\nScenario 1 — Happy path: $250,000 loan disbursement\n");
await runSaga(borrower, 250_000, false);

await sleep(1500);

log(DIM, "\nScenario 2 — Rollback: disbursement agent rejects (insufficient funds)\n");
await runSaga(borrower, 5_000_000, true);

log(CYAN, "\nKey takeaways:");
log(DIM, "  • Every agent action is a signed ArohaEnvelope — auditable, non-repudiable.");
log(DIM, "  • Partial state is structurally impossible: Reserve → Commit → Cancel.");
log(DIM, "  • Rollback is automatic, LIFO, and idempotent — no manual incident response.");
