// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha SaaS Integrators Demo — Cross-product saga
 *
 * Demonstrates Aroha coordinating agents across three SaaS products atomically:
 *   1. SalesforceAgent — creates a CRM opportunity
 *   2. StripeAgent      — creates a subscription and charges card
 *   3. SlackAgent       — sends deal-closed notification to sales channel
 *
 * One Aroha envelope from the orchestrator coordinates all three. If Stripe
 * rejects the card, the CRM opportunity is rolled back (no phantom records).
 * This replaces N² webhook logic with one saga.
 *
 *
 * Usage:
 *   node scripts/demo-cross-product.mjs
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

// ─── Agent identities ─────────────────────────────────────────────────────────

const AGENTS = {
  orchestrator: { did: "did:aroha:sales-orchestrator",  name: "SalesOrchestrator" },
  salesforce:   { did: "did:aroha:salesforce-bridge",   name: "SalesforceAgent (Aroha bridge)" },
  stripe:       { did: "did:aroha:stripe-bridge",       name: "StripeAgent (Aroha bridge)" },
  slack:        { did: "did:aroha:slack-bridge",        name: "SlackAgent (Aroha bridge)" },
};

// ─── Saga simulation ──────────────────────────────────────────────────────────

async function runCrossProductSaga(deal, simulateStripeFailure = false) {
  const sagaId = `saga-cross-${Date.now()}`;
  const steps = [
    {
      agent: AGENTS.salesforce,
      capability: "create-opportunity",
      params: {
        accountName: deal.company,
        amount: deal.amount,
        stage: "Closed Won",
        closeDate: new Date().toISOString().split("T")[0],
      },
    },
    {
      agent: AGENTS.stripe,
      capability: "create-subscription",
      params: {
        customerId: deal.stripeCustomerId,
        planId: deal.planId,
        amount: deal.amount,
        currency: "USD",
      },
    },
    {
      agent: AGENTS.slack,
      capability: "send-channel-message",
      params: {
        channel: "#deals-won",
        message: `🎉 New deal closed: ${deal.company} — $${deal.amount.toLocaleString()}/yr`,
        sagaId,
      },
    },
  ];

  log(BOLD, `\n${"─".repeat(64)}`);
  log(BOLD, `Cross-Product Saga — Salesforce + Stripe + Slack`);
  log(BOLD, `${"─".repeat(64)}`);
  log(DIM, `Saga ID:   ${sagaId}`);
  log(DIM, `Customer:  ${deal.company}`);
  log(DIM, `Deal size: $${deal.amount.toLocaleString()}/yr (${deal.planId})`);
  log(BOLD, `${"─".repeat(64)}\n`);

  const reservationTokens = [];

  // ── Phase 1: RESERVE ────────────────────────────────────────────────────────
  log(CYAN, "▶ Phase 1: RESERVE\n");

  for (const step of steps) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaReserve(${step.capability})`);
    await sleep(450 + Math.random() * 250);

    const failHere = simulateStripeFailure && step.agent.did === AGENTS.stripe.did;

    if (failHere) {
      console.log(`  ${RED}✗ ArohaError: CARD_DECLINED — reserve rejected${RESET}`);
      log(RED, `\n✗ Stripe declined. Rolling back CRM record and aborting Slack message...\n`);
      return await rollback(sagaId, reservationTokens);
    }

    const token = `tok-${step.agent.name.split(" ")[0].toLowerCase()}-${Date.now()}`;
    reservationTokens.push({ step, token });

    if (step.agent.did === AGENTS.salesforce.did) {
      console.log(`  ${GREEN}✓ ArohaReserveAck — opportunity draft created (pending commit)${RESET}`);
    } else if (step.agent.did === AGENTS.stripe.did) {
      console.log(`  ${GREEN}✓ ArohaReserveAck — payment intent created (pending capture)${RESET}`);
    } else {
      console.log(`  ${GREEN}✓ ArohaReserveAck — message queued (pending delivery)${RESET}`);
    }
  }

  log(GREEN, "\n✓ All three agents reserved. Proceeding to COMMIT.\n");

  // ── Phase 2: COMMIT ─────────────────────────────────────────────────────────
  log(CYAN, "▶ Phase 2: COMMIT\n");

  const results = {};
  for (const { step, token } of reservationTokens) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaCommit(${token.slice(0, 22)}...)`);
    await sleep(300 + Math.random() * 150);

    if (step.agent.did === AGENTS.salesforce.did) {
      results.opportunityId = `0065f00000${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
      console.log(`  ${GREEN}✓ opportunityId=${results.opportunityId}${RESET}`);
    } else if (step.agent.did === AGENTS.stripe.did) {
      results.subscriptionId = `sub_${Math.random().toString(36).slice(2, 18)}`;
      results.invoiceId = `inv_${Math.random().toString(36).slice(2, 18)}`;
      console.log(`  ${GREEN}✓ subscriptionId=${results.subscriptionId}${RESET}`);
    } else {
      results.messageTs = `${Date.now() / 1000}`;
      console.log(`  ${GREEN}✓ delivered to #deals-won (ts=${results.messageTs})${RESET}`);
    }
  }

  log(GREEN, `\n${"═".repeat(64)}`);
  log(GREEN, `✓ SAGA COMMITTED — All three systems updated atomically`);
  log(GREEN, `${"═".repeat(64)}`);
  log(DIM, `  Salesforce:  Opportunity ${results.opportunityId} — Closed Won`);
  log(DIM, `  Stripe:      Subscription ${results.subscriptionId} active`);
  log(DIM, `  Slack:       Message delivered to #deals-won`);
  log(DIM, `  Consistency: Guaranteed — all or nothing, zero phantom records`);
  log(DIM, `  Signed envelopes: ${steps.length * 2} total (Reserve + Commit × 3 agents)\n`);
}

async function rollback(sagaId, reservedSteps) {
  log(YELLOW, "▶ Phase 3: CANCEL (LIFO)\n");

  const toCancel = [...reservedSteps].reverse();
  for (const { step, token } of toCancel) {
    process.stdout.write(`  ${step.agent.name}  →  ArohaCancel(${token.slice(0, 22)}...)`);
    await sleep(250);
    if (step.agent.did === AGENTS.salesforce.did) {
      console.log(`  ${YELLOW}✓ CRM opportunity draft deleted — no record created${RESET}`);
    } else {
      console.log(`  ${YELLOW}✓ ArohaCancelAck — reservation released${RESET}`);
    }
  }

  log(RED, `\n${"═".repeat(64)}`);
  log(RED, `✗ SAGA ROLLED BACK — Zero phantom records created`);
  log(RED, `${"═".repeat(64)}`);
  log(DIM, `  Salesforce: no opportunity written`);
  log(DIM, `  Stripe:     no charge processed`);
  log(DIM, `  Slack:      no premature notification sent`);
  log(DIM, `  Manual cleanup required: NONE\n`);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

const deal = {
  company: "Meridian SaaS Inc.",
  amount: 48_000,
  planId: "plan_enterprise_annual",
  stripeCustomerId: "cus_meridian_001",
};

log(BOLD, "\n╔══════════════════════════════════════════════════════════════╗");
log(BOLD, "║  Aroha Protocol — SaaS Integrators Demo                      ║");
log(BOLD, "║  Cross-Product Saga: Salesforce + Stripe + Slack             ║");
log(BOLD, "╚══════════════════════════════════════════════════════════════╝");

log(DIM, "\nScenario 1 — Happy path: $48k/yr deal closed, all three systems updated\n");
await runCrossProductSaga(deal, false);

await sleep(1500);

log(DIM, "\nScenario 2 — Card declined: Stripe rejects, CRM opportunity rolled back\n");
await runCrossProductSaga(deal, true);

log(CYAN, "\nKey takeaways:");
log(DIM, "  • One Aroha orchestrator replaces three separate API integrations.");
log(DIM, "  • Rollback eliminates phantom CRM records — no manual cleanup tickets.");
log(DIM, "  • Each bridge (Salesforce, Stripe, Slack) wraps existing REST APIs.");
log(DIM, "  • The saga coordinator can be in any language — protocol is language-agnostic.");
