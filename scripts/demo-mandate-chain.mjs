#!/usr/bin/env node
/**
 * Aroha Protocol — End-to-End Mandate Chain Demo
 *
 * Demonstrates the full delegated authority chain:
 *   Human → Orchestrator → Flight Agent → Payment Processor
 *
 * Run:  npm run demo:mandate   (after npm run build)
 *
 * No network calls. All keys generated in-memory.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  issueIntentMandate,
  attenuateToCart,
  attenuateToPayment,
  verifyMandate,
} from "@aroha-sdk/credentials";
import { generateDid } from "@aroha-sdk/core";

// noble/ed25519 requires a synchronous sha512 shim in Node < 20
ed.etc.sha512Sync = (...m) => sha512(...m);

// ─── ANSI helpers ─────────────────────────────────────────────────────────────

const GREEN  = (s) => `\x1b[32m${s}\x1b[0m`;
const RED    = (s) => `\x1b[31m${s}\x1b[0m`;
const CYAN   = (s) => `\x1b[36m${s}\x1b[0m`;
const BOLD   = (s) => `\x1b[1m${s}\x1b[0m`;
const DIM    = (s) => `\x1b[2m${s}\x1b[0m`;

let passed = 0;
let failed = 0;

function pass(label) {
  passed++;
  console.log(`  ${GREEN("✓")} ${label}`);
}

function fail(label, reason) {
  failed++;
  console.log(`  ${RED("✗")} ${label} — ${DIM(reason)}`);
}

function section(title) {
  console.log(`\n${BOLD(CYAN("▶ " + title))}`);
}

// ─── Key generation ───────────────────────────────────────────────────────────

async function generateKeypair(name) {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey  = await ed.getPublicKeyAsync(privateKey);
  // Content-addressed did:aroha:z… DIDs commit to their own public key, so a
  // verifier resolves every grantor in the chain without a registry lookup.
  return { name, privateKey, publicKey, did: generateDid(publicKey) };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(BOLD("\nAroha Protocol — Mandate Chain Demo\n"));
  console.log(DIM("Generating Ed25519 key pairs for each participant...\n"));

  const human        = await generateKeypair("human");
  const orchestrator = await generateKeypair("orchestrator");
  const flightAgent  = await generateKeypair("flight-agent");
  const payment      = await generateKeypair("payment-processor");

  console.log(`  ${DIM("Human:")}        ${human.did}`);
  console.log(`  ${DIM("Orchestrator:")} ${orchestrator.did}`);
  console.log(`  ${DIM("Flight agent:")} ${flightAgent.did}`);
  console.log(`  ${DIM("Payment proc:")} ${payment.did}`);

  // ─── 1. Issue Intent Mandate (Human → Orchestrator) ────────────────────────

  section("1. Human issues Intent Mandate to Orchestrator");

  const intentMandate = await issueIntentMandate(
    human.did,
    orchestrator.did,
    { spendLimitUsd: 1000, currency: "USD", allowedMerchants: null },
    human.privateKey,
    3_600_000 // 1 hour TTL
  );

  // Verify from orchestrator's perspective
  const intentVerified = await verifyMandate(
    intentMandate.token,
    human.publicKey,
    orchestrator.did
  );

  if (intentVerified.valid) {
    pass(`Intent mandate verified — limit: $${intentVerified.mandate.constraints.spendLimitUsd}`);
  } else {
    fail("Intent mandate verification", intentVerified.reason ?? "unknown");
  }

  // ─── 2. Orchestrator attenuates to Cart Mandate (→ Flight Agent) ───────────

  section("2. Orchestrator attenuates to Cart Mandate for Flight Agent");

  const cartMandate = await attenuateToCart(
    intentMandate,
    flightAgent.did,
    {
      spendLimitUsd: 450,        // narrowed from $1000
      currency: "USD",
      merchantCategory: "airlines",
      allowedMerchants: ["did:aroha:provider:united-airlines"],
    },
    orchestrator.privateKey
  );

  const cartVerified = await verifyMandate(
    cartMandate.token,
    orchestrator.publicKey,
    flightAgent.did
  );

  if (cartVerified.valid) {
    pass(`Cart mandate verified — limit: $${cartVerified.mandate.constraints.spendLimitUsd}, category: ${cartVerified.mandate.constraints.merchantCategory}`);
  } else {
    fail("Cart mandate verification", cartVerified.reason ?? "unknown");
  }

  // ─── 3. Flight Agent attenuates to Payment Mandate (→ Payment Processor) ───

  section("3. Flight Agent attenuates to Payment Mandate for specific transaction");

  const paymentMandate = await attenuateToPayment(
    cartMandate,
    payment.did,
    {
      spendLimitUsd: 389.99,    // narrowed to the actual ticket price
      currency: "USD",
      merchantCategory: "airlines",
      allowedMerchants: ["did:aroha:provider:united-airlines"],
    },
    flightAgent.privateKey
  );

  const paymentVerified = await verifyMandate(
    paymentMandate.token,
    flightAgent.publicKey,
    payment.did
  );

  if (paymentVerified.valid) {
    pass(`Payment mandate verified — authorized: $${paymentVerified.mandate.constraints.spendLimitUsd}`);
  } else {
    fail("Payment mandate verification", paymentVerified.reason ?? "unknown");
  }

  // ─── 4. Security: Wrong grantee rejected ───────────────────────────────────

  section("4. Security: mandate is grantee-locked");

  const wrongGranteeResult = await verifyMandate(
    paymentMandate.token,
    flightAgent.publicKey,
    "did:aroha:attacker:malicious-agent"
  );

  if (!wrongGranteeResult.valid) {
    pass(`Rejected wrong grantee — ${wrongGranteeResult.reason}`);
  } else {
    fail("Wrong grantee should have been rejected", "accepted without error");
  }

  // ─── 5. Security: Tampered token rejected ──────────────────────────────────

  section("5. Security: tampered mandate is rejected");

  const decoded = JSON.parse(Buffer.from(paymentMandate.token, "base64url").toString("utf8"));
  decoded.mandate.constraints.spendLimitUsd = 99999; // attacker tries to raise the limit
  const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString("base64url");

  const tamperedResult = await verifyMandate(tamperedToken, flightAgent.publicKey, payment.did);

  if (!tamperedResult.valid) {
    pass(`Tampered token rejected — ${tamperedResult.reason}`);
  } else {
    fail("Tampered token should have been rejected", "accepted despite modification");
  }

  // ─── 6. Security: Over-scope attenuation rejected ──────────────────────────

  section("6. Security: over-scope attenuation (narrowing violation) is rejected");

  let overScopeRejected = false;
  try {
    await attenuateToPayment(
      cartMandate,
      payment.did,
      { spendLimitUsd: 9999, currency: "USD" }, // $9999 > cart limit of $450
      flightAgent.privateKey
    );
  } catch (err) {
    overScopeRejected = true;
    pass(`Over-scope rejected at creation time — ${err.message.slice(0, 80)}`);
  }

  if (!overScopeRejected) {
    fail("Over-scope attenuation should have thrown", "no error was thrown");
  }

  // ─── 7. Expired mandate rejected ──────────────────────────────────────────

  section("7. Expired mandate is rejected");

  const expiredMandate = await issueIntentMandate(
    human.did,
    orchestrator.did,
    { spendLimitUsd: 100 },
    human.privateKey,
    -1000  // already expired 1 second ago
  );

  const expiredResult = await verifyMandate(expiredMandate.token, human.publicKey);

  if (!expiredResult.valid) {
    pass(`Expired mandate rejected — ${expiredResult.reason}`);
  } else {
    fail("Expired mandate should have been rejected", "accepted past expiry");
  }

  // ─── 8. Wrong key rejected ─────────────────────────────────────────────────

  section("8. Mandate verified with wrong public key is rejected");

  const attacker = await generateKeypair("attacker");
  const wrongKeyResult = await verifyMandate(paymentMandate.token, attacker.publicKey, payment.did);

  if (!wrongKeyResult.valid) {
    pass(`Wrong key rejected — ${wrongKeyResult.reason}`);
  } else {
    fail("Wrong key should have been rejected", "verification passed");
  }

  // ─── Summary ───────────────────────────────────────────────────────────────

  console.log(`\n${"─".repeat(60)}`);
  const total = passed + failed;
  if (failed === 0) {
    console.log(GREEN(BOLD(`✓ All ${total} checks passed.`)));
    console.log(DIM("\nThe mandate chain is cryptographically sound:\n"));
    console.log(DIM("  Human ($1000) → Orchestrator ($450 airlines) → Payment ($389.99)"));
    console.log(DIM("  Forgery, over-scoping, tampering, expiry, and grantee mismatch"));
    console.log(DIM("  are all detected and rejected at the protocol layer.\n"));
  } else {
    console.log(RED(BOLD(`✗ ${failed} of ${total} checks failed.`)));
    process.exitCode = 1;
  }
}

main().catch(err => {
  console.error(RED("\nUnexpected error:"), err);
  process.exitCode = 1;
});
