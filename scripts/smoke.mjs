// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Aroha Node SDK — runtime smoke test
// Runs against the *published* npm packages (not local workspace builds).
//
// Usage:
//   npm run smoke          # from repo root
//   node scripts/smoke.mjs # directly
//
// Prerequisites: all @aroha-sdk/* packages must be installed in the working
// directory or globally. The easiest way is to run inside a temp dir that has
// them installed, or add a devDependency install step.

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const results = [];

function check(label, ok, detail = "") {
  const mark = ok ? PASS : FAIL;
  console.log(`  ${mark}  ${label}${detail ? " — " + detail : ""}`);
  results.push({ label, ok });
}

async function run() {
  console.log(`\nNode ${process.version} — Aroha SDK runtime smoke test\n`);

  // ── @aroha-sdk/core ────────────────────────────────────────────────────────
  console.log("── @aroha-sdk/core ──────────────────────────────────────────────────");
  const core = await import("@aroha-sdk/core");

  const { privateKey, publicKey } = await core.generateKeyPair();
  check("generateKeyPair() returns Uint8Arrays",
    privateKey instanceof Uint8Array && publicKey instanceof Uint8Array,
    `privKey=${privateKey.length}B pubKey=${publicKey.length}B`);
  check("generateKeyPair() key lengths", privateKey.length === 32 && publicKey.length === 32);

  const did = core.generateDid(publicKey);
  check("generateDid(publicKey) → did:aroha:…", did.startsWith("did:aroha:"), did.slice(0, 30) + "…");
  check("generateDid is deterministic (same key → same DID)", core.generateDid(publicKey) === did);

  const identity = await core.generateDID("smoke-test", "http://localhost:9999");
  check("generateDID(agentId, endpoint) → { did, privateKey, publicKey, document }",
    identity.did && identity.document && identity.privateKey instanceof Uint8Array,
    identity.did);
  check("generateDID document id matches did", identity.document.id === identity.did);

  const toMultibase = core.toMultibase;
  check("toMultibase is exported", typeof toMultibase === "function");
  const mb = toMultibase(publicKey);
  check("toMultibase returns z-prefixed string", mb.startsWith("z"), mb.slice(0, 12) + "…");

  const corrId = core.newCorrelationId();
  check("newCorrelationId() → non-empty string", typeof corrId === "string" && corrId.length > 0, corrId.slice(0, 20));

  const identity2 = await core.generateDID("smoke-receiver", "http://localhost");
  const env = await core.buildEnvelope(
    "ArohaRequest",
    identity.did,
    identity2.did,
    { capability: "search-flights", params: { from: "JFK", to: "LHR" } },
    corrId,
    identity.privateKey
  );
  check("buildEnvelope() returns signed envelope",
    env && env.type === "ArohaRequest" && env.proof,
    `id=${env?.id?.slice(0, 20)}…`);
  check("envelope from/to match", env.from === identity.did && env.to === identity2.did);

  // validateEnvelope(envelope, senderPubKey, myDID, nonceRegistry)
  const nonces = new core.NonceRegistry(60_000);
  const vResult = await core.validateEnvelope(env, identity.publicKey, identity2.did, nonces);
  check("validateEnvelope() → valid=true", vResult.valid === true, vResult.reason ?? "ok");

  const tampered = JSON.parse(JSON.stringify(env));
  tampered.body.params = { from: "evil" };
  tampered.id = "tampered-" + tampered.id;
  const nonces2 = new core.NonceRegistry(60_000);
  const tResult = await core.validateEnvelope(tampered, identity.publicKey, identity2.did, nonces2);
  check("validateEnvelope() rejects tampered envelope", tResult.valid === false);

  // ── @aroha-sdk/run ─────────────────────────────────────────────────────────
  console.log("\n── @aroha-sdk/run ───────────────────────────────────────────────────");
  const { serve } = await import("@aroha-sdk/run");
  check("serve() is a function", typeof serve === "function");

  const agent = serve("smoke-test-agent", async ({ message }) => `Echo: ${message}`);
  check("serve() returns agent object with start/app", typeof agent.start === "function");

  // serve().start() doesn't return the http.Server handle, so we bridge
  // agent.fetch ourselves to keep a closeable reference. Port 0 → OS picks
  // a free ephemeral port each run (no EADDRINUSE across runs).
  const { createServer: createHttpServer } = await import("http");
  let PORT, httpServer;
  try {
    PORT = await new Promise((resolve, reject) => {
      const probe = createHttpServer();
      probe.listen(0, () => { const p = probe.address().port; probe.close(() => resolve(p)); });
      probe.on("error", reject);
    });

    httpServer = createHttpServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const bodyText = Buffer.concat(chunks).toString("utf8");
      const fetchHeaders = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v) fetchHeaders.set(k, Array.isArray(v) ? v.join(", ") : v);
      }
      const request = new Request(`http://localhost:${PORT}${req.url ?? "/"}`, {
        method: req.method ?? "GET",
        headers: fetchHeaders,
        body: req.method !== "GET" && req.method !== "HEAD" && bodyText ? bodyText : null,
      });
      const response = await agent.fetch(request);
      res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }
      res.end();
    });
    await new Promise((resolve, reject) => {
      httpServer.listen(PORT, resolve);
      httpServer.on("error", reject);
    });
    check("agent server starts without throwing", true, `port ${PORT}`);
  } catch (e) {
    check("agent server starts without throwing", false, e.message);
  }

  try {
    const healthRes = await fetch(`http://localhost:${PORT}/health`);
    const health = await healthRes.json();
    check("/health responds 200", healthRes.ok, JSON.stringify(health).slice(0, 60));
  } catch (e) {
    check("/health responds 200", false, e.message);
  }

  try {
    const runRes = await fetch(`http://localhost:${PORT}/v1/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello", sessionId: "sess-1" }),
    });
    check("/v1/run responds 200", runRes.ok, `status=${runRes.status}`);
    if (runRes.ok) {
      const body = await runRes.json();
      check("/v1/run response contains message", typeof body.message === "string", `"${body.message?.slice(0, 40)}"`);
      check("/v1/run echoes correctly", body.message === "Echo: hello");
    }
  } catch (e) {
    check("/v1/run responds 200", false, e.message);
    results.push({ label: "/v1/run response contains message", ok: false });
    results.push({ label: "/v1/run echoes correctly", ok: false });
  }

  // ── @aroha-sdk/credentials ─────────────────────────────────────────────────
  console.log("\n── @aroha-sdk/credentials ───────────────────────────────────────────");
  const creds = await import("@aroha-sdk/credentials");

  const user = await core.generateDID("user", "http://localhost");
  const orch = await core.generateDID("orch", "http://localhost");

  // issueIntentMandate(grantorDID, granteeDID, constraints, privateKey, ttlMs?)
  const mandate = await creds.issueIntentMandate(
    user.did, orch.did, { spendLimitUsd: 100 }, user.privateKey
  );
  check("issueIntentMandate() → { mandate, signature, token }",
    mandate && typeof mandate.mandate === "object" && typeof mandate.token === "string");

  // verifyMandate(token, publicKey) → { valid, mandate?, reason? }
  const mResult = await creds.verifyMandate(mandate.token, user.publicKey);
  check("verifyMandate() → valid=true", mResult.valid === true, mResult.reason ?? "ok");
  check("verifyMandate() decoded grantor matches", mResult.mandate?.grantor === user.did);

  // attenuateToCart(parent, granteeDID, narrowedConstraints, grantorPrivateKey, ttlMs?)
  const provider = await core.generateDID("provider", "http://localhost");
  const cartMandate = await creds.attenuateToCart(
    mandate, provider.did, { spendLimitUsd: 50 }, orch.privateKey
  );
  check("attenuateToCart() → { mandate, signature, token }",
    cartMandate && typeof cartMandate.token === "string");
  const cartResult = await creds.verifyMandate(cartMandate.token, orch.publicKey, provider.did);
  check("attenuateToCart() produces valid mandate", cartResult.valid === true, cartResult.reason ?? "ok");

  // attenuateToPayment(parent, granteeDID, narrowedConstraints, grantorPrivateKey, ttlMs?)
  const payMandate = await creds.attenuateToPayment(
    cartMandate, provider.did, { spendLimitUsd: 49 }, provider.privateKey
  );
  check("attenuateToPayment() → { mandate, signature, token }",
    payMandate && typeof payMandate.token === "string");
  const payResult = await creds.verifyMandate(payMandate.token, provider.publicKey, provider.did);
  check("attenuateToPayment() produces valid mandate", payResult.valid === true, payResult.reason ?? "ok");
  check("attenuateToPayment() tier is 'payment'", payMandate.mandate?.mandateTier === "payment");

  // ── @aroha-sdk/micro ───────────────────────────────────────────────────────
  console.log("\n── @aroha-sdk/micro ─────────────────────────────────────────────────");
  const micro = await import("@aroha-sdk/micro");
  check("createMicroAgent is exported", typeof micro.createMicroAgent === "function");
  const microAgent = micro.createMicroAgent({
    name: "smoke-micro",
    capabilities: { greet: async ({ name }) => `Hello ${name}` },
    devMode: true,
  });
  check("createMicroAgent() returns agent with start()", typeof microAgent.start === "function");

  // ── @aroha-sdk/evals ───────────────────────────────────────────────────────
  console.log("\n── @aroha-sdk/evals ─────────────────────────────────────────────────");
  const evals = await import("@aroha-sdk/evals");
  check("runEvals is a function", typeof evals.runEvals === "function");
  check("judge is a function", typeof evals.judge === "function");

  // ── Summary ────────────────────────────────────────────────────────────────
  const passed = results.filter(r => r.ok).length;
  const failed = results.filter(r => !r.ok).length;
  const total = results.length;
  console.log(`\n${"─".repeat(60)}`);
  if (failed === 0) {
    console.log(`  \x1b[32m✓ ALL ${total} RUNTIME CHECKS PASSED\x1b[0m`);
  } else {
    console.log(`  \x1b[32m✓ ${passed} passed\x1b[0m  \x1b[31m✗ ${failed} failed\x1b[0m  (${total} total)`);
    results.filter(r => !r.ok).forEach(r => console.log(`    ✗ ${r.label}`));
  }
  console.log();
  if (httpServer) await new Promise(resolve => httpServer.close(resolve));
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
