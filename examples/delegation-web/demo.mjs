// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// A working web of agents:
//
//   A (root issuer) ──► B (orchestrator) ──► C (searcher)
//                                        └─► D (summariser)
//
// Every hop carries a signed, attenuated mandate chain. Run it:
//
//   node examples/delegation-web/demo.mjs
//
// What it proves:
//   1. B verifies A's mandate before doing anything (unauthenticated → 400)
//   2. B sub-delegates to C and D with ctx.delegate() — narrower scope each hop
//   3. C cannot delegate further (depth exhausted → DELEGATION_DEPTH_EXCEEDED)
//   4. A forged root key is rejected at the door
//   5. A receipt TREE comes back: B's receipt with C's and D's stitched in

import * as ed from "@noble/ed25519";
import {
  serveDelegated, publicKeyB64, issueDelegation, callDelegated, staticResolver,
} from "@aroha-sdk/delegation";

// ── Identities ────────────────────────────────────────────────────────────────
const ids = {};
for (const name of ["root", "orchestrator", "searcher", "summariser"]) {
  const privateKey = ed.utils.randomPrivateKey();
  ids[name] = {
    did: `did:aroha:demo:${name}`,
    privateKey,
    pubB64: await publicKeyB64(privateKey),
  };
}

const PORT_B = 9301, PORT_C = 9302, PORT_D = 9303;

// Key directory — in production this is registryResolver(); here, a static map.
const resolvePublicKey = staticResolver({
  [ids.orchestrator.did]: ids.orchestrator.pubB64,
  [ids.searcher.did]:     ids.searcher.pubB64,
  [ids.summariser.did]:   ids.summariser.pubB64,
});

const trustAnchors = { [ids.root.did]: ids.root.pubB64 };

// ── D: summariser (leaf) ──────────────────────────────────────────────────────
serveDelegated("summariser", {
  identity: ids.summariser, trustAnchors, resolvePublicKey,
}, async (ctx) => {
  ctx.assertCapability("summarise");
  ctx.recordAction("summarise");
  const words = ctx.message.split(/\s+/).length;
  return `[summary of ${words} words] ${ctx.message.slice(0, 60)}…`;
}).start(PORT_D, "127.0.0.1");

// ── C: searcher (leaf that TRIES to over-reach) ──────────────────────────────
serveDelegated("searcher", {
  identity: ids.searcher, trustAnchors, resolvePublicKey,
}, async (ctx) => {
  ctx.assertCapability("web-search");
  ctx.recordAction("web-search");

  // C attempts to sub-delegate — its mandate says maxDelegationDepth: 0
  try {
    await ctx.delegate({ endpoint: `http://127.0.0.1:${PORT_D}`, did: ids.summariser.did },
      "please do my job for me", { allowed: ["summarise"] });
    return "BUG: depth limit not enforced";
  } catch (err) {
    console.log(`  [C] sub-delegation blocked as designed → ${err.code}`);
  }

  return `results for "${ctx.message}": [r1] agent protocols overview [r2] mandate chains explained`;
}).start(PORT_C, "127.0.0.1");

// ── B: orchestrator (fans out to C and D) ─────────────────────────────────────
serveDelegated("orchestrator", {
  identity: ids.orchestrator, trustAnchors, resolvePublicKey,
}, async (ctx) => {
  ctx.assertCapability("research");
  console.log(`  [B] mandate verified — depth ${ctx.chainDepth}, corr ${ctx.correlationId.slice(0, 8)}…`);

  const search = await ctx.delegate(
    { endpoint: `http://127.0.0.1:${PORT_C}`, did: ids.searcher.did },
    ctx.message,
    { allowed: ["web-search"], constraints: { actionLimits: { "web-search": 5 } } },
  );

  const summary = await ctx.delegate(
    { endpoint: `http://127.0.0.1:${PORT_D}`, did: ids.summariser.did },
    search.message,
    { allowed: ["summarise"] },
  );

  return summary.message;
}).start(PORT_B, "127.0.0.1");

await new Promise((r) => setTimeout(r, 300)); // let servers bind

// ── A: the root issuer drives the web ────────────────────────────────────────
console.log("\n═══ 1. Legitimate delegated request (A → B → C, D) ═══");
const { envelope } = await issueDelegation(ids.root, ids.orchestrator.did, {
  allowed: ["research", "web-search", "summarise"],
  constraints: { maxDelegationDepth: 1 },   // B may delegate once; C/D may not
  ttlMs: 60_000,
});

const res = await callDelegated(`http://127.0.0.1:${PORT_B}`, "history of agent protocols", envelope);
console.log(`  [A] answer: ${res.message}`);

const tree = res.receipts[0];
console.log(`  [A] receipt tree: ${tree.receipt.executedByDid} (${tree.receipt.status})`);
for (const child of tree.children) {
  console.log(`        └─ ${child.receipt.executedByDid} (${child.receipt.status}) — actions: ${child.receipt.actions.map((a) => a.capability).join(", ")}`);
}
const chainOk = tree.children.length === 2 &&
  tree.children.every((c) => c.receipt.correlationId === tree.receipt.correlationId);
console.log(`  [A] 2 child receipts, one correlationId end-to-end: ${chainOk ? "✓" : "✗ FAIL"}`);

console.log("\n═══ 2. No mandate → rejected at the door ═══");
const bare = await fetch(`http://127.0.0.1:${PORT_B}/v1/run`, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "do things without authority" }),
});
console.log(`  HTTP ${bare.status} — ${(await bare.json()).error?.slice(0, 60)}…  ${bare.status === 400 ? "✓" : "✗ FAIL"}`);

console.log("\n═══ 3. Forged root (attacker's own key) → rejected ═══");
const mallory = { did: ids.root.did, privateKey: ed.utils.randomPrivateKey() }; // claims A's DID, wrong key
const { envelope: forged } = await issueDelegation(mallory, ids.orchestrator.did, {
  allowed: ["research"], ttlMs: 60_000,
});
try {
  await callDelegated(`http://127.0.0.1:${PORT_B}`, "steal the crown jewels", forged);
  console.log("  ✗ FAIL: forged root accepted");
} catch (err) {
  console.log(`  rejected: ${err.message.split("\n")[0].slice(0, 90)}  ✓`);
}

console.log("\n═══ 4. Capability outside the grant → refused by the node ═══");
const { envelope: narrow } = await issueDelegation(ids.root, ids.orchestrator.did, {
  allowed: ["summarise"],           // B is NOT granted "research"
  ttlMs: 60_000,
});
const refused = await callDelegated(`http://127.0.0.1:${PORT_B}`, "research something", narrow);
console.log(`  [B] replied: ${refused.message.slice(0, 70)}…`);
console.log(`  receipt status: ${refused.receipts[0]?.receipt.status}  ${refused.receipts[0]?.receipt.status === "failed" ? "✓" : "✗ FAIL"}`);

console.log("\nDone — the web held its shape.\n");
process.exit(0);
