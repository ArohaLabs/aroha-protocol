// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Cross-language harness for the Python SDK tests (tests/test_cross_language.py).
// Loads the BUILT TypeScript packages (packages/aroha-core/dist and
// packages/aroha-credentials/dist) and runs one operation read as JSON from
// stdin, printing the JSON result on stdout.
//
// usage: node interop.mjs <packages-dir> < request.json

import { pathToFileURL } from "node:url";

const base = process.argv[2];
const core = await import(pathToFileURL(`${base}/aroha-core/dist/index.js`).href);
const cred = await import(pathToFileURL(`${base}/aroha-credentials/dist/index.js`).href);

const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);

async function run(req) {
  switch (req.op) {
    case "verifyMandateChain": {
      const r = await cred.verifyMandateChain(req.token, undefined, { now: req.now });
      return { valid: r.valid, reason: r.reason ?? null, chainVerified: !!r.chainVerified, rootGrantor: r.rootGrantor ?? null,
               leafMandateId: r.mandate?.mandateId ?? null };
    }
    case "issueChain": {
      const intent = await cred.issueIntentMandate(req.humanDid, req.agentDid, req.intentConstraints, hex(req.humanPrivHex));
      const cart = await cred.attenuateToCart(intent, req.providerDid, req.cartConstraints, hex(req.agentPrivHex));
      return { intent: intent.token, cart: cart.token };
    }
    case "issueTaskChain": {
      const root = await cred.issueTaskMandate(req.humanDid, req.agentDid, req.allowed, req.constraints,
        hex(req.humanPrivHex), req.ttlMs, req.options);
      const out = { root: root.token };
      if (req.child) {
        const child = await cred.attenuateTaskMandate(root, req.child.granteeDid, req.child.allowed,
          req.child.constraints, hex(req.agentPrivHex), req.child.ttlMs, req.child.options);
        out.child = child.token;
      }
      return out;
    }
    case "verifyTaskMandate": {
      const r = await cred.verifyTaskMandate(req.token, hex(req.pubHex), req.expectedGrantee ?? undefined,
        req.now !== undefined ? { now: req.now } : {});
      return { valid: r.valid, reason: r.reason ?? null, mandate: r.mandate ?? null };
    }
    case "enforceTaskConstraints": {
      try {
        const m = await cred.enforceTaskConstraints(req.token, hex(req.pubHex), req.options);
        return { ok: true, mandateId: m.mandateId };
      } catch (e) {
        return { ok: false, code: e.code ?? null, message: e.message };
      }
    }
    case "checkTaskNarrowing":
      return { reason: cred.checkTaskNarrowing(req.parent, req.child) };
    case "taskSigningPayload":
      return { out: cred.taskMandateSigningPayloadV2(req.mandate) };
    case "jcs":
      return { out: core.canonicalizeJcs(req.value) };
    case "canonicalizeMessage":
      return { out: core.canonicalizeMessage(req.value) };
    case "buildEnvelope": {
      const env = await core.buildEnvelope(req.type, req.from, req.to, req.body, req.cid, hex(req.privHex), req.ttlSeconds ?? 300);
      return { envelope: env };
    }
    case "validateEnvelope": {
      const reg = new core.NonceRegistry();
      const first = await core.validateEnvelope(req.envelope, hex(req.pubHex), req.myDid, reg);
      const replay = await core.validateEnvelope(req.envelope, hex(req.pubHex), req.myDid, reg);
      return { first, replay };
    }
    case "encryptBody":
      return { encrypted: await core.encryptBody(req.plaintext, hex(req.pubHex)) };
    case "decryptBody":
      return { plaintext: await core.decryptBody(req.encrypted, hex(req.privHex)) };
    case "webDidRotated": {
      const a = await core.generateWebAgent(req.domain, req.path);
      const b = await core.rotateKey(a, req.coolDownHours ?? 24);
      return { did: a.did, before: a.webDocument, after: b.webDocument,
               oldTxt: a.dnsTXTRecord, newTxt: b.dnsTXTRecord };
    }
    case "resolveWebDid": {
      globalThis.fetch = async () => new Response(JSON.stringify(req.document), { status: 200 });
      try {
        const r = await core.resolveWebDID(req.did, {
          dnsResolver: async () => req.txt, now: new Date(req.now), logger: () => {},
        });
        return { ok: true, dnsVerified: r.dnsVerified, keyTrusted: r.keyTrusted,
                 acceptedKeys: r.acceptedKeys, deprecatedRotations: r.deprecatedRotations };
      } catch (e) {
        return { ok: false, message: e.message };
      }
    }
    case "verifyKel": {
      try {
        const s = await core.verifyKel(req.did, req.events, req.controllerEvents
          ? { resolveControllerKel: async () => req.controllerEvents } : {});
        return { ok: true, revoked: s.revoked, sequence: s.sequence, currentKeys: s.currentKeys };
      } catch (e) {
        return { ok: false, code: e.code ?? null, message: e.message };
      }
    }
    default:
      throw new Error(`unknown op ${req.op}`);
  }
}

process.stdout.write(JSON.stringify(await run(req)));
