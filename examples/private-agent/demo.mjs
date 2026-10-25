// E2E: a private agent that only two specific agent DIDs may call.
import { serve, signRequest } from "@aroha-sdk/run";

const PORT = 9401;
const ALICE = "did:aroha:alice";
const MALLORY = "did:aroha:mallory";

async function gen() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return {
    priv: new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)),
    pub: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)),
  };
}

const alice = await gen();
const mallory = await gen();

// The private agent: signed requests only, and only from Alice.
const keys = { [ALICE]: alice.pub, [MALLORY]: mallory.pub };
serve("private-agent", async ({ message }) => `handled: ${message}`, {
  auth: "aroha-sig",
  allowedCallers: [ALICE],
  resolveCallerKey: (did) => keys[did] ?? null,
}).start(PORT, "127.0.0.1");

await new Promise((r) => setTimeout(r, 300));

const URL_ = `http://127.0.0.1:${PORT}/v1/run`;
let pass = 0, fail = 0;
const check = (name, cond) => cond
  ? (pass++, console.log("  ✓", name))
  : (fail++, console.log("  ✗", name));

async function call(who, keypair, body) {
  const raw = JSON.stringify(body);
  const headers = await signRequest({
    did: who, privateKey: keypair.priv, method: "POST", path: "/v1/run", body: raw,
  });
  return fetch(URL_, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: raw });
}

console.log("\n═══ private agent, allow-list = [alice] ═══");

// 1. Unsigned request → rejected
const bare = await fetch(URL_, {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "hi" }),
});
check(`unsigned request rejected (${bare.status})`, bare.status === 401);

// 2. Alice (on the allow-list) → allowed
const ok = await call(ALICE, alice, { message: "hi" });
const okBody = await ok.json().catch(() => ({}));
check(`alice allowed (${ok.status})`, ok.status === 200 && okBody.message === "handled: hi");

// 3. Mallory: validly signed, but not on the allow-list → rejected
const mal = await call(MALLORY, mallory, { message: "let me in" });
check(`mallory rejected despite a valid signature (${mal.status})`, mal.status === 401);

// 4. Mallory impersonating Alice's DID with her own key → rejected
const rawImp = JSON.stringify({ message: "impersonating" });
const impHeaders = await signRequest({
  did: ALICE, privateKey: mallory.priv, method: "POST", path: "/v1/run", body: rawImp,
});
const imp = await fetch(URL_, {
  method: "POST", headers: { "Content-Type": "application/json", ...impHeaders }, body: rawImp,
});
check(`impersonation of alice's DID rejected (${imp.status})`, imp.status === 401);

// 5. Tampered body after signing → rejected
const rawOrig = JSON.stringify({ message: "transfer 10" });
const tamperHeaders = await signRequest({
  did: ALICE, privateKey: alice.priv, method: "POST", path: "/v1/run", body: rawOrig,
});
const tampered = await fetch(URL_, {
  method: "POST", headers: { "Content-Type": "application/json", ...tamperHeaders },
  body: JSON.stringify({ message: "transfer 10000" }),
});
check(`tampered body rejected (${tampered.status})`, tampered.status === 401);

// 6. Replay of alice's exact request → rejected
const rawReplay = JSON.stringify({ message: "replay me" });
const replayHeaders = await signRequest({
  did: ALICE, privateKey: alice.priv, method: "POST", path: "/v1/run", body: rawReplay,
});
const first = await fetch(URL_, {
  method: "POST", headers: { "Content-Type": "application/json", ...replayHeaders }, body: rawReplay,
});
const second = await fetch(URL_, {
  method: "POST", headers: { "Content-Type": "application/json", ...replayHeaders }, body: rawReplay,
});
check(`first accepted (${first.status}), replay rejected (${second.status})`,
      first.status === 200 && second.status === 401);

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
