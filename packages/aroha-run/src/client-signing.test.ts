// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// callAgent/streamAgent with `signAs`, verified against the REAL serve()
// handler rather than a mock verifier.
//
// A mock would happily accept whatever the client produced and prove nothing.
// The property that matters is that the two halves agree — same canonical
// string, same path, same body bytes — so these tests wire the client's fetch
// straight into the server's request handler and let the real verification run.

import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import { callAgent, streamAgent } from "./client.js";
import { serve } from "./serve.js";

const ALICE = "did:aroha:alice";
const MALLORY = "did:aroha:mallory";
const DID_HASH = "abc123";

let alicePriv: Uint8Array;
let alicePub: Uint8Array;
let malloryPriv: Uint8Array;
let malloryPub: Uint8Array;

async function generate() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const priv = new Uint8Array(await crypto.subtle.exportKey("pkcs8", (kp as CryptoKeyPair).privateKey));
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", (kp as CryptoKeyPair).publicKey));
  return { priv, pub };
}

const KEYS: Record<string, Uint8Array> = {};

// One hook, not two. Populating KEYS from a second beforeAll created an
// implicit ordering dependency between hooks — it ran with the key variables
// still undefined, so every signed request failed key resolution and only the
// negative tests passed. Keep generation and registration together.
beforeAll(async () => {
  ({ priv: alicePriv, pub: alicePub } = await generate());
  ({ priv: malloryPriv, pub: malloryPub } = await generate());
  KEYS[ALICE] = alicePub;
  KEYS[MALLORY] = malloryPub;
});

afterEach(() => { vi.unstubAllGlobals(); });

/** A private agent that only Alice may call. */
function privateAgent(allowedCallers?: string[]) {
  return serve("private-agent", async ({ message }) => `Echo: ${message}`, {
    auth: "aroha-sig",
    allowedCallers,
    // Resolve from a local map so the test never touches the live registry.
    resolveCallerKey: (did) => KEYS[did] ?? null,
  });
}

/**
 * Route the client's fetch into the agent's handler.
 *
 * The registry lookup is intercepted too, so resolveAgent returns a local
 * endpoint without a network call.
 */
function wire(agent: ReturnType<typeof serve>, endpoint = "https://agent.test") {
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;

    if (url.includes("/v1/agents/")) {
      return new Response(JSON.stringify({ endpointUrl: endpoint, active: true }), { status: 200 });
    }
    return agent.fetch(new Request(url, init));
  });
}

describe("callAgent with signAs", () => {
  it("an allow-listed caller is accepted end to end", async () => {
    wire(privateAgent([ALICE]));

    const res = await callAgent(DID_HASH, "Hello", {
      signAs: { did: ALICE, privateKey: alicePriv },
    });

    expect(res.message).toBe("Echo: Hello");
  });

  it("an unsigned call to the same agent is rejected", async () => {
    wire(privateAgent([ALICE]));

    await expect(callAgent(DID_HASH, "Hello")).rejects.toThrow(/401|authentication/i);
  });

  // The whole point of signing over the caller's DID: a valid signature from
  // the wrong identity is still the wrong identity.
  it("a caller outside allowedCallers is rejected despite a valid signature", async () => {
    wire(privateAgent([ALICE]));

    await expect(
      callAgent(DID_HASH, "Hello", { signAs: { did: MALLORY, privateKey: malloryPriv } }),
    ).rejects.toThrow(/signature|401/i);
  });

  it("cannot impersonate by claiming another DID with your own key", async () => {
    wire(privateAgent([ALICE]));

    await expect(
      callAgent(DID_HASH, "Hello", { signAs: { did: ALICE, privateKey: malloryPriv } }),
    ).rejects.toThrow(/signature|401/i);
  });

  it("reports a signature failure differently from a missing bearer token", async () => {
    wire(privateAgent([ALICE]));

    // Signed but not permitted → the message should point at the signature,
    // not tell the developer to go find a bearer token.
    const signedErr = await callAgent(DID_HASH, "Hi", {
      signAs: { did: MALLORY, privateKey: malloryPriv },
    }).catch((e: Error) => e);
    expect(signedErr.message).toMatch(/allowedCallers|signature|clock skew/i);
    expect(signedErr.message).not.toMatch(/pass bearerToken/i);

    const unsignedErr = await callAgent(DID_HASH, "Hi").catch((e: Error) => e);
    expect(unsignedErr.message).toMatch(/bearerToken|signAs/i);
  });

  // With no allow-list the agent takes any verifiable caller — attribution
  // rather than restriction.
  it("without an allow-list, any caller with a resolvable key is accepted", async () => {
    wire(privateAgent(undefined));

    const res = await callAgent(DID_HASH, "Hello", {
      signAs: { did: MALLORY, privateKey: malloryPriv },
    });

    expect(res.message).toBe("Echo: Hello");
  });

  // The signature covers a hash of the body, so the bytes that were signed must
  // be the bytes that are sent. This is the regression test for anyone
  // "tidying up" prepareRequest by re-serialising the payload at the fetch call.
  it("sends exactly the body that was signed", async () => {
    const agent = privateAgent([ALICE]);
    let sentBody: string | undefined;

    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/v1/agents/")) {
        return new Response(JSON.stringify({ endpointUrl: "https://agent.test", active: true }), { status: 200 });
      }
      sentBody = init?.body as string;
      return agent.fetch(new Request(url, init));
    });

    await callAgent(DID_HASH, "Hello", { signAs: { did: ALICE, privateKey: alicePriv } });

    expect(typeof sentBody).toBe("string");
    // Verification already passed, which is the real proof; assert the shape
    // too so a failure here is self-explanatory.
    expect(JSON.parse(sentBody!).message).toBe("Hello");
  });
});

describe("streamAgent with signAs", () => {
  it("streams from a private agent when correctly signed", async () => {
    wire(
      serve(
        "streaming-private-agent",
        async function* ({ message }) {
          yield message.toUpperCase();
        },
        {
          auth: "aroha-sig",
          allowedCallers: [ALICE],
          resolveCallerKey: (did) => KEYS[did] ?? null,
        },
      ),
    );

    const events = [];
    for await (const ev of streamAgent(DID_HASH, "hello", {
      signAs: { did: ALICE, privateKey: alicePriv },
    })) {
      events.push(ev);
    }

    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.type === "final" || e.type === "token")).toBe(true);
  });

  it("rejects an unsigned stream request", async () => {
    wire(privateAgent([ALICE]));

    await expect(async () => {
      for await (const _ of streamAgent(DID_HASH, "hello")) { /* drain */ }
    }).rejects.toThrow(/401|authentication/i);
  });
});

describe("a verified signature names the caller", () => {
  it("the handler is told which agent signed, and the host cannot override it", async () => {
    // A signature is proof; ServeOptions.resolveCaller is an assertion. When
    // both are present the proof wins — otherwise a host bug could relabel a
    // cryptographically identified agent as any person it liked.
    let seen: { kind: string; id: string } | undefined;
    const agent = serve("named-agent", (ctx) => { seen = ctx.caller; return "ok"; }, {
      auth: "aroha-sig",
      allowedCallers: [ALICE],
      resolveCallerKey: (did) => KEYS[did] ?? null,
      resolveCaller: () => ({ kind: "person", id: "the-host-would-say-this" }),
    });
    wire(agent);

    await callAgent(DID_HASH, "Hello", { signAs: { did: ALICE, privateKey: alicePriv } });

    expect(seen).toEqual({ kind: "agent", id: ALICE });
  });
});
