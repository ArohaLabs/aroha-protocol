// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Who the handler is told it is talking to.
 *
 * The interesting cases are all negative: a caller that could name itself in
 * its own request body could name anyone, so the tests that matter are the
 * ones proving the wire cannot set this.
 */

import { describe, it, expect } from "vitest";
import { serve as rawServe } from "./serve.js";

// serve() now defaults to auth: "aroha-sig". These tests exercise behaviour
// orthogonal to authentication, so they opt in to an open agent explicitly;
// tests that pass their own `auth` keep it.
const serve: typeof rawServe = (name, handler, options = {}) =>
  rawServe(name, handler, { auth: "none", ...options });
import { UNATTRIBUTED_CALLER, type Caller, type HandlerContext } from "./types.js";

/** Runs one request against a served agent and reports the caller it saw. */
async function callerSeenBy(
  options: Parameters<typeof serve>[2],
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<Caller> {
  let seen: Caller | undefined;
  const agent = serve(
    "t",
    (ctx: HandlerContext) => {
      seen = ctx.caller;
      return "ok";
    },
    options,
  );
  await agent.fetch(
    new Request("http://agent.local/v1/run", {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
  );
  return seen!;
}

describe("ctx.caller", () => {
  it("is unattributed when nobody can be identified", async () => {
    // Not undefined: a handler that forgets to check then keys off an id
    // belonging to no one, rather than silently pooling every caller into a
    // single bucket.
    const caller = await callerSeenBy({}, { message: "hi" });
    expect(caller).toEqual({ kind: "unattributed", id: UNATTRIBUTED_CALLER });
  });

  it("IGNORES a caller supplied in the request body", async () => {
    // The whole reason this is not on the wire.
    const caller = await callerSeenBy({}, {
      message: "hi",
      caller: { kind: "person", id: "did:aroha:personal:the-boss" },
    });
    expect(caller.kind).toBe("unattributed");
    expect(caller.id).not.toContain("the-boss");
  });

  it("takes the host's answer when the host can identify someone", async () => {
    const caller = await callerSeenBy(
      { resolveCaller: () => ({ kind: "person", id: "user-42", displayName: "Dana" }) },
      { message: "hi" },
    );
    expect(caller).toEqual({ kind: "person", id: "user-42", displayName: "Dana" });
  });

  it("lets the host read the request it admitted", async () => {
    const caller = await callerSeenBy(
      {
        resolveCaller: (req) => {
          const id = req.headers.get("x-host-user");
          return id ? { kind: "person" as const, id } : undefined;
        },
      },
      { message: "hi" },
      { "x-host-user": "user-7" },
    );
    expect(caller).toEqual({ kind: "person", id: "user-7" });
  });

  it("is unattributed when the host declines to identify anyone", async () => {
    const caller = await callerSeenBy(
      { resolveCaller: () => undefined },
      { message: "hi" },
    );
    expect(caller.kind).toBe("unattributed");
  });

  it("accepts an async host resolver", async () => {
    const caller = await callerSeenBy(
      { resolveCaller: async () => ({ kind: "person" as const, id: "user-9" }) },
      { message: "hi" },
    );
    expect(caller.id).toBe("user-9");
  });
});

describe("precedence", () => {
  it("the host's answer beats a body that names someone else", async () => {
    // The signature-beats-host half is in client-signing.test.ts, which has
    // the key harness to produce a real one.
    const caller = await callerSeenBy(
      { resolveCaller: () => ({ kind: "person" as const, id: "the-host-answer" }) },
      { message: "hi", caller: { kind: "agent", id: "did:aroha:forged" } },
    );
    expect(caller.id).toBe("the-host-answer");
  });
});
