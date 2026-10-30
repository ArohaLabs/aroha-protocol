// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The tool layer.
 *
 * What matters here is what a MODEL receives, since that is what decides
 * whether it answers, retries, or apologises. Several of these assertions
 * exist because of watching a real agent misread a tool result during this
 * work: it treated a refusal as something to retry, and an empty result as a
 * failure.
 */

import { describe, it, expect } from "vitest";
import { runTool, TOOLS } from "./index.js";
import { configFromEnv, GoogleAuth } from "./auth.js";
import type { GmailClient } from "./gmail.js";

function gmailStub(over: Partial<Record<keyof GmailClient, unknown>> = {}): GmailClient {
  return {
    listLabels: async () => [{ id: "INBOX", name: "INBOX", messagesTotal: 3 }],
    searchMessages: async () => [
      { id: "m1", threadId: "t1", from: "a@example.com", to: "me@example.com",
        subject: "Hello", date: "Sat, 22 Aug 2026", snippet: "hi", body: "", labelIds: [] },
    ],
    getMessage: async () => ({
      id: "m1", threadId: "t1", from: "a@example.com", to: "me@example.com",
      subject: "Hello", date: "Sat, 22 Aug 2026", snippet: "hi", body: "full body", labelIds: [],
    }),
    createDraft: async () => ({ id: "d1", threadId: "t1" }),
    ...over,
  } as unknown as GmailClient;
}

const textOf = (r: { content: Array<{ text?: string }> }) => r.content[0].text ?? "";

describe("the tool list", () => {
  it("offers drafting but not sending", () => {
    const names = TOOLS.map((t) => t.name);
    expect(names).toContain("gmail_create_draft");
    // A draft is reviewable and reversible; sending is neither. The safer
    // primitive is the one worth exposing first.
    expect(names).not.toContain("gmail_send_message");
  });

  it("tells the model Gmail's query syntax, since it cannot guess it", () => {
    const search = TOOLS.find((t) => t.name === "gmail_search_messages")!;
    expect(search.description).toMatch(/from:/);
    expect(search.description).toMatch(/newer_than:|is:unread/);
  });

  it("says plainly that drafting does not send", () => {
    const draft = TOOLS.find((t) => t.name === "gmail_create_draft")!;
    expect(draft.description).toMatch(/never sends/i);
  });

  it("sets all four annotation hints on every tool, as booleans", () => {
    // A missing hint reads as "unknown" to clients, and some directories
    // reject tools without them.
    for (const tool of TOOLS) {
      for (const hint of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const) {
        expect(typeof tool.annotations[hint], `${tool.name}.${hint}`).toBe("boolean");
      }
    }
  });

  it("marks only the draft tool as writing, and nothing as destructive", () => {
    for (const tool of TOOLS) {
      expect(tool.annotations.readOnlyHint, tool.name).toBe(tool.name !== "gmail_create_draft");
      expect(tool.annotations.destructiveHint, tool.name).toBe(false);
    }
  });
});

describe("runTool", () => {
  it("returns the fields a person would want from a search", async () => {
    const out = textOf(await runTool(gmailStub(), "gmail_search_messages", { query: "from:a" }));
    expect(out).toContain("a@example.com");
    expect(out).toContain("Hello");
  });

  it("says no messages matched, rather than returning an empty array", async () => {
    // A model handed [] will often retry or apologise. A sentence closes it.
    const out = textOf(await runTool(
      gmailStub({ searchMessages: async () => [] }),
      "gmail_search_messages", { query: "from:nobody" },
    ));
    expect(out).toMatch(/No messages matched/);
    expect(out).toContain("from:nobody");
  });

  it("refuses an empty query with the syntax it wants", async () => {
    const res = await runTool(gmailStub(), "gmail_search_messages", { query: "  " });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/from:alice|Gmail syntax/);
  });

  it("reads one message in full", async () => {
    const out = textOf(await runTool(gmailStub(), "gmail_get_message", { messageId: "m1" }));
    expect(out).toContain("full body");
  });

  it("points at the search tool when no id was given", async () => {
    const res = await runTool(gmailStub(), "gmail_get_message", {});
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/gmail_search_messages/);
  });

  it("states that a created draft was not sent", async () => {
    // The one sentence that decides whether somebody trusts the tool.
    const out = textOf(await runTool(gmailStub(), "gmail_create_draft", {
      to: ["a@example.com"], subject: "s", body: "b",
    }));
    expect(out).toMatch(/NOT been sent/);
    expect(out).toContain("d1");
  });

  it("refuses a draft with no recipient", async () => {
    const res = await runTool(gmailStub(), "gmail_create_draft", { to: [], subject: "s", body: "b" });
    expect(res.isError).toBe(true);
  });

  it("passes Gmail's own error text through", async () => {
    const res = await runTool(
      gmailStub({ listLabels: async () => { throw new Error("Invalid query: bad operator"); } }),
      "gmail_list_labels", {},
    );
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain("Invalid query: bad operator");
  });

  it("reports an unknown tool rather than throwing", async () => {
    const res = await runTool(gmailStub(), "gmail_delete_everything", {});
    expect(res.isError).toBe(true);
  });
});

describe("configFromEnv", () => {
  it("names exactly what is missing", () => {
    // A server that starts happily and then refuses every call is the
    // failure this whole area kept producing.
    expect(() => configFromEnv({} as NodeJS.ProcessEnv))
      .toThrow(/GOOGLE_CLIENT_ID and GOOGLE_REFRESH_TOKEN/);
    expect(() => configFromEnv({ GOOGLE_CLIENT_ID: "x" } as NodeJS.ProcessEnv))
      .toThrow(/GOOGLE_REFRESH_TOKEN/);
  });

  it("points at the login command rather than leaving somebody guessing", () => {
    expect(() => configFromEnv({} as NodeJS.ProcessEnv)).toThrow(/login/);
  });

  it("treats a client secret as optional, because a Desktop client has none", () => {
    const cfg = configFromEnv({ GOOGLE_CLIENT_ID: "id", GOOGLE_REFRESH_TOKEN: "rt" } as NodeJS.ProcessEnv);
    expect(cfg.clientSecret).toBeUndefined();
  });
});

describe("GoogleAuth", () => {
  function authWith(replies: Array<Record<string, unknown>>, now = () => 0) {
    let n = 0;
    const calls: string[] = [];
    const fetchImpl = (async (_u: Parameters<typeof fetch>[0], init?: RequestInit) => {
      calls.push(String(init?.body));
      return new Response(JSON.stringify(replies[Math.min(n++, replies.length - 1)]), { status: 200 });
    }) as typeof fetch;
    return {
      auth: new GoogleAuth({ clientId: "id", refreshToken: "rt", fetchImpl, now }),
      calls,
    };
  }

  it("mints an access token from the refresh token", async () => {
    const { auth, calls } = authWith([{ access_token: "at", expires_in: 3600 }]);
    expect(await auth.accessTokenNow()).toBe("at");
    expect(calls[0]).toContain("grant_type=refresh_token");
  });

  it("caches it rather than refreshing on every call", async () => {
    const { auth, calls } = authWith([{ access_token: "at", expires_in: 3600 }]);
    await auth.accessTokenNow();
    await auth.accessTokenNow();
    expect(calls).toHaveLength(1);
  });

  it("renews before expiry rather than at it", async () => {
    // A token that expires mid-request fails with a 401 that reads exactly
    // like a bad credential.
    let clock = 0;
    const { auth, calls } = authWith(
      [{ access_token: "first", expires_in: 3600 }, { access_token: "second", expires_in: 3600 }],
      () => clock,
    );
    expect(await auth.accessTokenNow()).toBe("first");
    clock = 3600_000 - 30_000;   // inside the safety margin
    expect(await auth.accessTokenNow()).toBe("second");
    expect(calls).toHaveLength(2);
  });

  it("omits the client secret when there is none", async () => {
    const { auth, calls } = authWith([{ access_token: "at", expires_in: 60 }]);
    await auth.accessTokenNow();
    // Sending an empty client_secret is not the same as sending none.
    expect(calls[0]).not.toContain("client_secret");
  });

  it("explains a refusal in terms somebody can act on", async () => {
    const fetchImpl = (async () => new Response(
      JSON.stringify({ error: "invalid_grant", error_description: "Token has been expired or revoked." }),
      { status: 400 },
    )) as typeof fetch;
    const auth = new GoogleAuth({ clientId: "id", refreshToken: "rt", fetchImpl });
    await expect(auth.accessTokenNow()).rejects.toThrow(/revoked|client id and secret/);
  });
});
