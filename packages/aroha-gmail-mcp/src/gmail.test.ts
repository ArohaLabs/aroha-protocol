// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The Gmail layer.
 *
 * Two things here are worth testing hard: the MIME decoding, because Gmail's
 * shape is genuinely awkward and a wrong guess silently returns an empty
 * body; and the header encoding, because a subject is very often model output
 * and a newline in it would inject headers into a message a person is about
 * to trust.
 */

import { describe, it, expect } from "vitest";
import { GmailClient, plainTextOf, encodeMime, decodeMessage } from "./gmail.js";
import { GoogleAuth } from "./auth.js";

const b64u = (s: string) =>
  Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function authStub(): GoogleAuth {
  return { accessTokenNow: async () => "test-token" } as unknown as GoogleAuth;
}

describe("plainTextOf", () => {
  it("prefers text/plain from a multipart message", () => {
    expect(plainTextOf({
      mimeType: "multipart/alternative",
      parts: [
        { mimeType: "text/html", body: { data: b64u("<p>html</p>") } },
        { mimeType: "text/plain", body: { data: b64u("the plain one") } },
      ],
    })).toBe("the plain one");
  });

  it("falls back to html when there is no plain part", () => {
    expect(plainTextOf({
      mimeType: "multipart/alternative",
      parts: [{ mimeType: "text/html", body: { data: b64u("<p>only html</p>") } }],
    })).toBe("<p>only html</p>");
  });

  it("finds a body nested several parts deep", () => {
    // Real messages nest — multipart/mixed wrapping multipart/alternative is
    // the common shape once there is an attachment.
    expect(plainTextOf({
      mimeType: "multipart/mixed",
      parts: [{
        mimeType: "multipart/alternative",
        parts: [{ mimeType: "text/plain", body: { data: b64u("buried") } }],
      }],
    })).toBe("buried");
  });

  it("handles a single-part message with the body on the payload", () => {
    expect(plainTextOf({ mimeType: "text/plain", body: { data: b64u("simple") } })).toBe("simple");
  });

  it("decodes base64url, not plain base64", () => {
    // A body containing characters that encode to - and _ is where a plain
    // atob-style decode quietly produces mojibake instead of failing.
    const tricky = "e-mail ~ files/paths ?query=1&x=2";
    expect(plainTextOf({ mimeType: "text/plain", body: { data: b64u(tricky) } })).toBe(tricky);
  });

  it("returns empty rather than throwing on a shape it does not know", () => {
    // A message whose body cannot be extracted is still worth listing by
    // subject and sender, so this must not take the whole call down.
    expect(plainTextOf(undefined)).toBe("");
    expect(plainTextOf({ mimeType: "application/octet-stream" })).toBe("");
  });
});

describe("encodeMime", () => {
  const decode = (raw: string) =>
    Buffer.from(raw.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");

  it("writes the headers Gmail expects", () => {
    const mime = decode(encodeMime({ to: ["a@example.com"], subject: "Hello", body: "Hi there" }));
    expect(mime).toContain("To: a@example.com");
    expect(mime).toContain("Subject: Hello");
    expect(mime).toContain("Content-Type: text/plain; charset=UTF-8");
    expect(mime.endsWith("Hi there")).toBe(true);
  });

  it("strips newlines from a subject, so headers cannot be injected", () => {
    // The subject of a drafted email is very often model output. Without
    // this, a newline lets anything upstream add a Bcc to a message a person
    // is about to read and trust.
    const mime = decode(encodeMime({
      to: ["a@example.com"],
      subject: "Invoice\r\nBcc: attacker@evil.com",
      body: "body",
    }));
    expect(mime).not.toMatch(/^Bcc: attacker@evil\.com$/m);
    expect(mime).toContain("Subject: Invoice Bcc: attacker@evil.com");
  });

  it("strips newlines from recipients too", () => {
    const mime = decode(encodeMime({
      to: ["a@example.com\r\nBcc: attacker@evil.com"],
      subject: "s",
      body: "b",
    }));
    expect(mime).not.toMatch(/^Bcc: attacker@evil\.com$/m);
  });

  it("keeps newlines in the BODY, where they are just text", () => {
    const mime = decode(encodeMime({
      to: ["a@example.com"], subject: "s", body: "line one\nline two",
    }));
    expect(mime).toContain("line one\nline two");
  });

  it("omits cc and bcc headers entirely when there are none", () => {
    const mime = decode(encodeMime({ to: ["a@example.com"], subject: "s", body: "b" }));
    expect(mime).not.toContain("Cc:");
    expect(mime).not.toContain("Bcc:");
  });
});

describe("decodeMessage", () => {
  it("pulls the headers a person actually wants", () => {
    const msg = decodeMessage({
      id: "m1", threadId: "t1", snippet: "a snippet", labelIds: ["INBOX"],
      payload: {
        headers: [
          { name: "From", value: "Alice <a@example.com>" },
          { name: "Subject", value: "Quarterly figures" },
          { name: "Date", value: "Sat, 22 Aug 2026 10:00:00 +0000" },
          { name: "To", value: "me@example.com" },
        ],
        mimeType: "text/plain", body: { data: b64u("the body") },
      },
    }, true);
    expect(msg).toMatchObject({
      id: "m1", from: "Alice <a@example.com>", subject: "Quarterly figures",
      to: "me@example.com", snippet: "a snippet", body: "the body",
    });
  });

  it("matches header names case-insensitively", () => {
    // Gmail is consistent, but RFC 5322 header names are case-insensitive
    // and a proxy in between may normalise them.
    const msg = decodeMessage({
      id: "m", threadId: "t",
      payload: { headers: [{ name: "subject", value: "lowercase" }] },
    }, false);
    expect(msg.subject).toBe("lowercase");
  });

  it("leaves the body empty when it was not fetched", () => {
    const msg = decodeMessage({
      id: "m", threadId: "t",
      payload: { mimeType: "text/plain", body: { data: b64u("not asked for") } },
    }, false);
    expect(msg.body).toBe("");
  });
});

describe("GmailClient", () => {
  function clientReturning(handler: (url: string, init?: RequestInit) => unknown) {
    const calls: string[] = [];
    const fetchImpl = (async (url: Parameters<typeof fetch>[0], init?: RequestInit) => {
      calls.push(String(url));
      return new Response(JSON.stringify(handler(String(url), init)), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    return { client: new GmailClient(authStub(), fetchImpl), calls };
  }

  it("sends the access token as a bearer", async () => {
    let seen = "";
    const fetchImpl = (async (_u: Parameters<typeof fetch>[0], init?: RequestInit) => {
      seen = (init?.headers as Record<string, string>).authorization;
      return new Response(JSON.stringify({ labels: [] }), { status: 200 });
    }) as typeof fetch;
    await new GmailClient(authStub(), fetchImpl).listLabels();
    expect(seen).toBe("Bearer test-token");
  });

  it("caps the number of messages a search will fetch", async () => {
    // Every result costs a request, and a model asked for "all of them" will
    // cheerfully ask for five hundred.
    const { client, calls } = clientReturning((url) =>
      url.includes("/messages?")
        ? { messages: Array.from({ length: 25 }, (_, i) => ({ id: `m${i}` })) }
        : { id: "m", threadId: "t", payload: { headers: [] } });
    await client.searchMessages("is:unread", 500);
    expect(calls[0]).toContain("maxResults=25");
  });

  it("asks for metadata only when a full body was not requested", async () => {
    const { client, calls } = clientReturning((url) =>
      url.includes("/messages?") ? { messages: [{ id: "m1" }] }
        : { id: "m1", threadId: "t", payload: { headers: [] } });
    await client.searchMessages("x", 1, false);
    const get = calls.find((c) => c.includes("/messages/m1"))!;
    expect(get).toContain("format=metadata");
    expect(get).toContain("metadataHeaders=Subject");
  });

  it("returns an empty list for a search that matched nothing", async () => {
    // Gmail omits `messages` entirely rather than sending [].
    const { client } = clientReturning(() => ({ resultSizeEstimate: 0 }));
    expect(await client.searchMessages("from:nobody", 5)).toEqual([]);
  });

  it("surfaces Gmail's own error text", async () => {
    const fetchImpl = (async () => new Response(
      JSON.stringify({ error: { message: "Invalid query", status: "INVALID_ARGUMENT" } }),
      { status: 400 },
    )) as typeof fetch;
    await expect(new GmailClient(authStub(), fetchImpl).listLabels())
      .rejects.toThrow(/Invalid query/);
  });

  it("adds a scope hint to a permission error, which is the usual cause", async () => {
    const fetchImpl = (async () => new Response(
      JSON.stringify({ error: { message: "Request had insufficient authentication scopes.", status: "PERMISSION_DENIED" } }),
      { status: 403 },
    )) as typeof fetch;
    await expect(new GmailClient(authStub(), fetchImpl).listLabels())
      .rejects.toThrow(/may not have granted the scope/);
  });

  it("posts a draft rather than sending a message", async () => {
    const { client, calls } = clientReturning(() => ({ id: "d1", message: { threadId: "t1" } }));
    const draft = await client.createDraft({ to: ["a@example.com"], subject: "s", body: "b" });
    expect(calls[0]).toContain("/drafts");
    expect(calls[0]).not.toContain("/send");
    expect(draft).toEqual({ id: "d1", threadId: "t1" });
  });
});
