#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/gmail-mcp
 *
 * An MCP stdio server for Gmail, built against the ORDINARY Gmail API.
 *
 * ── Why this exists ──────────────────────────────────────────────────────
 *
 * Google publishes a Gmail MCP server at `gmailmcp.googleapis.com`. It is
 * part of the Google Workspace Developer Preview Program, and a project that
 * is not enrolled cannot use it — every call is answered
 * "The caller does not have permission", regardless of scopes, regardless of
 * the API being enabled, and with nothing in the message to say why.
 *
 * That was established by measurement, not inference: one account, one token
 * carrying every scope that service lists, refused by the preview endpoint
 * and accepted by `gmail.googleapis.com` in the same minute. The capability
 * was never out of reach — only that one endpoint was.
 *
 * So this server exposes the same shape of tools over the API that is
 * actually open to everybody.
 *
 * ── Setup ────────────────────────────────────────────────────────────────
 *
 *   1. Create an OAuth client in Google Cloud (Desktop app if offered; a Web
 *      application works too, and then you also need its client secret).
 *   2. GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... npx aroha-gmail-mcp login
 *   3. Put the printed refresh token in this server's environment.
 *
 * In Aroha: Tools → Add manually, command `npx`, arguments
 * `-y @aroha-sdk/gmail-mcp`. Every call still passes through mcp-guard, so a
 * draft is gated the same as any other tool.
 *
 * Tools exposed:
 *   gmail_search_messages  — search the mailbox with Gmail's own query syntax
 *   gmail_get_message      — read one message in full
 *   gmail_list_labels      — labels, with unread counts
 *   gmail_create_draft     — compose a draft (never sends)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { GoogleAuth, configFromEnv } from "./auth.js";
import { GmailClient } from "./gmail.js";
import { login, DEFAULT_SCOPES } from "./login.js";

/**
 * MCP tool annotations. All four hints are set on every tool, because clients
 * and directories treat a missing hint as unknown. Every tool talks to the
 * Gmail API, so all are open-world; only the draft writes, and it never
 * changes or removes anything that already exists.
 */
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;
const CREATES_DRAFT = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true } as const;

export const TOOLS = [
  {
    name: "gmail_search_messages",
    description:
      "Search the signed-in mailbox using Gmail's own query syntax (for example " +
      "'from:alice newer_than:7d', 'subject:invoice has:attachment', 'is:unread'). " +
      "Returns sender, subject, date and a snippet for each match. Use gmail_get_message " +
      "to read one in full.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "A Gmail search query." },
        limit: {
          type: "number",
          description: "How many messages to return, 1-25. Defaults to 10.",
        },
      },
      required: ["query"],
    },
    annotations: READ_ONLY,
  },
  {
    name: "gmail_get_message",
    description:
      "Read one message in full, including its body text. Takes an id from " +
      "gmail_search_messages.",
    inputSchema: {
      type: "object",
      properties: { messageId: { type: "string", description: "The message id." } },
      required: ["messageId"],
    },
    annotations: READ_ONLY,
  },
  {
    name: "gmail_list_labels",
    description: "List the mailbox's labels, with message and unread counts.",
    inputSchema: { type: "object", properties: {} },
    annotations: READ_ONLY,
  },
  {
    name: "gmail_create_draft",
    description:
      "Create a draft email. This never sends: the draft appears in Gmail for a " +
      "person to review, edit and send themselves.",
    inputSchema: {
      type: "object",
      properties: {
        to: { type: "array", items: { type: "string" }, description: "Recipient addresses." },
        subject: { type: "string" },
        body: { type: "string", description: "Plain text body." },
        cc: { type: "array", items: { type: "string" } },
        bcc: { type: "array", items: { type: "string" } },
      },
      required: ["to", "subject", "body"],
    },
    annotations: CREATES_DRAFT,
  },
] as const;

/**
 * Run one tool.
 *
 * Exported so the tools can be tested without a transport — the MCP plumbing
 * below adds nothing this needs, and a test that has to speak stdio to check
 * a search result is testing the SDK rather than this server.
 */
export async function runTool(
  gmail: GmailClient,
  name: string,
  args: Record<string, unknown>,
): Promise<CallToolResult> {
  const text = (value: unknown): CallToolResult => ({
    content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }],
  });

  try {
    switch (name) {
      case "gmail_search_messages": {
        const query = String(args.query ?? "").trim();
        if (!query) return fail("A query is required. Gmail syntax, e.g. 'from:alice newer_than:7d'.");
        const limit = typeof args.limit === "number" ? args.limit : 10;
        const found = await gmail.searchMessages(query, limit, false);
        // An empty result is an ANSWER, not an error — said plainly, because
        // a model handed [] will otherwise often retry or apologise.
        if (found.length === 0) return text(`No messages matched ${query}.`);
        return text(found.map((m) => ({
          id: m.id, from: m.from, to: m.to, subject: m.subject, date: m.date, snippet: m.snippet,
        })));
      }
      case "gmail_get_message": {
        const id = String(args.messageId ?? "").trim();
        if (!id) return fail("A messageId is required — take one from gmail_search_messages.");
        return text(await gmail.getMessage(id, true));
      }
      case "gmail_list_labels":
        return text(await gmail.listLabels());
      case "gmail_create_draft": {
        const to = Array.isArray(args.to) ? args.to.map(String).filter(Boolean) : [];
        if (to.length === 0) return fail("At least one recipient is required.");
        const draft = await gmail.createDraft({
          to,
          subject: String(args.subject ?? ""),
          body: String(args.body ?? ""),
          cc: Array.isArray(args.cc) ? args.cc.map(String) : undefined,
          bcc: Array.isArray(args.bcc) ? args.bcc.map(String) : undefined,
        });
        return text(
          `Draft created (id ${draft.id}). It has NOT been sent — it is in the Drafts folder ` +
          "for you to review and send.",
        );
      }
      default:
        return fail(`Unknown tool: ${name}`);
    }
  } catch (e) {
    // Gmail's own message, which is specific and worth passing through
    // untouched — unlike the preview endpoint's, it names the real problem.
    return fail((e as Error).message);
  }
}

function fail(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

async function main(): Promise<void> {
  if (process.argv[2] === "login") {
    const clientId = process.env.GOOGLE_CLIENT_ID?.trim();
    if (!clientId) {
      process.stderr.write("Set GOOGLE_CLIENT_ID (and GOOGLE_CLIENT_SECRET for a Web client).\n");
      process.exit(1);
    }
    const scopes = process.env.GOOGLE_SCOPES?.trim()
      ? process.env.GOOGLE_SCOPES.trim().split(/\s+/)
      : DEFAULT_SCOPES;
    const refreshToken = await login({
      clientId,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET?.trim(),
      scopes,
      // Set this to the URI already registered on a Web-application client,
      // so signing in needs no second entry in the Google console.
      redirectUri: process.env.GOOGLE_REDIRECT_URI?.trim() || undefined,
    });
    // stdout, so it can be piped; everything explanatory went to stderr.
    process.stdout.write(`${refreshToken}\n`);
    return;
  }

  const auth = new GoogleAuth(configFromEnv());
  const gmail = new GmailClient(auth);
  const server = new Server(
    { name: "aroha-gmail-mcp", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) =>
    runTool(gmail, req.params.name, (req.params.arguments ?? {}) as Record<string, unknown>),
  );

  await server.connect(new StdioServerTransport());
}

// Only when run as a program: importing this module for its tools must not
// start a server or read the environment.
const invokedDirectly = process.argv[1]?.includes("aroha-gmail-mcp") ||
  process.argv[1]?.endsWith("index.js");
if (invokedDirectly) {
  main().catch((err) => {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
}
