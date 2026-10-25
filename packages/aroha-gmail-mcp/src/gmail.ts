// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The Gmail API, as much of it as this server exposes.
 *
 * Deliberately thin. Each function is one documented Gmail endpoint plus the
 * decoding Gmail's wire format demands — nothing here interprets a message or
 * decides what a caller wanted. The tool layer above adds no logic either, so
 * a reader can hold "which endpoint does this tool hit" in their head.
 *
 * ── The two things Gmail makes awkward ───────────────────────────────────
 *
 * BODIES ARE BASE64URL, NESTED. A message body is buried in a MIME part tree
 * whose leaves carry base64url data, and which part is the readable one
 * depends on whether the sender sent text, HTML, or both. `plainTextOf` walks
 * that tree once, preferring text/plain, because handing a model a raw part
 * tree is handing it the problem.
 *
 * SEARCH RETURNS IDS, NOT MESSAGES. `users.messages.list` gives ids and
 * nothing else, so a useful search is a list call plus one get per result.
 * That is a real cost, which is why `searchMessages` takes a limit and
 * fetches metadata-only unless a caller asks for more.
 */

import type { GoogleAuth } from "./auth.js";

const BASE = "https://gmail.googleapis.com/gmail/v1/users/me";

export interface GmailHeaderSummary {
  id: string;
  threadId: string;
  from: string;
  to: string;
  subject: string;
  date: string;
  snippet: string;
}

export interface GmailMessage extends GmailHeaderSummary {
  body: string;
  labelIds: string[];
}

export interface GmailLabel {
  id: string;
  name: string;
  messagesTotal?: number;
  messagesUnread?: number;
}

export class GmailClient {
  constructor(
    private readonly auth: GoogleAuth,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  private async call(path: string, init: RequestInit = {}): Promise<unknown> {
    const token = await this.auth.accessTokenNow();
    const res = await this.fetchImpl(`${BASE}${path}`, {
      ...init,
      headers: {
        ...(init.headers as Record<string, string> | undefined),
        authorization: `Bearer ${token}`,
        accept: "application/json",
      },
    });
    const body = (await res.json().catch(() => ({}))) as {
      error?: { message?: string; status?: string };
    };
    if (!res.ok) {
      // Gmail's own sentence, which is specific and useful — unlike the
      // preview MCP endpoint's, this one names the actual problem.
      const detail = body.error?.message ?? `HTTP ${res.status}`;
      throw new Error(
        body.error?.status === "PERMISSION_DENIED"
          ? `${detail} (the signed-in account may not have granted the scope this needs)`
          : detail,
      );
    }
    return body;
  }

  async listLabels(): Promise<GmailLabel[]> {
    const body = (await this.call("/labels")) as { labels?: GmailLabel[] };
    return body.labels ?? [];
  }

  /**
   * Search, then fetch each hit.
   *
   * `limit` is enforced here rather than trusted from the caller, because
   * every result costs a request and a model asked for "all of them" will
   * cheerfully ask for five hundred.
   */
  async searchMessages(query: string, limit = 10, full = false): Promise<GmailMessage[]> {
    const capped = Math.max(1, Math.min(limit, 25));
    const params = new URLSearchParams({ q: query, maxResults: String(capped) });
    const list = (await this.call(`/messages?${params}`)) as {
      messages?: Array<{ id: string }>;
    };
    const ids = (list.messages ?? []).map((m) => m.id);
    return Promise.all(ids.map((id) => this.getMessage(id, full)));
  }

  async getMessage(id: string, full = true): Promise<GmailMessage> {
    // metadata format is markedly cheaper and is all a search listing needs;
    // full is fetched only when somebody actually wants to read the thing.
    const params = full
      ? new URLSearchParams({ format: "full" })
      : new URLSearchParams({
          format: "metadata",
          ...{} as Record<string, string>,
        });
    if (!full) {
      for (const h of ["From", "To", "Subject", "Date"]) params.append("metadataHeaders", h);
    }
    const raw = (await this.call(`/messages/${encodeURIComponent(id)}?${params}`)) as RawMessage;
    return decodeMessage(raw, full);
  }

  /**
   * Create a draft. Deliberately NOT send.
   *
   * A draft is reviewable and reversible; sending is neither. The runtime's
   * approval rail gates tool calls either way, but the safer primitive is the
   * one worth exposing first — and "draft it and let me look" is what people
   * actually asked for.
   */
  async createDraft(input: {
    to: string[];
    subject: string;
    body: string;
    cc?: string[];
    bcc?: string[];
  }): Promise<{ id: string; threadId?: string }> {
    const raw = encodeMime(input);
    const created = (await this.call("/drafts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: { raw } }),
    })) as { id?: string; message?: { threadId?: string } };
    return { id: created.id ?? "", ...(created.message?.threadId ? { threadId: created.message.threadId } : {}) };
  }
}

interface RawMessage {
  id: string;
  threadId: string;
  snippet?: string;
  labelIds?: string[];
  payload?: MimePart;
}

interface MimePart {
  mimeType?: string;
  headers?: Array<{ name: string; value: string }>;
  body?: { data?: string; size?: number };
  parts?: MimePart[];
}

function headerOf(part: MimePart | undefined, name: string): string {
  const found = (part?.headers ?? []).find((h) => h.name.toLowerCase() === name.toLowerCase());
  return found?.value ?? "";
}

/** base64url, which is not what atob expects. */
function decodeBase64Url(data: string): string {
  const padded = data.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64").toString("utf8");
}

/**
 * The readable text of a message.
 *
 * Walks the part tree preferring text/plain, falling back to text/html, and
 * finally to whatever single body exists. Returns "" rather than throwing on
 * a shape it does not recognise: a message whose body cannot be extracted is
 * still worth listing by subject and sender.
 */
export function plainTextOf(payload: MimePart | undefined): string {
  if (!payload) return "";

  const collect = (part: MimePart, wanted: string): string | null => {
    if (part.mimeType === wanted && part.body?.data) return decodeBase64Url(part.body.data);
    for (const child of part.parts ?? []) {
      const found = collect(child, wanted);
      if (found !== null) return found;
    }
    return null;
  };

  return (
    collect(payload, "text/plain") ??
    collect(payload, "text/html") ??
    (payload.body?.data ? decodeBase64Url(payload.body.data) : "")
  );
}

export function decodeMessage(raw: RawMessage, full: boolean): GmailMessage {
  return {
    id: raw.id,
    threadId: raw.threadId,
    from: headerOf(raw.payload, "From"),
    to: headerOf(raw.payload, "To"),
    subject: headerOf(raw.payload, "Subject"),
    date: headerOf(raw.payload, "Date"),
    snippet: raw.snippet ?? "",
    labelIds: raw.labelIds ?? [],
    body: full ? plainTextOf(raw.payload) : "",
  };
}

/**
 * An RFC 5322 message, base64url encoded, which is what drafts.create wants.
 *
 * Header values are stripped of CR and LF before being written. Without that,
 * a subject containing a newline would inject arbitrary headers — a Bcc, a
 * different From — into a message a person is about to be shown and trust.
 * The subject of a drafted email is very often model output, so this is a
 * real path rather than a theoretical one.
 */
export function encodeMime(input: {
  to: string[]; subject: string; body: string; cc?: string[]; bcc?: string[];
}): string {
  const clean = (value: string) => value.replace(/[\r\n]+/g, " ").trim();
  const lines = [
    `To: ${input.to.map(clean).join(", ")}`,
    ...(input.cc?.length ? [`Cc: ${input.cc.map(clean).join(", ")}`] : []),
    ...(input.bcc?.length ? [`Bcc: ${input.bcc.map(clean).join(", ")}`] : []),
    `Subject: ${clean(input.subject)}`,
    "Content-Type: text/plain; charset=UTF-8",
    "MIME-Version: 1.0",
    "",
    input.body,
  ];
  return Buffer.from(lines.join("\r\n"), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
