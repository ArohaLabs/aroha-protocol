// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * sandbox-summarizer — public sandbox text summarization agent
 *
 * DID: did:aroha:sandbox-summarizer
 * Returns mock summaries — no LLM calls in sandbox mode.
 * In production, wire to ANTHROPIC_API_KEY for real summarization.
 */

import { ArohaServer, type ArohaRequestBody, type ArohaResponseBody, type DIDDocument } from "@aroha-sdk/core";

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "did:aroha:sandbox-summarizer";
const PORT = Number(process.env.PORT ?? 3014);
// Loopback unless AGENT_HOST says otherwise. docker-compose.yml sets
// AGENT_HOST=0.0.0.0 so the published container port is reachable.
const HOST = process.env.AGENT_HOST ?? "127.0.0.1";
if (!["127.0.0.1", "::1", "localhost"].includes(HOST)) {
  console.warn(`[sandbox-summarizer] AGENT_HOST=${HOST} — listener is reachable from other machines`);
}

async function realSummarize(text: string): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    const words = text.split(/\s+/);
    const preview = words.slice(0, 20).join(" ");
    return `[Sandbox summary] ${preview}${words.length > 20 ? "..." : ""} (${words.length} words input)`;
  }

  // Real path — only used if ANTHROPIC_API_KEY is set
  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": apiKey, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 256,
      messages: [{ role: "user", content: `Summarize in 2-3 sentences:\n\n${text.slice(0, 4000)}` }],
    }),
  });
  const data = await resp.json() as { content: Array<{ text: string }> };
  return data.content[0]?.text ?? "[No summary]";
}

const handlers: Record<string, (params: Record<string, unknown>) => Promise<unknown>> = {
  "summarize-text": async ({ text, maxLength = 256 }) => {
    const summary = await realSummarize(String(text ?? ""));
    return {
      summary: summary.slice(0, Number(maxLength)),
      wordCount: String(text ?? "").split(/\s+/).length,
      summarizedAt: new Date().toISOString(),
      model: process.env.ANTHROPIC_API_KEY ? "claude-haiku-4-5-20251001" : "sandbox-mock",
    };
  },

  "summarize-url": async ({ url }) => {
    const summary = await realSummarize(`Content from ${String(url)}`);
    return {
      url,
      summary,
      fetchedAt: new Date().toISOString(),
      model: process.env.ANTHROPIC_API_KEY ? "claude-haiku-4-5-20251001" : "sandbox-mock",
      _sandbox: !process.env.ANTHROPIC_API_KEY,
    };
  },
};

async function main() {
  const server = new ArohaServer({
    agentDID: AGENT_DID,
    port: PORT,
    host: HOST,
    // Sandbox agents hold no signing key: the document carries only the service entry.
    didDocument: { "@context": ["https://www.w3.org/ns/did/v1"], id: AGENT_DID, service: [{ id: `${AGENT_DID}#aroha`, type: "ArohaEndpoint", serviceEndpoint: `http://localhost:${PORT}` }] } as DIDDocument,
    resolvePublicKey: async () => null,
    onMessage: async (envelope, respond) => {
      if (envelope.type !== "ArohaRequest") return;
      const body = envelope.body as ArohaRequestBody;
      const handler = handlers[body.capability];
      const result = handler ? await handler(body.params as Record<string, unknown>) : { error: `Unknown capability: ${body.capability}` };
      const responseBody: ArohaResponseBody = { capability: body.capability, result: result as Record<string, unknown> };
      respond({ type: "ArohaResponse", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: responseBody, signature: "sandbox-no-sig" } as never);
    },
  });

  await server.start();
  console.log(`[sandbox-summarizer] ${AGENT_DID}  →  http://localhost:${PORT}`);
  if (process.env.ANTHROPIC_API_KEY) {
    console.log(`[sandbox-summarizer] Real Claude summarization enabled`);
  } else {
    console.log(`[sandbox-summarizer] Mock mode — set ANTHROPIC_API_KEY for real summaries`);
  }
}

main().catch((err) => { console.error("[sandbox-summarizer]", err); process.exit(1); });
