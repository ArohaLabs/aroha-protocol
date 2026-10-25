// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * sandbox-web-search — public sandbox web search agent
 *
 * DID: did:aroha:sandbox-web-search
 * Returns mock search results — useful for testing orchestration flows.
 */

import { ArohaServer, type ArohaRequestBody, type ArohaResponseBody, type DIDDocument } from "@aroha-sdk/core";

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "did:aroha:sandbox-web-search";
const PORT = Number(process.env.PORT ?? 3013);
// Loopback unless AGENT_HOST says otherwise. docker-compose.yml sets
// AGENT_HOST=0.0.0.0 so the published container port is reachable.
const HOST = process.env.AGENT_HOST ?? "127.0.0.1";
if (!["127.0.0.1", "::1", "localhost"].includes(HOST)) {
  console.warn(`[sandbox-web-search] AGENT_HOST=${HOST} — listener is reachable from other machines`);
}

const MOCK_RESULTS = [
  { title: "Aroha Protocol — Open Agent Standard", url: "https://aroha-labs.com", snippet: "An open protocol for autonomous AI agents to discover each other, communicate securely, and transact." },
  { title: "MCP vs Aroha: When to Use Each", url: "https://aroha-labs.com/blog/mcp-vs-aroha", snippet: "MCP carries the call. Aroha carries what the caller is allowed to do, and a receipt of what it did. They're complementary, not competing." },
  { title: "Getting Started with Multi-Agent Systems", url: "https://aroha-labs.com/docs/quickstart", snippet: "npx create-aroha-agent my-agent — scaffold your first Aroha agent in 60 seconds." },
];

const handlers: Record<string, (params: Record<string, unknown>) => unknown> = {
  "search-web": ({ query, limit = 5 }) => ({
    query,
    results: MOCK_RESULTS.slice(0, Number(limit)).map((r, i) => ({
      rank: i + 1,
      ...r,
      relevanceScore: 0.95 - i * 0.1,
    })),
    totalResults: MOCK_RESULTS.length,
    searchedAt: new Date().toISOString(),
    _sandbox: true,
    _note: `Sandbox mode: results are mock data for query "${query}"`,
  }),

  "fetch-url": ({ url }) => ({
    url,
    content: `[Sandbox] Mock content from ${url}. In production this would be the actual page text.`,
    title: `Mock page: ${url}`,
    fetchedAt: new Date().toISOString(),
    statusCode: 200,
    _sandbox: true,
  }),
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
      const result = handler ? handler(body.params as Record<string, unknown>) : { error: `Unknown capability: ${body.capability}` };
      const responseBody: ArohaResponseBody = { capability: body.capability, result: result as Record<string, unknown> };
      respond({ type: "ArohaResponse", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: responseBody, signature: "sandbox-no-sig" } as never);
    },
  });

  await server.start();
  console.log(`[sandbox-web-search] ${AGENT_DID}  →  http://localhost:${PORT}`);
}

main().catch((err) => { console.error("[sandbox-web-search]", err); process.exit(1); });
