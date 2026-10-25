// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * sandbox-weather — public sandbox weather agent
 *
 * DID: did:aroha:sandbox-weather
 * Returns deterministic mock weather — no external API calls.
 */

import { ArohaServer, type ArohaRequestBody, type ArohaResponseBody, type DIDDocument } from "@aroha-sdk/core";

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "did:aroha:sandbox-weather";
const PORT = Number(process.env.PORT ?? 3012);
// Loopback unless AGENT_HOST says otherwise. docker-compose.yml sets
// AGENT_HOST=0.0.0.0 so the published container port is reachable.
const HOST = process.env.AGENT_HOST ?? "127.0.0.1";
if (!["127.0.0.1", "::1", "localhost"].includes(HOST)) {
  console.warn(`[sandbox-weather] AGENT_HOST=${HOST} — listener is reachable from other machines`);
}

function mockWeather(city: string, date?: string) {
  const seed = city.toLowerCase().charCodeAt(0) + (date ? new Date(date).getDate() : 0);
  const conditions = ["Sunny", "Partly Cloudy", "Cloudy", "Light Rain", "Clear"];
  const condition = conditions[seed % conditions.length];
  const tempC = 10 + (seed % 25);
  return {
    city,
    date: date ?? new Date().toISOString().split("T")[0],
    condition,
    temperatureC: tempC,
    temperatureF: Math.round(tempC * 9 / 5 + 32),
    humidity: 40 + (seed % 40),
    windKph: 5 + (seed % 30),
    _sandbox: true,
  };
}

const handlers: Record<string, (params: Record<string, unknown>) => unknown> = {
  "get-weather": ({ city, date }) => mockWeather(String(city ?? "Unknown"), date as string | undefined),

  "get-forecast": ({ city, days = 5 }) => ({
    city,
    forecast: Array.from({ length: Number(days) }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() + i);
      return mockWeather(String(city ?? "Unknown"), d.toISOString().split("T")[0]);
    }),
    generatedAt: new Date().toISOString(),
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
  console.log(`[sandbox-weather] ${AGENT_DID}  →  http://localhost:${PORT}`);
}

main().catch((err) => { console.error("[sandbox-weather]", err); process.exit(1); });
