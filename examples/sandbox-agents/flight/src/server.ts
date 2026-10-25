// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * sandbox-flight — public sandbox agent for testing flight search/booking
 *
 * DID: did:aroha:sandbox-flight
 * Endpoint: run locally (the hosted sandbox.aroha.dev is not currently available)
 *
 * Returns mock data — no real flights are booked.
 */

import { ArohaServer, type ArohaRequestBody, type ArohaResponseBody, type DIDDocument } from "@aroha-sdk/core";

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "did:aroha:sandbox-flight";
const PORT = Number(process.env.PORT ?? 3010);
// Loopback unless AGENT_HOST says otherwise. docker-compose.yml sets
// AGENT_HOST=0.0.0.0 so the published container port is reachable.
const HOST = process.env.AGENT_HOST ?? "127.0.0.1";
if (!["127.0.0.1", "::1", "localhost"].includes(HOST)) {
  console.warn(`[sandbox-flight] AGENT_HOST=${HOST} — listener is reachable from other machines`);
}

const MOCK_FLIGHTS = [
  { id: "AA101", airline: "Aroha Air", origin: "JFK", destination: "NRT", date: "2026-08-01", price: 899, currency: "USD", duration: "14h 30m", seats: 42 },
  { id: "UA202", airline: "United",    origin: "JFK", destination: "NRT", date: "2026-08-01", price: 1129, currency: "USD", duration: "13h 55m", seats: 8 },
  { id: "NH303", airline: "ANA",       origin: "JFK", destination: "NRT", date: "2026-08-01", price: 987, currency: "USD", duration: "13h 40m", seats: 23 },
];

const handlers: Record<string, (params: Record<string, unknown>) => unknown> = {
  "search-flights": ({ origin, destination, date, limit = 10 }) => {
    const results = MOCK_FLIGHTS
      .filter((f) => (!origin || f.origin === origin) && (!destination || f.destination === destination) && (!date || f.date === date))
      .slice(0, Number(limit));
    return { flights: results, count: results.length, searchedAt: new Date().toISOString() };
  },

  "book-flight": ({ flightId, passengerId }) => {
    const flight = MOCK_FLIGHTS.find((f) => f.id === flightId);
    if (!flight) return { error: `Flight ${String(flightId)} not found` };
    return {
      bookingId: `BK-${Date.now().toString(36).toUpperCase()}`,
      flightId,
      passengerId,
      status: "confirmed",
      price: flight.price,
      currency: flight.currency,
      bookedAt: new Date().toISOString(),
      _sandbox: true,
    };
  },

  "cancel-flight": ({ bookingId }) => ({
    bookingId,
    status: "cancelled",
    refundAmount: 850,
    cancelledAt: new Date().toISOString(),
    _sandbox: true,
  }),
};

async function main() {
  const server = new ArohaServer({
    agentDID: AGENT_DID,
    port: PORT,
    host: HOST,
    // Sandbox agents hold no signing key: the document carries only the service entry.
    didDocument: {
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: AGENT_DID,
      service: [{ id: `${AGENT_DID}#aroha`, type: "ArohaEndpoint", serviceEndpoint: `http://localhost:${PORT}` }],
    } as DIDDocument,
    resolvePublicKey: async () => null,
    onMessage: async (envelope, respond) => {
      if (envelope.type !== "ArohaRequest") return;
      const body = envelope.body as ArohaRequestBody;
      const handler = handlers[body.capability];
      if (!handler) {
        respond(await buildError(envelope, `Unknown capability: ${body.capability}. Available: ${Object.keys(handlers).join(", ")}`));
        return;
      }
      const result = handler(body.params as Record<string, unknown>);
      const responseBody: ArohaResponseBody = { capability: body.capability, result: result as Record<string, unknown> };
      respond({ type: "ArohaResponse", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: responseBody, signature: "sandbox-no-sig" } as never);
    },
  });

  await server.start();
  console.log(`[sandbox-flight] ${AGENT_DID}  →  http://localhost:${PORT}`);
  console.log(`[sandbox-flight] Capabilities: ${Object.keys(handlers).join(", ")}`);
}

async function buildError(envelope: { from: string; correlationId: string }, message: string) {
  return { type: "ArohaError", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: { code: "UNKNOWN_CAPABILITY", message, retryable: false }, signature: "sandbox-no-sig" } as never;
}

main().catch((err) => { console.error("[sandbox-flight]", err); process.exit(1); });
