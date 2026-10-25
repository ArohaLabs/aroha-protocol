// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * sandbox-hotel — public sandbox agent for testing hotel search/booking
 *
 * DID: did:aroha:sandbox-hotel
 * Endpoint: run locally (the hosted sandbox.aroha.dev is not currently available)
 *
 * Returns mock data — no real hotels are booked.
 */

import { ArohaServer, type ArohaRequestBody, type ArohaResponseBody, type DIDDocument } from "@aroha-sdk/core";

const AGENT_DID = process.env.AROHA_AGENT_DID ?? "did:aroha:sandbox-hotel";
const PORT = Number(process.env.PORT ?? 3011);
// Loopback unless AGENT_HOST says otherwise. docker-compose.yml sets
// AGENT_HOST=0.0.0.0 so the published container port is reachable.
const HOST = process.env.AGENT_HOST ?? "127.0.0.1";
if (!["127.0.0.1", "::1", "localhost"].includes(HOST)) {
  console.warn(`[sandbox-hotel] AGENT_HOST=${HOST} — listener is reachable from other machines`);
}

const MOCK_HOTELS = [
  { id: "H001", name: "Aroha Grand Shinjuku",     city: "Tokyo", area: "Shinjuku",    stars: 4, pricePerNight: 189, currency: "USD", rooms: 12 },
  { id: "H002", name: "Park Hyatt Tokyo",          city: "Tokyo", area: "Shinjuku",    stars: 5, pricePerNight: 450, currency: "USD", rooms: 3 },
  { id: "H003", name: "Capsule Inn Akihabara",     city: "Tokyo", area: "Akihabara",   stars: 2, pricePerNight: 49,  currency: "USD", rooms: 30 },
  { id: "H004", name: "Shibuya Stream Excel Hotel",city: "Tokyo", area: "Shibuya",     stars: 4, pricePerNight: 220, currency: "USD", rooms: 7 },
];

const handlers: Record<string, (params: Record<string, unknown>) => unknown> = {
  "search-hotels": ({ city, area, checkIn, checkOut, maxPricePerNight, limit = 10 }) => {
    let results = MOCK_HOTELS.filter((h) =>
      (!city || h.city.toLowerCase() === String(city).toLowerCase()) &&
      (!area || h.area.toLowerCase().includes(String(area).toLowerCase())) &&
      (!maxPricePerNight || h.pricePerNight <= Number(maxPricePerNight))
    ).slice(0, Number(limit));

    const nights = checkIn && checkOut
      ? Math.max(1, Math.round((new Date(String(checkOut)).getTime() - new Date(String(checkIn)).getTime()) / 86400000))
      : 1;

    return {
      hotels: results.map((h) => ({ ...h, totalPrice: h.pricePerNight * nights, nights })),
      count: results.length,
      checkIn, checkOut,
      searchedAt: new Date().toISOString(),
    };
  },

  "book-hotel": ({ hotelId, guestId, checkIn, checkOut }) => {
    const hotel = MOCK_HOTELS.find((h) => h.id === hotelId);
    if (!hotel) return { error: `Hotel ${String(hotelId)} not found` };
    const nights = checkIn && checkOut
      ? Math.max(1, Math.round((new Date(String(checkOut)).getTime() - new Date(String(checkIn)).getTime()) / 86400000))
      : 1;
    return {
      bookingId: `HB-${Date.now().toString(36).toUpperCase()}`,
      hotelId, guestId, checkIn, checkOut,
      hotelName: hotel.name,
      nights,
      totalPrice: hotel.pricePerNight * nights,
      currency: hotel.currency,
      status: "confirmed",
      bookedAt: new Date().toISOString(),
      _sandbox: true,
    };
  },

  "cancel-hotel": ({ bookingId }) => ({
    bookingId,
    status: "cancelled",
    refundAmount: 170,
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
        respond({ type: "ArohaError", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: { code: "UNKNOWN_CAPABILITY", message: `Unknown capability: ${body.capability}`, retryable: false }, signature: "sandbox-no-sig" } as never);
        return;
      }
      const result = handler(body.params as Record<string, unknown>);
      const responseBody: ArohaResponseBody = { capability: body.capability, result: result as Record<string, unknown> };
      respond({ type: "ArohaResponse", from: AGENT_DID, to: envelope.from, correlationId: envelope.correlationId, issuedAt: new Date().toISOString(), nonce: crypto.randomUUID(), body: responseBody, signature: "sandbox-no-sig" } as never);
    },
  });

  await server.start();
  console.log(`[sandbox-hotel] ${AGENT_DID}  →  http://localhost:${PORT}`);
  console.log(`[sandbox-hotel] Capabilities: ${Object.keys(handlers).join(", ")}`);
}

main().catch((err) => { console.error("[sandbox-hotel]", err); process.exit(1); });
