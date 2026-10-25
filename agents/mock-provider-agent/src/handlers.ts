// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Mock Provider Agent — Capability Handlers (Tier 3: Application)
 *
 * This is an EXAMPLE of what a provider agent looks like from the inside.
 * It simulates flight search + booking (like Expedia) for testing purposes.
 *
 * Key point: these handlers contain APPLICATION LOGIC.
 * The Aroha protocol has zero knowledge of what happens in here.
 * A real Expedia agent would call their actual booking APIs instead.
 *
 * Handlers receive a validated ArohaEnvelope (already verified by the
 * ArohaServer transport layer) and return a reply envelope.
 */

import { buildEnvelope, type ArohaEnvelope } from "@aroha-sdk/core";
import {
  type ArohaRequestBody,
  type ArohaReserveBody,
  type ArohaCommitBody,
  type ArohaCancelBody,
  ArohaErrorCode,
} from "@aroha-sdk/core";
import { AgentError, toErrorBody } from "./errors.js";
import { ReservationStore } from "./reservations.js";

// In-memory reservation store (a real agent uses a database). Tokens are
// 128-bit random and bound to the reserving DID; Commit/Cancel from any
// other DID is refused, expiry is enforced on commit, and lapsed holds are
// swept so the map stays bounded (see reservations.ts).
export const reservations = new ReservationStore<{ params: Record<string, unknown> }>({ prefix: "MOCK" });

export async function handleMessage(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  switch (envelope.type) {
    case "ArohaRequest":
      return handleRequest(envelope, agentDID, privateKey);
    case "ArohaReserve":
      return handleReserve(envelope, agentDID, privateKey);
    case "ArohaCommit":
      return handleCommit(envelope, agentDID, privateKey);
    case "ArohaCancel":
      return handleCancel(envelope, agentDID, privateKey);
    default:
      return buildErrorEnvelope(envelope, agentDID, privateKey, ArohaErrorCode.UnknownCapability, `Unsupported message type: ${envelope.type}`);
  }
}

// ─── ArohaRequest — search / query ────────────────────────────────────────────

async function handleRequest(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const body = envelope.body as ArohaRequestBody;

  if (body.capability === "search-flights") {
    const result = simulateFlightSearch(body.params);
    return buildEnvelope("ArohaResponse", agentDID, envelope.from,
      { capability: "search-flights", result }, envelope.correlationId, privateKey);
  }

  if (body.capability === "search-hotels") {
    const result = simulateHotelSearch(body.params);
    return buildEnvelope("ArohaResponse", agentDID, envelope.from,
      { capability: "search-hotels", result }, envelope.correlationId, privateKey);
  }

  return buildErrorEnvelope(envelope, agentDID, privateKey, ArohaErrorCode.UnknownCapability, `Unknown capability: ${body.capability}`);
}

// ─── ArohaReserve — hold inventory ────────────────────────────────────────────

async function handleReserve(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const body = envelope.body as ArohaReserveBody;

  const bookableCapabilities = ["book-flight", "book-hotel", "book-restaurant"];
  if (!bookableCapabilities.includes(body.capability)) {
    return buildErrorEnvelope(envelope, agentDID, privateKey, ArohaErrorCode.UnknownCapability, `Cannot reserve: ${body.capability}`);
  }

  // Simulate inventory availability check
  const available = Math.random() > 0.1; // 90% availability
  if (!available) {
    return buildErrorEnvelope(envelope, agentDID, privateKey, ArohaErrorCode.NoInventory, "No seats available for this flight");
  }

  let r;
  try {
    r = reservations.create(body.capability, envelope.from, body.holdDurationMs, { params: body.params ?? {} });
  } catch (e) {
    return storeErrorEnvelope(envelope, agentDID, privateKey, e);
  }

  return buildEnvelope(
    "ArohaReserveAck",
    agentDID,
    envelope.from,
    { reservationToken: r.token, expiresAt: r.expiresAt.toISOString() },
    envelope.correlationId,
    privateKey
  );
}

// ─── ArohaCommit — finalize reservation ───────────────────────────────────────

async function handleCommit(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const body = envelope.body as ArohaCommitBody;

  // Idempotent: a repeated commit returns the identical stored result
  let result: Record<string, unknown>;
  try {
    result = await reservations.commit(body.reservationToken, envelope.from, async (reservation) => {
      const ref = `${reservation.capability === "book-hotel" ? "HTL" : reservation.capability === "book-restaurant" ? "RSV" : "PNR"}${Math.floor(Math.random() * 900000 + 100000)}`;
      return {
        pnr: ref,
        status: "confirmed",
        capability: reservation.capability,
        details: reservation.data.params,
        issuedAt: new Date().toISOString(),
      };
    });
  } catch (e) {
    return storeErrorEnvelope(envelope, agentDID, privateKey, e);
  }

  return buildEnvelope(
    "ArohaCommitAck",
    agentDID,
    envelope.from,
    {
      reservationToken: body.reservationToken,
      result,
    },
    envelope.correlationId,
    privateKey
  );
}

// ─── ArohaCancel — compensating transaction ───────────────────────────────────

async function handleCancel(
  envelope: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array
): Promise<ArohaEnvelope> {
  const body = envelope.body as ArohaCancelBody;

  // Per spec: ArohaCancel must be accepted even after commit (if business rules allow)
  // This mock always accepts cancellations from the reserving DID
  try {
    await reservations.cancel(body.reservationToken, envelope.from, async () => {});
  } catch (e) {
    return storeErrorEnvelope(envelope, agentDID, privateKey, e);
  }

  return buildEnvelope(
    "ArohaCancelAck",
    agentDID,
    envelope.from,
    { reservationToken: body.reservationToken },
    envelope.correlationId,
    privateKey
  );
}

// ─── Application logic: simulate flight data ─────────────────────────────────

function simulateFlightSearch(params: Record<string, unknown>) {
  return {
    flights: [
      {
        flightId: `FL${Math.floor(Math.random() * 9000 + 1000)}`,
        origin: params.origin,
        destination: params.destination,
        departDate: params.departDate,
        price: Math.floor(Math.random() * 300 + 200),
        currency: "USD",
        duration: "5h30m",
        stops: 0,
        airline: "Mock Airlines",
      },
      {
        flightId: `FL${Math.floor(Math.random() * 9000 + 1000)}`,
        origin: params.origin,
        destination: params.destination,
        departDate: params.departDate,
        price: Math.floor(Math.random() * 200 + 150),
        currency: "USD",
        duration: "7h15m",
        stops: 1,
        airline: "Budget Air",
      },
    ],
  };
}

function simulateHotelSearch(params: Record<string, unknown>) {
  return {
    hotels: [
      {
        hotelId: `HTL${Math.floor(Math.random() * 9000 + 1000)}`,
        name: "The Grand Mock Hotel",
        city: params.city,
        checkIn: params.checkIn,
        checkOut: params.checkOut,
        pricePerNight: Math.floor(Math.random() * 150 + 100),
        currency: "USD",
        stars: 4,
        available: true,
      },
      {
        hotelId: `HTL${Math.floor(Math.random() * 9000 + 1000)}`,
        name: "Budget Inn Mock",
        city: params.city,
        checkIn: params.checkIn,
        checkOut: params.checkOut,
        pricePerNight: Math.floor(Math.random() * 80 + 50),
        currency: "USD",
        stars: 3,
        available: true,
      },
    ],
  };
}

// ─── Error helpers ────────────────────────────────────────────────────────────

/** Reply for a refusal raised by the reservation store (unknown/foreign token, expiry, capacity). */
async function storeErrorEnvelope(
  inbound: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array,
  e: unknown
): Promise<ArohaEnvelope> {
  if (!(e instanceof AgentError)) throw e;
  return buildEnvelope("ArohaError", agentDID, inbound.from, toErrorBody(e, "[MockProvider]"), inbound.correlationId, privateKey);
}

async function buildErrorEnvelope(
  inbound: ArohaEnvelope,
  agentDID: string,
  privateKey: Uint8Array,
  code: ArohaErrorCode,
  message: string
): Promise<ArohaEnvelope> {
  return buildEnvelope(
    "ArohaError",
    agentDID,
    inbound.from,
    { code, message, retryable: false },
    inbound.correlationId,
    privateKey
  );
}
