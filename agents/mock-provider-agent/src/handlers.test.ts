// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from "vitest";
import { ArohaErrorCode, buildEnvelope, generateDID, type ArohaEnvelope, type AgentKeyPair } from "@aroha-sdk/core";
import { handleMessage, reservations } from "./handlers.js";

let agent: AgentKeyPair;
let peer: AgentKeyPair;
let other: AgentKeyPair;

beforeAll(async () => {
  agent = await generateDID("mock", "http://localhost/aroha/v1");
  peer = await generateDID("orchestrator", "http://localhost/aroha/v1");
  other = await generateDID("other", "http://localhost/aroha/v1");
});
beforeEach(() => {
  reservations.clear();
  vi.spyOn(Math, "random").mockReturnValue(0.5); // inventory always available
});
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

const send = async (type: string, body: Record<string, unknown>, from: AgentKeyPair = peer) =>
  handleMessage(await buildEnvelope(type as "ArohaRequest", from.did, agent.did, body as never, "cid", from.privateKey), agent.did, agent.privateKey);
const code = (e: ArohaEnvelope) => (e.body as unknown as { code: string }).code;
const tokenOf = (e: ArohaEnvelope) => (e.body as { reservationToken: string }).reservationToken;

describe("mock provider reservations", () => {
  it("mints 128-bit tokens and binds them to the reserving DID", async () => {
    const ack = await send("ArohaReserve", { capability: "book-flight", params: {}, holdDurationMs: 60_000 });
    expect(tokenOf(ack)).toMatch(/^MOCK-[0-9a-f]{32}$/);
    expect(code(await send("ArohaCommit", { reservationToken: tokenOf(ack) }, other))).toBe(ArohaErrorCode.InvalidToken);
    expect(code(await send("ArohaCancel", { reservationToken: tokenOf(ack) }, other))).toBe(ArohaErrorCode.InvalidToken);
    const c1 = await send("ArohaCommit", { reservationToken: tokenOf(ack) });
    const c2 = await send("ArohaCommit", { reservationToken: tokenOf(ack) });
    expect(c1.type).toBe("ArohaCommitAck");
    expect(c2.body).toEqual(c1.body); // idempotent
  });

  it("enforces expiry on commit", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const ack = await send("ArohaReserve", { capability: "book-hotel", params: {}, holdDurationMs: 2_000 });
    vi.setSystemTime(Date.now() + 3_000);
    // Re-sign with the advanced clock so the envelope itself is fresh.
    expect(code(await send("ArohaCommit", { reservationToken: tokenOf(ack) }))).toBe(ArohaErrorCode.ReservationExpired);
  });
});
