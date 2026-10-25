// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

// Tests for the helper modules every bridge agent carries a copy of
// (errors.ts, reservations.ts, authz.ts, startup.ts). Identical in each agent.

import { describe, it, expect, vi } from "vitest";
import { ArohaErrorCode } from "@aroha-sdk/core";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { AgentError, UpstreamError, toErrorBody } from "./errors.js";
import { ReservationStore } from "./reservations.js";
import { isLoopbackHost, loadIdentity, publicKeyFromSeed, requireEnv, resolveEndpoint, resolveListenHost } from "./startup.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

describe("ReservationStore", () => {
  const A = "did:aroha:alice";
  const B = "did:aroha:bob";

  it("mints 128-bit random tokens", () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const a = s.create("cap", A, 60_000, null).token;
    const b = s.create("cap", A, 60_000, null).token;
    expect(a).toMatch(/^t-[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });

  it("only the reserving DID may commit or cancel", async () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const r = s.create("cap", A, 60_000, null);
    await expect(s.commit(r.token, B, async () => ({}))).rejects.toMatchObject({ code: ArohaErrorCode.InvalidToken });
    await expect(s.cancel(r.token, B, async () => {})).rejects.toMatchObject({ code: ArohaErrorCode.InvalidToken });
    expect(await s.commit(r.token, A, async () => ({ ok: 1 }))).toEqual({ ok: 1 });
  });

  it("refuses commit after expiry", async () => {
    let now = 1_000_000;
    const s = new ReservationStore<null>({ prefix: "t", now: () => now });
    const r = s.create("cap", A, 5_000, null);
    now += 6_000;
    await expect(s.commit(r.token, A, async () => ({}))).rejects.toMatchObject({ code: ArohaErrorCode.ReservationExpired });
  });

  it("clamps hold duration and defaults bad input", () => {
    const s = new ReservationStore<null>({ prefix: "t", now: () => 0, maxHoldMs: 900_000 });
    expect(s.create("c", A, 10 * 86_400_000, null).expiresAt.getTime()).toBe(900_000);
    expect(s.create("c", A, "x", null).expiresAt.getTime()).toBe(300_000);
    expect(s.create("c", A, -5, null).expiresAt.getTime()).toBe(1_000);
  });

  it("commit is idempotent and runs exec once", async () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const r = s.create("cap", A, 60_000, null);
    const exec = vi.fn(async () => ({ id: 1 }));
    await s.commit(r.token, A, exec);
    await s.commit(r.token, A, exec);
    expect(exec).toHaveBeenCalledTimes(1);
  });

  it("refuses a concurrent commit while one is in flight", async () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const r = s.create("cap", A, 60_000, null);
    let release!: () => void;
    const first = s.commit(r.token, A, () => new Promise((res) => { release = () => res({}); }));
    await expect(s.commit(r.token, A, async () => ({}))).rejects.toMatchObject({ code: ArohaErrorCode.CommitFailed, retryable: true });
    release();
    await first;
  });

  it("a failed commit leaves the reservation retryable", async () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const r = s.create("cap", A, 60_000, null);
    await expect(s.commit(r.token, A, async () => { throw new Error("x"); })).rejects.toThrow();
    expect(await s.commit(r.token, A, async () => ({ ok: true }))).toEqual({ ok: true });
  });

  it("keeps the reservation when release fails; unknown token cancel is a no-op", async () => {
    const s = new ReservationStore<null>({ prefix: "t" });
    const r = s.create("cap", A, 60_000, null);
    await expect(s.cancel(r.token, A, async () => { throw new Error("upstream"); })).rejects.toThrow();
    expect(s.size).toBe(1);
    await s.cancel(r.token, A, async () => {});
    expect(s.size).toBe(0);
    await expect(s.cancel("t-unknown", A, async () => {})).resolves.toBeUndefined();
  });

  it("sweeps expired entries, calls onExpire, and caps the map size", () => {
    let now = 0;
    const expired: string[] = [];
    const s = new ReservationStore<null>({ prefix: "t", maxEntries: 2, now: () => now, onExpire: (r) => expired.push(r.token) });
    const r1 = s.create("c", A, 1_000, null);
    s.create("c", A, 60_000, null);
    expect(() => s.create("c", A, 60_000, null)).toThrow(AgentError);
    now = 2_000;
    s.create("c", A, 60_000, null); // sweep frees r1's slot
    expect(expired).toEqual([r1.token]);
    expect(s.size).toBe(2);
  });
});

describe("toErrorBody", () => {
  it("does not forward upstream detail to the peer", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const body = toErrorBody(new UpstreamError("Svc", 400, "internal detail https://internal.example/x"), "[T]");
    expect(body.code).toBe(ArohaErrorCode.InvalidParams);
    expect(JSON.stringify(body)).not.toContain("internal");
    expect(toErrorBody(new UpstreamError("Svc", 503, ""), "[T]")).toMatchObject({ code: ArohaErrorCode.ServiceUnavailable, retryable: true });
    expect(toErrorBody(new UpstreamError("Svc", 429, ""), "[T]")).toMatchObject({ code: ArohaErrorCode.CapacityExceeded, retryable: true });
    expect(toErrorBody(new Error("secret stack detail"), "[T]")).toEqual({ code: ArohaErrorCode.InternalError, message: "Internal error", retryable: false });
    spy.mockRestore();
  });

  it("passes AgentError text through", () => {
    expect(toErrorBody(new AgentError(ArohaErrorCode.InvalidParams, "bad id"), "[T]")).toMatchObject({ message: "bad id" });
  });
});

describe("startup checks", () => {
  it("requireEnv throws outside development and warns inside", () => {
    expect(() => requireEnv(["X_KEY"], "[T]", {})).toThrow(/X_KEY/);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(() => requireEnv(["X_KEY"], "[T]", { NODE_ENV: "development" })).not.toThrow();
    warn.mockRestore();
    expect(() => requireEnv(["X_KEY"], "[T]", { X_KEY: "v" })).not.toThrow();
  });

  it("resolveEndpoint requires AGENT_ENDPOINT outside development", () => {
    expect(() => resolveEndpoint(["AGENT_ENDPOINT"], "http://localhost:1", "[T]", {})).toThrow(/AGENT_ENDPOINT/);
    expect(resolveEndpoint(["AGENT_ENDPOINT"], "http://localhost:1", "[T]", { NODE_ENV: "development" })).toBe("http://localhost:1");
    expect(resolveEndpoint(["AGENT_ENDPOINT"], "d", "[T]", { AGENT_ENDPOINT: "https://a.example/aroha/v1" })).toBe("https://a.example/aroha/v1");
    expect(() => resolveEndpoint(["AGENT_ENDPOINT"], "d", "[T]", { AGENT_ENDPOINT: "not a url" })).toThrow();
  });

  it("resolveListenHost defaults to loopback and warns when widened", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      expect(resolveListenHost("[T]", {})).toBe("127.0.0.1");
      expect(resolveListenHost("[T]", { AGENT_HOST: "  " })).toBe("127.0.0.1");
      expect(resolveListenHost("[T]", { AGENT_HOST: "::1" })).toBe("::1");
      expect(warn).not.toHaveBeenCalled();
      expect(resolveListenHost("[T]", { AGENT_HOST: "0.0.0.0" })).toBe("0.0.0.0");
      expect(warn).toHaveBeenCalledTimes(1);
      expect(isLoopbackHost("127.0.0.5")).toBe(true);
      expect(isLoopbackHost("127.0.0.1.example.com")).toBe(false);
    } finally {
      warn.mockRestore();
    }
  });

  it("derives the same public key as @noble/ed25519 and loads a persistent identity", async () => {
    const seed = new Uint8Array(32).map((_, i) => i + 1);
    expect(Buffer.from(publicKeyFromSeed(seed))).toEqual(Buffer.from(await ed.getPublicKeyAsync(seed)));
    const hex = Buffer.from(seed).toString("hex");
    const a = await loadIdentity("agent", "https://x/aroha/v1", "[T]", { AGENT_PRIVATE_KEY_HEX: hex });
    const b = await loadIdentity("agent", "https://x/aroha/v1", "[T]", { AGENT_PRIVATE_KEY_HEX: hex });
    expect(Buffer.from(a.publicKey)).toEqual(Buffer.from(b.publicKey));
    expect(a.document.verificationMethod[0].publicKeyMultibase).toBe(b.document.verificationMethod[0].publicKeyMultibase);
    await expect(loadIdentity("agent", "https://x", "[T]", { AGENT_PRIVATE_KEY_HEX: "zz" })).rejects.toThrow(/64 hex/);
  });
});
