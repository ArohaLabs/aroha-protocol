// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Reservation store — shared saga bookkeeping for the bridge agents (each
 * agent carries an identical copy; see errors.ts for why).
 *
 * What it fixes, relative to the per-agent Maps it replaces:
 *
 *   - Tokens were `prefix-${Date.now()}-${Math.random()…}` or an 8-hex-char
 *     slice of a UUID: guessable or small enough to enumerate. They are now
 *     128 bits from the OS CSPRNG, so a token is an unforgeable capability.
 *   - Any verified peer could commit or cancel any reservation it learned the
 *     token of. A reservation is now bound to the DID that reserved it, and
 *     Commit/Cancel must arrive from that same DID (`envelope.from`, which
 *     the transport has already signature-checked).
 *   - Some agents never checked `expiresAt` on commit. All do now.
 *   - The Maps grew without bound. Expired entries are swept on every access
 *     and the store refuses new holds past `maxEntries` instead of evicting
 *     live ones.
 *   - holdDurationMs was taken from the peer as-is. It is now clamped to
 *     `maxHoldMs`, so a peer cannot pin upstream resources for days.
 *
 * Commit is idempotent (a retried commit returns the stored result) and
 * at-most-once-in-flight (a concurrent retry gets a retryable refusal instead
 * of running the upstream write twice). A failed commit returns the
 * reservation to "reserved" so the orchestrator can retry or cancel it.
 */

import { randomBytes } from "node:crypto";
import { ArohaErrorCode } from "@aroha-sdk/core";
import { AgentError } from "./errors.js";

export type ReservationState = "reserved" | "committing" | "committed";

export interface StoredReservation<T> {
  readonly token: string;
  readonly capability: string;
  /** DID that created the hold; the only DID allowed to commit or cancel it. */
  readonly ownerDID: string;
  readonly expiresAt: Date;
  state: ReservationState;
  data: T;
  commitResult?: Record<string, unknown>;
}

export interface ReservationStoreOptions<T> {
  /** Human-readable token prefix, e.g. "stripe-res". */
  prefix: string;
  /** Cap on concurrently held reservations (default 10 000). */
  maxEntries?: number;
  /** Hold applied when the peer sends none (default 5 min). */
  defaultHoldMs?: number;
  /** Upper bound on any hold (default 15 min). */
  maxHoldMs?: number;
  /**
   * Called (fire-and-forget) for an expired, never-committed reservation as
   * it is swept, so an agent that created an upstream object at reserve time
   * can release it. Failures must be handled inside the callback.
   */
  onExpire?: (reservation: StoredReservation<T>) => void;
  now?: () => number;
}

const NOT_FOUND = "Unknown reservation token";

export class ReservationStore<T> {
  private readonly entries = new Map<string, StoredReservation<T>>();
  private readonly prefix: string;
  private readonly maxEntries: number;
  private readonly defaultHoldMs: number;
  private readonly maxHoldMs: number;
  private readonly onExpire?: (reservation: StoredReservation<T>) => void;
  private readonly now: () => number;

  constructor(opts: ReservationStoreOptions<T>) {
    this.prefix = opts.prefix;
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.defaultHoldMs = opts.defaultHoldMs ?? 300_000;
    this.maxHoldMs = opts.maxHoldMs ?? 900_000;
    this.onExpire = opts.onExpire;
    this.now = opts.now ?? (() => Date.now()); // late-bound so test clocks apply
  }

  get size(): number {
    return this.entries.size;
  }

  /** Clamp a peer-supplied hold to [1 s, maxHoldMs]; default when absent or not a finite number. */
  clampHold(holdDurationMs: unknown): number {
    const n = typeof holdDurationMs === "number" && Number.isFinite(holdDurationMs) ? holdDurationMs : this.defaultHoldMs;
    return Math.min(Math.max(Math.floor(n), 1_000), this.maxHoldMs);
  }

  /** Mint a new token and hold `data` for `ownerDID`. */
  create(capability: string, ownerDID: string, holdDurationMs: unknown, data: T): StoredReservation<T> {
    this.sweep();
    if (this.entries.size >= this.maxEntries) {
      throw new AgentError(ArohaErrorCode.CapacityExceeded, "Too many open reservations; retry later", true);
    }
    const reservation: StoredReservation<T> = {
      token: `${this.prefix}-${randomBytes(16).toString("hex")}`,
      capability,
      ownerDID,
      expiresAt: new Date(this.now() + this.clampHold(holdDurationMs)),
      state: "reserved",
      data,
    };
    this.entries.set(reservation.token, reservation);
    return reservation;
  }

  /**
   * Run `exec` exactly once for this reservation and cache its result.
   * Refuses unknown/foreign tokens, expired holds, and concurrent commits.
   */
  async commit(
    token: string,
    requesterDID: string,
    exec: (reservation: StoredReservation<T>) => Promise<Record<string, unknown>>,
  ): Promise<Record<string, unknown>> {
    const reservation = this.owned(token, requesterDID);
    if (reservation.state === "committed") return reservation.commitResult ?? {};
    if (reservation.state === "committing") {
      throw new AgentError(ArohaErrorCode.CommitFailed, "Commit already in progress for this reservation", true);
    }
    if (reservation.expiresAt.getTime() <= this.now()) {
      throw new AgentError(ArohaErrorCode.ReservationExpired, "Reservation has expired");
    }

    reservation.state = "committing";
    try {
      const result = await exec(reservation);
      reservation.state = "committed";
      reservation.commitResult = result;
      return result;
    } catch (e) {
      reservation.state = "reserved"; // leave it retryable / cancellable
      throw e;
    }
  }

  /**
   * Release a reservation. An unknown token is treated as already released
   * (Cancel must be idempotent for saga compensation). If `release` throws,
   * the reservation is KEPT so the orchestrator can retry the compensation —
   * dropping it would silently orphan the upstream object.
   */
  async cancel(
    token: string,
    requesterDID: string,
    release: (reservation: StoredReservation<T>) => Promise<void>,
  ): Promise<void> {
    this.sweep(token);
    const reservation = this.entries.get(token);
    if (!reservation) return;
    if (reservation.ownerDID !== requesterDID) throw new AgentError(ArohaErrorCode.InvalidToken, NOT_FOUND);
    if (reservation.state === "committing") {
      throw new AgentError(ArohaErrorCode.CancelFailed, "Commit in progress; retry cancel later", true);
    }
    await release(reservation);
    this.entries.delete(token);
  }

  /** Look up a reservation the requester owns (no state/expiry checks). */
  owned(token: string, requesterDID: string): StoredReservation<T> {
    this.sweep(token);
    const reservation = typeof token === "string" ? this.entries.get(token) : undefined;
    // Same answer for "no such token" and "someone else's token", so the
    // reply cannot be used to probe which tokens exist.
    if (!reservation || reservation.ownerDID !== requesterDID) {
      throw new AgentError(ArohaErrorCode.InvalidToken, NOT_FOUND);
    }
    return reservation;
  }

  /**
   * Drop reservations whose hold has lapsed. Committed entries are kept
   * until expiry so retried commits stay idempotent, then dropped too.
   * `keep` exempts one token so a lookup sees its own entry's real state
   * (an expired-but-present reservation reports "expired", not "unknown").
   */
  sweep(keep?: string): void {
    const now = this.now();
    for (const [token, reservation] of this.entries) {
      if (token === keep || reservation.state === "committing") continue;
      if (reservation.expiresAt.getTime() > now) continue;
      this.entries.delete(token);
      if (reservation.state === "reserved" && this.onExpire) this.onExpire(reservation);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}
