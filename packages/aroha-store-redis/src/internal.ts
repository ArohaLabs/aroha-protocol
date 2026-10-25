// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import type { Cluster, Redis } from "ioredis";

/** An ioredis client: a `Redis` connection or a `Cluster`. */
export type RedisClient = Redis | Cluster;

/** Options every Redis store accepts. */
export interface RedisStoreOptions {
  /**
   * Namespace for every key this package writes (default `"aroha:"`). 1-64
   * characters from `[A-Za-z0-9:_.{}-]`. Give each environment or tenant its
   * own prefix. Applied on top of any ioredis `keyPrefix`.
   *
   * On Redis Cluster, put a hash tag in the prefix (e.g. `"{aroha}:"`): the
   * enrollment and ledger scripts touch two keys each, which Cluster only
   * allows within one slot. Without one, those calls fail (closed) with
   * CROSSSLOT.
   */
  keyPrefix?: string;
}

export const DEFAULT_KEY_PREFIX = "aroha:";
const KEY_PREFIX_RE = /^[A-Za-z0-9:_.{}-]{1,64}$/;

export function keyPrefix(prefix: unknown = DEFAULT_KEY_PREFIX): string {
  if (typeof prefix !== "string" || !KEY_PREFIX_RE.test(prefix)) {
    throw new TypeError(`keyPrefix must match ${KEY_PREFIX_RE.source} (got ${JSON.stringify(prefix)})`);
  }
  return prefix;
}

export function requireClient(name: string, redis: unknown): asserts redis is RedisClient {
  const r = redis as Partial<Redis> | null | undefined;
  if (!r || typeof r.evalsha !== "function" || typeof r.eval !== "function" || typeof r.set !== "function") {
    throw new TypeError(`${name}: an ioredis client is required`);
  }
}

/**
 * A Lua script run with EVALSHA, falling back to EVAL once when the server
 * does not have it cached (after a restart or SCRIPT FLUSH). Redis runs a
 * script atomically: no other command interleaves with it.
 */
export class LuaScript {
  readonly sha: string;
  constructor(readonly source: string) {
    this.sha = createHash("sha1").update(source).digest("hex");
  }

  async run(redis: RedisClient, keys: string[], args: (string | number)[]): Promise<unknown> {
    try {
      return await redis.evalsha(this.sha, keys.length, ...keys, ...args);
    } catch (e) {
      if (!String((e as Error)?.message ?? "").startsWith("NOSCRIPT")) throw e;
      return await redis.eval(this.source, keys.length, ...keys, ...args);
    }
  }
}

// ─── Money ───────────────────────────────────────────────────────────────────

// Integer micro-USD, exactly as MapSpendingLedger keeps it.
const MICROS_PER_USD = 1_000_000;
export const toMicros = (usd: number): number => Math.round(usd * MICROS_PER_USD);
export const toUsd = (micros: number): number => micros / MICROS_PER_USD;

export function assertAmount(name: string, usd: number): void {
  if (typeof usd !== "number" || !Number.isFinite(usd) || usd < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number of USD (got ${String(usd)})`);
  }
  if (!Number.isSafeInteger(toMicros(usd))) {
    throw new RangeError(`${name} is too large to account for exactly (got ${String(usd)})`);
  }
}

export function assertKey(name: string, v: unknown): asserts v is string {
  if (typeof v !== "string" || v.length === 0) throw new TypeError(`${name} must be a non-empty string`);
}

/** Relative expiry for SET … PX: the time left until `expiresAtMs`, plus 1 ms, at least 1. */
export function ttlMs(expiresAtMs: number, nowMs: number): number {
  return Math.max(1, Math.floor(expiresAtMs) - Math.floor(nowMs) + 1);
}

export function assertMs(name: string, v: unknown): asserts v is number {
  if (typeof v !== "number" || !Number.isSafeInteger(Math.floor(v))) {
    throw new TypeError(`${name} must be a finite number of Unix milliseconds (got ${String(v)})`);
  }
}
