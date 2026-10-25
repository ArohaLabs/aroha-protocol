// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { EnrollmentChallengeRecord, EnrollmentStore } from "@aroha-sdk/credentials/mandates";
import {
  type RedisClient, type RedisStoreOptions,
  LuaScript, assertKey, assertMs, keyPrefix, requireClient, ttlMs, DEFAULT_KEY_PREFIX,
} from "./internal.js";

export interface RedisEnrollmentStoreOptions extends RedisStoreOptions {
  /** Refuse to issue a challenge while this many unexpired challenges are outstanding (default 100 000). Exact: checked inside the issuing script. */
  maxChallenges?: number;
}

// KEYS[1] challenge key, KEYS[2] index (sorted set, score = expiresAtMs)
// ARGV[1] record JSON, ARGV[2] expiresAtMs, ARGV[3] PX ttl, ARGV[4] nowMs, ARGV[5] max, ARGV[6] challenge
const PUT = new LuaScript(`
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[4])
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return -2 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[6])
return 1
`);

// KEYS[1] challenge key, KEYS[2] index; ARGV[1] challenge
const CONSUME = new LuaScript(`
local v = redis.call('GET', KEYS[1])
if not v then return false end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return v
`);

/**
 * EnrollmentStore backed by Redis.
 *
 * Key layout (prefix `aroha:` by default; shared with the Python stores):
 *   <prefix>enroll:challenge:<challenge>  string, `{"accountId":…,"expiresAtMs":…}`, PX until expiry
 *   <prefix>enroll:challenges             sorted set of outstanding challenges, score = expiresAtMs
 *   <prefix>enroll:binding:<accountId>    string, the enrolled DID
 *
 * Atomicity: `consumeChallenge` is a Lua script (GET, DEL, ZREM) — Redis runs
 * it without interleaving, so of any number of concurrent consumers exactly
 * one gets the record. `putChallenge` prunes expired index entries, checks
 * the bound and inserts in one script too. Any Redis error rejects
 * (STORE_UNAVAILABLE).
 *
 * A challenge is deleted by Redis when it expires, so completing it later
 * reports CHALLENGE_UNKNOWN rather than CHALLENGE_EXPIRED.
 */
export class RedisEnrollmentStore implements EnrollmentStore {
  private readonly chPrefix: string;
  private readonly indexKey: string;
  private readonly bindingPrefix: string;
  private readonly maxChallenges: number;

  constructor(private readonly redis: RedisClient, options: RedisEnrollmentStoreOptions = {}) {
    requireClient("RedisEnrollmentStore", redis);
    const p = keyPrefix(options.keyPrefix ?? DEFAULT_KEY_PREFIX);
    this.chPrefix = `${p}enroll:challenge:`;
    this.indexKey = `${p}enroll:challenges`;
    this.bindingPrefix = `${p}enroll:binding:`;
    this.maxChallenges = options.maxChallenges ?? 100_000;
    if (!Number.isSafeInteger(this.maxChallenges) || this.maxChallenges < 1) {
      throw new TypeError("RedisEnrollmentStore: maxChallenges must be a positive integer");
    }
  }

  async putChallenge(challenge: string, record: EnrollmentChallengeRecord, nowMs: number): Promise<void> {
    assertKey("challenge", challenge);
    assertKey("record.accountId", record?.accountId);
    assertMs("record.expiresAtMs", record.expiresAtMs);
    assertMs("nowMs", nowMs);
    const expiresAtMs = Math.floor(record.expiresAtMs);
    // Compact JSON, accountId then expiresAtMs — the shared layout.
    const value = JSON.stringify({ accountId: record.accountId, expiresAtMs });
    const r = await PUT.run(
      this.redis,
      [this.chPrefix + challenge, this.indexKey],
      [value, expiresAtMs, ttlMs(expiresAtMs, nowMs), Math.floor(nowMs), this.maxChallenges, challenge],
    );
    if (r === -1) throw new Error("RedisEnrollmentStore: challenge already issued");
    if (r === -2) throw new Error("RedisEnrollmentStore: too many outstanding challenges");
    if (r !== 1) throw new Error(`RedisEnrollmentStore: unexpected reply ${String(r)}`);
  }

  async consumeChallenge(challenge: string): Promise<EnrollmentChallengeRecord | null> {
    assertKey("challenge", challenge);
    const v = await CONSUME.run(this.redis, [this.chPrefix + challenge, this.indexKey], [challenge]);
    if (v === null || v === undefined) return null;
    // A value this layout does not describe is an error, not "unknown": fail closed.
    const parsed = JSON.parse(String(v)) as { accountId?: unknown; expiresAtMs?: unknown };
    if (typeof parsed?.accountId !== "string" || typeof parsed.expiresAtMs !== "number") {
      throw new Error("RedisEnrollmentStore: malformed challenge record");
    }
    return { accountId: parsed.accountId, expiresAtMs: parsed.expiresAtMs };
  }

  async getBinding(accountId: string): Promise<string | null> {
    assertKey("accountId", accountId);
    return await this.redis.get(this.bindingPrefix + accountId);
  }

  async setBinding(accountId: string, did: string): Promise<void> {
    assertKey("accountId", accountId);
    assertKey("did", did);
    await this.redis.set(this.bindingPrefix + accountId, did);
  }

  /** Number of unexpired outstanding challenges (for tests and metrics). */
  async pendingChallenges(nowMs: number = Date.now()): Promise<number> {
    return await this.redis.zcount(this.indexKey, `(${Math.floor(nowMs)}`, "+inf");
  }
}
