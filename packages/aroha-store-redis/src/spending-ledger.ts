// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import {
  BudgetExhaustedError,
  type AllocationResult, type BudgetStatus, type ISpendingLedger,
} from "@aroha-sdk/credentials/mandates";
import {
  type RedisClient, type RedisStoreOptions,
  LuaScript, assertAmount, assertKey, keyPrefix, requireClient, toMicros, toUsd, DEFAULT_KEY_PREFIX,
} from "./internal.js";

// All amounts cross the JS/Lua boundary as decimal integer strings and are
// added with HINCRBY (64-bit integers): Lua's tostring() would print a large
// micro-USD figure in exponent form. tonumber() is exact below 2^53, which
// assertAmount guarantees for every input.

// KEYS[1] budget hash; ARGV[1] limit micros, ARGV[2] expiresAt ('' = none)
const INIT = new LuaScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'limit', ARGV[1], 'allocated', '0')
if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'expires', ARGV[2]) end
return 1
`);

// KEYS[1] budget hash, KEYS[2] allocations hash; ARGV[1] amount micros, ARGV[2] allocationId, ARGV[3] now
// -> {1, remaining} ok | {2, 0} no budget | {3, 0} expired | {4, remaining} exhausted
const ALLOCATE = new LuaScript(`
local h = redis.call('HMGET', KEYS[1], 'limit', 'allocated', 'expires')
if not h[1] then return {2, 0} end
local limit = tonumber(h[1])
local allocated = tonumber(h[2])
if h[3] and tonumber(ARGV[3]) > tonumber(h[3]) then return {3, 0} end
if allocated + tonumber(ARGV[1]) > limit then return {4, limit - allocated} end
local now_allocated = redis.call('HINCRBY', KEYS[1], 'allocated', ARGV[1])
redis.call('HSET', KEYS[2], ARGV[2], ARGV[1])
return {1, limit - now_allocated}
`);

// KEYS[1] budget hash, KEYS[2] allocations hash; ARGV[1] allocationId -> {1, remaining} | {2, 0} no budget
const RELEASE = new LuaScript(`
local limit = redis.call('HGET', KEYS[1], 'limit')
if not limit then return {2, 0} end
local amount = redis.call('HGET', KEYS[2], ARGV[1])
if amount then
  redis.call('HDEL', KEYS[2], ARGV[1])
  if amount ~= '0' then
    local n = redis.call('HINCRBY', KEYS[1], 'allocated', '-' .. amount)
    if n < 0 then redis.call('HSET', KEYS[1], 'allocated', '0') end
  end
end
return {1, tonumber(limit) - tonumber(redis.call('HGET', KEYS[1], 'allocated'))}
`);

/**
 * ISpendingLedger backed by Redis — running totals shared by every process
 * using the server. Same semantics as MapSpendingLedger: integer micro-USD,
 * idempotent `init`, `allocate` throws BudgetExhaustedError past the limit
 * (or after `expiresAt`), `release` safe to repeat.
 *
 * Key layout (shared with the Python stores; the ledger key is
 * `grantor#mandateId`, mandateRedemptionKey):
 *   <prefix>ledger:budget:<key>  hash {limit, allocated} in integer micro-USD
 *                                (plus `expires`, Unix ms, when init was given expiresAt)
 *   <prefix>ledger:alloc:<key>   hash allocationId -> micro-USD, one field per live allocation
 * Budgets never expire in Redis.
 *
 * Atomicity: `allocate` is a Lua script that reads the total, checks
 * `allocated + amount <= limit`, adds, and records the allocation in one
 * step; Redis runs scripts without interleaving, so concurrent allocations
 * can never cross the limit. `release` removes the allocation field and
 * subtracts its amount (floored at 0) in one script, so a repeated or
 * concurrent release returns the money once.
 *
 * Durability is Redis's: run it with AOF persistence (`appendonly yes`,
 * ideally `appendfsync always` for money) or a Redis restart can lose the
 * most recent allocations. Any Redis error rejects; verifyHttpSpendRequest
 * maps that to LEDGER_UNAVAILABLE.
 */
export class RedisSpendingLedger implements ISpendingLedger {
  private readonly budgetPrefix: string;
  private readonly allocPrefix: string;

  constructor(private readonly redis: RedisClient, options: RedisStoreOptions = {}) {
    requireClient("RedisSpendingLedger", redis);
    const p = keyPrefix(options.keyPrefix ?? DEFAULT_KEY_PREFIX);
    this.budgetPrefix = `${p}ledger:budget:`;
    this.allocPrefix = `${p}ledger:alloc:`;
  }

  private keys(key: string): string[] {
    return [this.budgetPrefix + key, this.allocPrefix + key];
  }

  async init(mandateId: string, limitUsd: number, expiresAt?: number): Promise<void> {
    assertKey("mandateId", mandateId);
    assertAmount("limitUsd", limitUsd);
    if (expiresAt !== undefined && (typeof expiresAt !== "number" || !Number.isFinite(expiresAt))) {
      throw new TypeError(`expiresAt must be Unix milliseconds or undefined (got ${String(expiresAt)})`);
    }
    const exp = expiresAt === undefined ? "" : String(Math.floor(expiresAt));
    await INIT.run(this.redis, [this.budgetPrefix + mandateId], [String(toMicros(limitUsd)), exp]);
  }

  async allocate(parentMandateId: string, amountUsd: number): Promise<AllocationResult> {
    assertKey("parentMandateId", parentMandateId);
    // A negative allocation would ADD budget back; NaN would slip past a comparison.
    assertAmount("amountUsd", amountUsd);
    const allocationId = crypto.randomUUID();
    const [code, remaining] = reply(await ALLOCATE.run(
      this.redis, this.keys(parentMandateId), [String(toMicros(amountUsd)), allocationId, String(Date.now())],
    ));
    switch (code) {
      case 1: return { allocationId, remainingUsd: toUsd(remaining) };
      case 2:
        throw new Error(
          `No budget registered for mandate ${parentMandateId}. ` +
          `Pass { ledger } to issueIntentMandate() so the root budget is initialised before any children are issued.`,
        );
      case 3: throw new BudgetExhaustedError(parentMandateId, amountUsd, 0);
      case 4: throw new BudgetExhaustedError(parentMandateId, amountUsd, toUsd(remaining));
      default: throw new Error(`RedisSpendingLedger: unexpected reply ${String(code)}`);
    }
  }

  async release(parentMandateId: string, allocationId: string): Promise<{ remainingUsd: number }> {
    assertKey("parentMandateId", parentMandateId);
    if (typeof allocationId !== "string") throw new TypeError("allocationId must be a string");
    const [code, remaining] = reply(await RELEASE.run(this.redis, this.keys(parentMandateId), [allocationId]));
    if (code === 2) return { remainingUsd: 0 };
    if (code !== 1) throw new Error(`RedisSpendingLedger: unexpected reply ${String(code)}`);
    return { remainingUsd: toUsd(remaining) };
  }

  async status(mandateId: string): Promise<BudgetStatus | null> {
    assertKey("mandateId", mandateId);
    const [budget, count] = await Promise.all([
      this.redis.hmget(this.budgetPrefix + mandateId, "limit", "allocated"),
      this.redis.hlen(this.allocPrefix + mandateId),
    ]);
    const [limitS, allocatedS] = budget;
    if (limitS === null) return null;
    const limit = Number(limitS);
    const allocated = Number(allocatedS);
    if (![limit, allocated, count].every(Number.isSafeInteger)) throw new Error("RedisSpendingLedger: malformed budget record");
    return {
      mandateId,
      limitUsd: toUsd(limit),
      allocatedUsd: toUsd(allocated),
      remainingUsd: toUsd(limit - allocated),
      allocationCount: count,
    };
  }
}

function reply(v: unknown): [number, number] {
  if (!Array.isArray(v) || v.length !== 2 || !v.every((x) => typeof x === "number" && Number.isSafeInteger(x))) {
    throw new Error("RedisSpendingLedger: malformed script reply");
  }
  return [v[0], v[1]];
}
