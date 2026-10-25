// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Semantic Cache
 *
 * Content-addressed caching of ArohaRequest → ArohaResponse pairs.
 * Cache key = SHA-256(capability + canonical JSON of params), making responses
 * reusable across agents and sessions for identical requests.
 *
 * Backends:
 *   - InMemorySemanticCache   — in-process, zero dependencies (default)
 *   - RedisSemanticCache      — shared across processes (requires ioredis)
 */

import { createHash } from "crypto";
import { type ArohaResponseBody } from "@aroha-sdk/core";

// ─── Cache key ────────────────────────────────────────────────────────────────

/**
 * Deterministic cache key for a capability + params pair.
 * Keys are order-independent — { a: 1, b: 2 } and { b: 2, a: 1 } hash identically.
 */
export function cacheKey(capability: string, params: Record<string, unknown>): string {
  const canonical = JSON.stringify(sortDeep(params));
  return createHash("sha256")
    .update(`${capability}::${canonical}`)
    .digest("hex");
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      sorted[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

// ─── Interface ────────────────────────────────────────────────────────────────

export interface CacheEntry {
  capability: string;
  params: Record<string, unknown>;
  result: ArohaResponseBody["result"];
  cachedAt: string;   // ISO8601
  expiresAt: string;  // ISO8601
  hitCount: number;
}

export interface ISemanticCache {
  get(key: string): Promise<CacheEntry | null>;
  set(key: string, entry: CacheEntry): Promise<void>;
  invalidate(capabilityPrefix: string): Promise<number>;
  stats(): Promise<{ size: number; hitRate: number; totalHits: number; totalMisses: number }>;
}

// ─── In-memory backend ────────────────────────────────────────────────────────

export class InMemorySemanticCache implements ISemanticCache {
  private readonly store = new Map<string, CacheEntry>();
  private hits = 0;
  private misses = 0;
  private capabilityIndex = new Map<string, Set<string>>(); // capability → keys

  async get(key: string): Promise<CacheEntry | null> {
    const entry = this.store.get(key);
    if (!entry) { this.misses++; return null; }
    if (new Date(entry.expiresAt) < new Date()) {
      this.store.delete(key);
      this.misses++;
      return null;
    }
    entry.hitCount++;
    this.hits++;
    return entry;
  }

  async set(key: string, entry: CacheEntry): Promise<void> {
    this.store.set(key, entry);
    const cap = entry.capability;
    if (!this.capabilityIndex.has(cap)) this.capabilityIndex.set(cap, new Set());
    this.capabilityIndex.get(cap)!.add(key);
  }

  async invalidate(capabilityPrefix: string): Promise<number> {
    let count = 0;
    for (const [cap, keys] of this.capabilityIndex) {
      if (cap.startsWith(capabilityPrefix)) {
        for (const key of keys) { this.store.delete(key); count++; }
        this.capabilityIndex.delete(cap);
      }
    }
    return count;
  }

  async stats() {
    const total = this.hits + this.misses;
    return {
      size: this.store.size,
      hitRate: total === 0 ? 0 : this.hits / total,
      totalHits: this.hits,
      totalMisses: this.misses,
    };
  }
}

// ─── Redis backend ────────────────────────────────────────────────────────────

export interface RedisSemanticCacheOptions {
  /** ioredis connection URL: redis://localhost:6379 */
  url?: string;
  /** Key namespace prefix — default "aroha:cache:" */
  keyPrefix?: string;
}

interface IRedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, expiryMode: string, time: number): Promise<unknown>;
  keys(pattern: string): Promise<string[]>;
  del(...keys: string[]): Promise<number>;
  dbsize(): Promise<number>;
}

export class RedisSemanticCache implements ISemanticCache {
  private redis: IRedisClient | null = null;
  private readonly keyPrefix: string;
  private hits = 0;
  private misses = 0;

  constructor(private readonly opts: RedisSemanticCacheOptions = {}) {
    this.keyPrefix = opts.keyPrefix ?? "aroha:cache:";
  }

  private async getRedis(): Promise<IRedisClient> {
    if (!this.redis) {
      const pkg = "ioredis";
      const ioredis = await import(pkg).catch(() => {
        throw new Error("RedisSemanticCache requires ioredis. Run: npm install ioredis");
      }) as { default: new (url?: string) => IRedisClient };
      this.redis = new ioredis.default(this.opts.url);
    }
    return this.redis!;
  }

  async get(key: string): Promise<CacheEntry | null> {
    const r = await this.getRedis();
    const raw = await r.get(this.keyPrefix + key);
    if (!raw) { this.misses++; return null; }
    const entry = JSON.parse(raw) as CacheEntry;
    entry.hitCount++;
    this.hits++;
    await r.set(this.keyPrefix + key, JSON.stringify(entry), "KEEPTTL", 0);
    return entry;
  }

  async set(key: string, entry: CacheEntry): Promise<void> {
    const r = await this.getRedis();
    const ttlMs = new Date(entry.expiresAt).getTime() - Date.now();
    if (ttlMs <= 0) return;
    await r.set(this.keyPrefix + key, JSON.stringify(entry), "PX", Math.ceil(ttlMs));
  }

  async invalidate(capabilityPrefix: string): Promise<number> {
    const r = await this.getRedis();
    const keys = await r.keys(`${this.keyPrefix}*`);
    if (keys.length === 0) return 0;
    const raw = await Promise.all(keys.map((k) => r.get(k)));
    const matching = keys.filter((k, i) => {
      const entry = raw[i] ? JSON.parse(raw[i]!) as CacheEntry : null;
      return entry?.capability.startsWith(capabilityPrefix);
    });
    if (matching.length === 0) return 0;
    return r.del(...matching);
  }

  async stats() {
    const r = await this.getRedis();
    const size = await r.dbsize();
    const total = this.hits + this.misses;
    return {
      size,
      hitRate: total === 0 ? 0 : this.hits / total,
      totalHits: this.hits,
      totalMisses: this.misses,
    };
  }
}
