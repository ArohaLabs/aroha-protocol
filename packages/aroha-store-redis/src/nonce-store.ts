// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import type { HttpPresentationNonceStore } from "@aroha-sdk/credentials/mandates";
import {
  type RedisClient, type RedisStoreOptions,
  assertKey, assertMs, keyPrefix, requireClient, ttlMs, DEFAULT_KEY_PREFIX,
} from "./internal.js";

/**
 * HttpPresentationNonceStore backed by Redis — replay protection shared by
 * every process using the server, and kept across application restarts
 * (and across Redis restarts when Redis persistence — AOF or RDB — is on).
 *
 * Key: `<prefix>nonce:<key>` → "1".
 *
 * Atomicity: `claim` is ONE command, `SET <prefix>nonce:<key> 1 NX PX <ttl>`
 * with ttl = expiresAtMs - nowMs + 1. NX makes the first SET win and every
 * later one return nil (→ false). The TTL is relative, so it does not depend
 * on the Redis clock agreeing with the application's; it starts when Redis
 * receives the command, after `nowMs`, so the entry outlives the
 * presentation. Any Redis error rejects, which verifyHttpPresentation maps to
 * NONCE_STORE_UNAVAILABLE.
 */
export class RedisNonceStore implements HttpPresentationNonceStore {
  private readonly prefix: string;

  constructor(private readonly redis: RedisClient, options: RedisStoreOptions = {}) {
    requireClient("RedisNonceStore", redis);
    this.prefix = `${keyPrefix(options.keyPrefix ?? DEFAULT_KEY_PREFIX)}nonce:`;
  }

  async claim(key: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    assertKey("key", key);
    assertMs("expiresAtMs", expiresAtMs);
    assertMs("nowMs", nowMs);
    const r = await this.redis.set(this.prefix + key, "1", "PX", ttlMs(expiresAtMs, nowMs), "NX");
    return r === "OK";
  }
}
