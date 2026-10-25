// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/store-redis — shared Redis implementations of the three stores
 * @aroha-sdk/credentials needs in production:
 *
 *   RedisNonceStore       — HttpPresentationNonceStore (replay protection)
 *   RedisEnrollmentStore  — EnrollmentStore (challenges, account → DID)
 *   RedisSpendingLedger   — ISpendingLedger (running totals)
 *
 * Built on ioredis (a `Redis` connection or a `Cluster`). No schema to
 * migrate; keys are namespaced by `keyPrefix` (default `aroha:`). The key
 * layout is shared with the Python stores, so servers in both languages can
 * use one Redis.
 */

export { RedisNonceStore } from "./nonce-store.js";
export { RedisEnrollmentStore, type RedisEnrollmentStoreOptions } from "./enrollment-store.js";
export { RedisSpendingLedger } from "./spending-ledger.js";
export { DEFAULT_KEY_PREFIX, type RedisClient, type RedisStoreOptions } from "./internal.js";
