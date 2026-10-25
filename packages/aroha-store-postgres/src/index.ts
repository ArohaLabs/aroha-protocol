// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/store-postgres — durable, shared Postgres implementations of
 * the three stores @aroha-sdk/credentials needs in production:
 *
 *   PostgresNonceStore       — HttpPresentationNonceStore (replay protection)
 *   PostgresEnrollmentStore  — EnrollmentStore (challenges, account → DID)
 *   PostgresSpendingLedger   — ISpendingLedger (running totals)
 *
 * Run `migrate(pool)` once at start-up (idempotent), then pass the stores to
 * verifyHttpMandateRequest / verifyHttpSpendRequest / completeEnrollment.
 */

export { migrate, schemaSql, type PgMigratable } from "./schema.js";
export { PostgresNonceStore, type PostgresNonceStoreOptions } from "./nonce-store.js";
export { PostgresEnrollmentStore, type PostgresEnrollmentStoreOptions } from "./enrollment-store.js";
export { PostgresSpendingLedger } from "./spending-ledger.js";
export {
  DEFAULT_TABLE_PREFIX, tableNames,
  type PgQueryable, type PgQueryResult, type PostgresStoreOptions,
} from "./internal.js";
