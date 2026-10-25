// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * RFC 8785 JSON Canonicalization Scheme — re-exported from @aroha-sdk/core.
 *
 * The implementation moved to core (crypto/jcs.ts) because core's Key Event
 * Logs sign over JCS and core cannot depend on credentials. This module
 * keeps the old import path (`./jcs.js`, and the package-level export)
 * working, and guarantees mandates and KEL events canonicalise with the
 * SAME code — two copies could drift, and a drift is a signature that
 * verifies in one place and not the other.
 */
// Subpath, not the barrel — see the import note in mandate.ts.
export { canonicalizeJcs } from "@aroha-sdk/core/crypto";
