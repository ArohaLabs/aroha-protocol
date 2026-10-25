// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `@aroha-sdk/credentials/mandates` — the mandate surface WITHOUT the
 * Node-only parts of the package (HTTP middleware, credential registry).
 *
 * WHY A SEPARATE ENTRY POINT. The package root re-exports middleware.ts,
 * which imports the @aroha-sdk/core barrel, which pulls in the Node
 * transport (ws, undici → fs, http). A Cloudflare Worker cannot bundle that.
 * The registry's /v1/mandates endpoints need to verify mandate chains with
 * the exact code payees run — not a server-side copy that could drift — so
 * this entry point exposes only modules whose runtime imports are
 * @noble/* and core's ./identity and ./crypto subpaths.
 */

export * from "./mandate.js";
export * from "./governed.js";
export * from "./redemption.js";
export * from "./redemption-d1.js";
export * from "./mandate-registry-client.js";
export * from "./spending-ledger.js";
export * from "./spending-ledger-d1.js";
export * from "./jcs.js";
export * from "./http-mandate.js";
export * from "./http-spend.js";
export * from "./enrollment.js";
