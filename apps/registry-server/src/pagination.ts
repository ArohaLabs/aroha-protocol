// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `?limit=` / `?offset=` parsing for every list route.
 *
 * The routes used to do `Math.min(Number(limit), 100)` and `Number(offset)`
 * inline. That caps only one side: `?limit=-1` reached SQLite as LIMIT -1,
 * which means "no limit" — a full-table read from an anonymous request —
 * and `?limit=abc` became NaN, which the driver bound unpredictably. Both
 * are now clamped in one place: limit to [1, max], offset to >= 0, and
 * anything non-numeric falls back to the default.
 */

import type { Context } from "hono";

export const DEFAULT_PAGE_LIMIT = 50;
export const MAX_PAGE_LIMIT = 100;

export function clampPagination(
  rawLimit: string | undefined | null,
  rawOffset: string | undefined | null,
  opts: { defaultLimit?: number; maxLimit?: number } = {},
): { limit: number; offset: number } {
  const def = opts.defaultLimit ?? DEFAULT_PAGE_LIMIT;
  const max = opts.maxLimit ?? MAX_PAGE_LIMIT;
  const l = rawLimit == null || rawLimit === "" ? def : Number(rawLimit);
  const o = rawOffset == null || rawOffset === "" ? 0 : Number(rawOffset);
  const limit = Number.isFinite(l) ? Math.min(max, Math.max(1, Math.trunc(l))) : def;
  const offset = Number.isFinite(o) ? Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, Math.trunc(o))) : 0;
  return { limit, offset };
}

/** Read and clamp `limit` / `offset` from the request's query string. */
export function parsePagination(
  c: Context,
  opts?: { defaultLimit?: number; maxLimit?: number },
): { limit: number; offset: number } {
  return clampPagination(c.req.query("limit"), c.req.query("offset"), opts);
}
