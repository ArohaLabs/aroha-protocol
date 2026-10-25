// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { Hono } from "hono";
import type { HonoEnv } from "../index.js";
import { findSchemaGaps } from "../schema-manifest.js";
import { checkAdmin, logAdminUnconfigured, ADMIN_UNCONFIGURED_MESSAGE } from "../secrets.js";
import { manifestGatewayAttempts, type GatewayAttempt } from "../ipfs-gateways.js";

export const healthRoutes = new Hono<HonoEnv>();

healthRoutes.get("/", async (c) => {
  const ts = new Date().toISOString();
  try {
    const row = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM agent_records WHERE active = 1`,
    ).first<{ n: number }>();

    // Connectivity is not health. A database can answer this count perfectly
    // while lacking columns that every list endpoint selects — that is exactly
    // the state production was in while /health reported ok. So also assert the
    // schema this build actually requires.
    const gaps = await findSchemaGaps(c.env.DB);
    if (gaps.length > 0) {
      // The gap list names tables and columns — schema detail an anonymous
      // caller has no use for. The public answer says only "drift"; the
      // operator presenting the admin secret gets the named gaps so they
      // can map straight to a migration instead of reverse-engineering it
      // from a stack trace. The log carries them either way.
      console.error("[health] schema drift:", JSON.stringify(gaps));
      const isAdmin = (await checkAdmin(c)) === "ok";
      return c.json(
        {
          status: "degraded",
          ts,
          db: "ok",
          schema: "drift",
          ...(isAdmin
            ? { gaps, hint: "Unapplied migrations. Run: node scripts/migrate.mjs --remote" }
            : {}),
          activeAgents: row?.n ?? 0,
          version: "1.3.0",
        },
        503,
      );
    }

    return c.json({
      status: "ok",
      ts,
      db: "ok",
      schema: "ok",
      activeAgents: row?.n ?? 0,
      version: "1.3.0",
    });
  } catch (err) {
    // Never echo the driver's error text: it can carry SQL, table names, or
    // binding details. A fixed word publicly, the detail in the log.
    console.error("[health] database check failed:", err);
    return c.json({ status: "degraded", ts, db: "unavailable" }, 503);
  }
});

/** GET /health/caps?cid=Qm... — admin-only debug: test capability fetch for a CID */
healthRoutes.get("/caps", async (c) => {
  const check = await checkAdmin(c);
  if (check === "unconfigured") {
    logAdminUnconfigured();
    return c.json({ error: ADMIN_UNCONFIGURED_MESSAGE }, 503);
  }
  if (check !== "ok") return c.json({ error: "Unauthorized" }, 401);
  const cid = c.req.query("cid");
  if (!cid) return c.json({ error: "cid query param required" }, 400);

  const env = c.env;
  // The same gateways, in the same order, that registration uses.
  const attempts: GatewayAttempt[] = manifestGatewayAttempts(cid, env);
  if (!env.PINATA_JWT) attempts.unshift({ label: "pinata-jwt-missing", url: "" });

  const results: Array<Record<string, unknown>> = [];
  for (const { label, url, headers } of attempts) {
    if (!url) { results.push({ label, skipped: true }); continue; }
    try {
      const res = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) });
      const body = await res.text();
      let parsed: unknown = null;
      try { parsed = JSON.parse(body); } catch { /* not json */ }
      results.push({ label, url, status: res.status, caps: (parsed as { capabilities?: unknown })?.capabilities ?? null, bodyHead: body.slice(0, 200) });
    } catch (err) {
      results.push({ label, url, threw: String(err) });
    }
  }

  return c.json({ cid, pinataJwtPresent: !!env.PINATA_JWT, results });
});
