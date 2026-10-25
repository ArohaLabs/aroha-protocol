// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Routing SDK endpoints — shared quality signal store for the model routing layer.
 *
 * POST /v1/routing/feedback   — submit a batch of quality observations (requires API key)
 * GET  /v1/routing/priors     — retrieve aggregated Beta(α,β) priors (public)
 *
 * This is the feedback loop that turns per-SDK ephemeral learning into a
 * shared, persistent Bayesian prior. SDK instances call GET /v1/routing/priors
 * at session start to warm their OnlineLearner with crowd-sourced observations,
 * then POST /v1/routing/feedback to contribute new observations back.
 */

import { Hono } from "hono";
import { authMiddleware } from "../auth.js";
import type { HonoEnv } from "../index.js";
import type { RoutingSignalRow } from "../repository.js";

export const routingRoutes = new Hono<HonoEnv>();

interface FeedbackSignal {
  modelId:          string;
  taskType:         string;
  complexityBucket: number;
  quality:          number;
  tokenCount?:      number;
}

routingRoutes.post("/feedback", authMiddleware, async (c) => {
  let body: { signals: FeedbackSignal[] };
  try {
    body = await c.req.json<{ signals: FeedbackSignal[] }>();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (!Array.isArray(body?.signals) || body.signals.length === 0) {
    return c.json({ error: "signals array is required and must be non-empty" }, 400);
  }
  if (body.signals.length > 100) {
    return c.json({ error: "Max 100 signals per request" }, 400);
  }

  const keyHash = c.get("keyHash");

  const rows: RoutingSignalRow[] = [];
  for (const s of body.signals) {
    if (!s.modelId || !s.taskType) {
      return c.json({ error: "Each signal requires modelId and taskType" }, 400);
    }
    if (typeof s.quality !== "number" || s.quality < 0 || s.quality > 1) {
      return c.json({ error: "quality must be a number between 0 and 1" }, 400);
    }
    if (typeof s.complexityBucket !== "number" || s.complexityBucket < 0 || s.complexityBucket > 9) {
      return c.json({ error: "complexityBucket must be 0–9" }, 400);
    }
    rows.push({
      modelId:          s.modelId,
      taskType:         s.taskType,
      complexityBucket: s.complexityBucket,
      quality:          s.quality,
      tokenCount:       s.tokenCount ?? 0,
      apiKeyHash:       keyHash,
    });
  }

  await c.get("repo").recordRoutingSignals(rows);
  return c.json({ ok: true, recorded: rows.length });
});

routingRoutes.get("/priors", async (c) => {
  const modelId = c.req.query("modelId") ?? undefined;
  const priors  = await c.get("repo").getRoutingPriors(modelId);
  return c.json({ priors, count: priors.length });
});
