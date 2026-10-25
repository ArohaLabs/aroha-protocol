// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Model catalog endpoints — exposes the registry's model profiles for SDK routing.
 *
 * GET  /v1/models          — public; returns active models (optional ?provider= filter)
 * POST /v1/models          — admin only; upsert a model profile
 */

import { Hono } from "hono";
import { adminMiddleware } from "../auth.js";
import type { HonoEnv } from "../index.js";
import type { ModelCatalogRow } from "../repository.js";

export const modelRoutes = new Hono<HonoEnv>();

modelRoutes.get("/", async (c) => {
  const provider = c.req.query("provider") ?? undefined;
  const models   = await c.get("repo").getModelCatalog(provider);

  // ETag based on the latest updatedAt timestamp — clients can use If-None-Match
  // to skip re-parsing the catalog when nothing has changed (common at SDK boot).
  const maxUpdatedAt = models.reduce((m, r) => Math.max(m, r.updatedAt), 0);
  const etag         = `"mc-${maxUpdatedAt}-${models.length}"`;

  c.header("Cache-Control", "public, max-age=300, stale-while-revalidate=60");
  c.header("ETag", etag);

  if (c.req.header("If-None-Match") === etag) {
    return c.newResponse(null, 304);
  }

  return c.json({ models, count: models.length });
});

modelRoutes.post("/", adminMiddleware, async (c) => {
  let body: Partial<ModelCatalogRow>;
  try {
    body = await c.req.json<Partial<ModelCatalogRow>>();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const required: (keyof ModelCatalogRow)[] = [
    "modelId", "provider", "tier",
    "inputPricePerMtok", "outputPricePerMtok",
    "contextWindow", "avgLatencyMs",
  ];
  for (const field of required) {
    if (body[field] === undefined || body[field] === null) {
      return c.json({ error: `Missing required field: ${field}` }, 400);
    }
  }

  const row: ModelCatalogRow = {
    modelId:               body.modelId!,
    provider:              body.provider!,
    tier:                  body.tier!,
    inputPricePerMtok:     body.inputPricePerMtok!,
    outputPricePerMtok:    body.outputPricePerMtok!,
    contextWindow:         body.contextWindow!,
    avgLatencyMs:          body.avgLatencyMs!,
    qualityReasoning:      body.qualityReasoning      ?? 0.7,
    qualityCode:           body.qualityCode           ?? 0.7,
    qualityExtraction:     body.qualityExtraction     ?? 0.7,
    qualityCreative:       body.qualityCreative       ?? 0.7,
    qualityClassification: body.qualityClassification ?? 0.7,
    qualitySummarization:  body.qualitySummarization  ?? 0.7,
    active:                body.active                ?? true,
    updatedAt:             Date.now(),
  };

  await c.get("repo").upsertModel(row);
  return c.json({ ok: true, modelId: row.modelId }, 201);
});
