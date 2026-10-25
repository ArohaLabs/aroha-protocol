// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Analytics endpoints — gives agent publishers visibility into discovery activity.
 *
 * GET /v1/analytics/agents/:didHash  — per-agent discovery counts (requires API key)
 * GET /v1/analytics/summary          — platform-wide summary (requires admin secret)
 */

import { Hono } from "hono";
import { authMiddleware, adminMiddleware } from "../auth.js";
import type { HonoEnv } from "../index.js";
import { canViewAgent, viewerDependent } from "../visibility.js";

export const analyticsRoutes = new Hono<HonoEnv>();

/**
 * GET /v1/analytics/agents/:didHash
 *
 * Returns how many times this agent's record was fetched (discovery events).
 * Requires a valid API key — any key holder can query the stats of an agent
 * they can see. A private agent's stats follow GET /v1/agents/:did: owner or
 * grantee only, 404 for everyone else.
 */
analyticsRoutes.get("/agents/:didHash", authMiddleware, async (c) => {
  const didHash = c.req.param("didHash")!;
  const repo = c.get("repo");
  const agent = await repo.getAgent(didHash);
  if (!agent || !(await canViewAgent(repo, agent, c.get("keyHash")))) {
    return c.json({ error: "Agent not found" }, 404);
  }

  const stats = await repo.getAgentDiscoveryStats(didHash);
  viewerDependent(c);
  return c.json({ didHash, did: agent.did, ...stats });
});

/**
 * GET /v1/analytics/summary
 *
 * Platform-wide summary: active agents, verified agents, recent event volume.
 * Requires the ADMIN_SECRET — not intended for public consumption.
 */
analyticsRoutes.get("/summary", adminMiddleware, async (c) => {
  const summary = await c.get("repo").getAnalyticsSummary();
  return c.json(summary);
});
