// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * HealthChecker — pre-flight agent liveness probes.
 *
 * Before initiating a multi-step saga, the orchestrator can call
 * HealthChecker.checkAll() to verify that all participants are reachable
 * and in a healthy state. Agents that respond with "degraded" can still
 * participate but are flagged. Agents that fail the probe are excluded.
 *
 * Agent health endpoint contract:
 *   GET /health  →  { status: "ready" | "degraded" | "draining" }
 *
 * "ready"    — fully operational, include in saga
 * "degraded" — operational but under load/partial, warn but include
 * "draining" — shutting down, exclude from new sagas
 */

export type AgentHealthStatus = "ready" | "degraded" | "draining" | "unreachable";

export interface AgentHealthResult {
  agentDID: string;
  endpoint: string;
  status: AgentHealthStatus;
  latencyMs: number;
  error?: string;
}

export interface HealthCheckConfig {
  /** Timeout per probe in ms. Default: 3_000 */
  timeoutMs?: number;
  /**
   * Cache TTL for health results. Avoids re-probing agents within a short window.
   * Default: 5_000 (5 seconds)
   */
  cacheTtlMs?: number;
}

interface CachedResult {
  result: AgentHealthResult;
  cachedAt: number;
}

export class HealthChecker {
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, CachedResult>();

  constructor(config: HealthCheckConfig = {}) {
    this.timeoutMs  = config.timeoutMs  ?? 3_000;
    this.cacheTtlMs = config.cacheTtlMs ?? 5_000;
  }

  /**
   * Check a single agent endpoint.
   * Returns cached result if within TTL.
   */
  async check(agentDID: string, endpoint: string): Promise<AgentHealthResult> {
    const cached = this.cache.get(agentDID);
    if (cached && Date.now() - cached.cachedAt < this.cacheTtlMs) {
      return cached.result;
    }

    const healthUrl = this.resolveHealthUrl(endpoint);
    const start = Date.now();

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(healthUrl, {
        method: "GET",
        signal: controller.signal,
        headers: { Accept: "application/json" },
      }).finally(() => clearTimeout(timer));

      const latencyMs = Date.now() - start;

      if (!res.ok) {
        const result: AgentHealthResult = { agentDID, endpoint, status: "unreachable", latencyMs, error: `HTTP ${res.status}` };
        this.cache.set(agentDID, { result, cachedAt: Date.now() });
        return result;
      }

      const body = await res.json().catch(() => ({})) as { status?: string };
      const rawStatus = body.status ?? "ready";
      const status: AgentHealthStatus =
        rawStatus === "ready"    ? "ready"    :
        rawStatus === "degraded" ? "degraded" :
        rawStatus === "draining" ? "draining" :
        "unreachable";

      const result: AgentHealthResult = { agentDID, endpoint, status, latencyMs };
      this.cache.set(agentDID, { result, cachedAt: Date.now() });
      return result;
    } catch (err) {
      const latencyMs = Date.now() - start;
      const error = err instanceof Error ? err.message : String(err);
      const result: AgentHealthResult = { agentDID, endpoint, status: "unreachable", latencyMs, error };
      this.cache.set(agentDID, { result, cachedAt: Date.now() });
      return result;
    }
  }

  /**
   * Check all agents in parallel. Returns results for all, including unhealthy ones.
   * The orchestrator decides what to do with degraded/draining/unreachable agents.
   */
  async checkAll(
    agents: Array<{ agentDID: string; endpoint: string }>
  ): Promise<AgentHealthResult[]> {
    return Promise.all(agents.map((a) => this.check(a.agentDID, a.endpoint)));
  }

  /**
   * Filter a candidate list to only healthy agents.
   * "degraded" agents are included with a warning in the result.
   */
  async filterHealthy(
    agents: Array<{ agentDID: string; endpoint: string }>,
    opts: { allowDegraded?: boolean } = {}
  ): Promise<{ healthy: typeof agents; excluded: AgentHealthResult[] }> {
    const results = await this.checkAll(agents);
    const excluded: AgentHealthResult[] = [];
    const healthy: typeof agents = [];

    for (let i = 0; i < agents.length; i++) {
      const r = results[i];
      const include =
        r.status === "ready" ||
        (opts.allowDegraded && r.status === "degraded");

      if (include) {
        healthy.push(agents[i]);
      } else {
        excluded.push(r);
      }
    }

    return { healthy, excluded };
  }

  /** Derive the /health URL from the agent's base endpoint. */
  private resolveHealthUrl(endpoint: string): string {
    try {
      const url = new URL(endpoint);
      // Replace path with /health
      url.pathname = "/health";
      url.search = "";
      return url.toString();
    } catch {
      return `${endpoint.replace(/\/$/, "")}/health`;
    }
  }
}
