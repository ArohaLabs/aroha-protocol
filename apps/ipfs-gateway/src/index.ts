// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha IPFS Gateway — Cloudflare Worker
 *
 * Thin proxy over Pinata's pinning service. Exposes three endpoints:
 *
 *   GET  /api/v0/version   — Kubo-compatible health check (what the status page polls)
 *   GET  /ipfs/:cid        — Public content fetch via Pinata gateway
 *   POST /pin              — Pin JSON to IPFS via Pinata (requires a valid registry API key)
 *
 * Secrets required (set via `wrangler secret put <NAME> --name aroha-ipfs-gateway`):
 *   PINATA_JWT — Pinata JWT for server-side pinning calls
 *
 * Service binding (declared in wrangler.toml [[services]]):
 *   REGISTRY — direct internal call to aroha-registry Worker (no HTTP round-trip)
 *
 * Auth for POST /pin: callers send their registry API key as `Authorization: Bearer <key>`.
 * The gateway validates it by calling GET /v1/auth/ping on the registry via a Service Binding
 * (not a plain fetch) to guarantee headers pass through without edge interference.
 */

interface Env {
  PINATA_JWT: string;
  REGISTRY: Fetcher;
  /**
   * Upstream read gateway (wrangler.toml [vars]). This Worker IS a Pinata
   * proxy, so Pinata is its declared upstream, not a silent fallback; the var
   * exists so the upstream is visible in config and can be changed (e.g. to a
   * Pinata dedicated gateway) without a code change.
   */
  PINATA_GATEWAY?: string;
}

/** Default upstream when PINATA_GATEWAY is unset. */
const DEFAULT_PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs";
const PINATA_PIN_URL = "https://api.pinata.cloud/pinning/pinJSONToIPFS";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── GET /api/v0/version — Kubo-compatible health check ───────────────────
    if (request.method === "GET" && url.pathname === "/api/v0/version") {
      return json({
        Version: "0.1.0",
        Commit: "aroha",
        Repo: "14",
        APIVersion: "v0.14.0",
      });
    }

    // ── GET /ipfs/:cid — public content read ─────────────────────────────────
    const ipfsMatch = url.pathname.match(/^\/ipfs\/([A-Za-z0-9]+)$/);
    if (request.method === "GET" && ipfsMatch) {
      const cid = ipfsMatch[1];
      // Pinata's gateway requires authentication — content pinned via their API
      // is not publicly readable without the JWT.
      const gateway = (env.PINATA_GATEWAY?.trim() || DEFAULT_PINATA_GATEWAY).replace(/\/+$/, "");
      const upstream = await fetch(`${gateway}/${cid}`, {
        headers: { Authorization: `Bearer ${env.PINATA_JWT}` },
        signal: AbortSignal.timeout(10_000),
      });

      if (!upstream.ok) {
        return json({ error: `IPFS fetch failed: ${upstream.status}` }, upstream.status);
      }

      const body = await upstream.arrayBuffer();
      return new Response(body, {
        status: 200,
        headers: {
          ...CORS,
          // Always serve as JSON — this gateway only stores Aroha manifests.
          // Locking Content-Type prevents a pinned HTML payload from rendering
          // in the browser (stored XSS via Pinata's reflected Content-Type).
          "Content-Type": "application/json; charset=utf-8",
          "Content-Disposition": `attachment; filename="${cid}.json"`,
          "X-Content-Type-Options": "nosniff",
          "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
          // Safe to cache forever — CIDs are content-addressed and immutable
          "Cache-Control": "public, max-age=31536000, immutable",
        },
      });
    }

    // ── POST /pin — pin JSON content to IPFS via Pinata ──────────────────────
    if (request.method === "POST" && url.pathname === "/pin") {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;

      if (!token) {
        return json({ error: "Authorization header required" }, 401);
      }

      // Validate the API key via the registry Service Binding.
      // Using env.REGISTRY.fetch() (not plain fetch()) routes the call directly through
      // Cloudflare's internal network — guaranteed header passthrough, no TLS overhead.
      let pingOk = false;
      try {
        const ping = await env.REGISTRY.fetch(
          new Request("http://registry/v1/auth/ping", {
            headers: { Authorization: `Bearer ${token}` },
          }),
        );
        pingOk = ping.ok;
      } catch {
        return json({ error: "Could not reach registry to validate key" }, 503);
      }

      if (!pingOk) {
        return json({ error: "Invalid or revoked API key" }, 401);
      }

      let content: unknown;
      try {
        content = await request.json();
      } catch {
        return json({ error: "Request body must be valid JSON" }, 400);
      }

      const pinRes = await fetch(PINATA_PIN_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.PINATA_JWT}`,
        },
        body: JSON.stringify({ pinataContent: content }),
        signal: AbortSignal.timeout(15_000),
      });

      if (!pinRes.ok) {
        const err = await pinRes.text();
        return json({ error: `Pinata error: ${err}` }, 502);
      }

      const result = (await pinRes.json()) as { IpfsHash: string; PinSize: number };
      return json({ cid: result.IpfsHash, size: result.PinSize }, 201);
    }

    return json({ error: "Not found" }, 404);
  },
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}
