// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Registry — Cloudflare Worker entry point
 *
 * Architecture:
 *   Hono router  →  RegistryRepository interface  →  D1Repository (today)
 *                                                  →  PostgresRepository (future)
 *
 * To swap to Postgres (zero downtime):
 *   1. Implement PostgresRepository satisfying RegistryRepository
 *   2. Replace `new D1Repository(c.env.DB)` below with `new PostgresRepository(connectionString)`
 *   3. Deploy — routes, auth, and clients are unchanged
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { bodyLimit } from "hono/body-limit";
import { MAX_KEL_BODY_BYTES } from "./kel-store.js";
import { pruneExpired } from "./retention.js";
import { D1Repository } from "./d1-repository.js";
import type { RegistryRepository } from "./repository.js";
import { agentRoutes } from "./routes/agents.js";
import { mcpRoutes } from "./routes/mcps.js";
import { skillRoutes } from "./routes/skills.js";
import { keyRoutes } from "./routes/keys.js";
import { healthRoutes } from "./routes/health.js";
import { signalRoutes } from "./routes/signals.js";
import { spendingRoutes } from "./routes/spending.js";
import { credentialRoutes } from "./routes/credential.js";
import { analyticsRoutes } from "./routes/analytics.js";
import { modelRoutes } from "./routes/models.js";
import { routingRoutes } from "./routes/routing.js";
import { adminRoutes } from "./routes/admin.js";
import { grantRoutes } from "./routes/grants.js";
import { spaceRoutes } from "./routes/spaces.js";
import { trustRoutes } from "./routes/trust.js";
import { sarRoutes } from "./routes/sar.js";
import { personalNameRoutes } from "./routes/personal-names.js";
import { relayRoutes } from "./routes/relay.js";
import { kelRoutes, linkageRoutes } from "./routes/kel.js";
import { mandateRoutes } from "./routes/mandates.js";
import { auditAnchorRoutes, registryKeysRoutes } from "./routes/audit-anchors.js";
import { agentIdentityRoutes } from "./routes/agent-identity.js";
import { ssfRoutes, ssfWellKnownRoutes } from "./routes/ssf.js";
import { retryPendingPushes } from "./ssf.js";
import { AgentRelay } from "./relay/agent-relay.js";
import { globalIpLimiter } from "./middleware/rate-limit.js";

// Durable Object classes must be exported from the Worker's main module
// (see wrangler.toml's durable_objects binding) — this re-export is that
// requirement, not a public API of this module.
export { AgentRelay };

// ─── Environment bindings (set in wrangler.toml + `wrangler secret put`) ─────
export interface Env {
  DB: D1Database;
  /**
   * Relay broker (M10, design spec §6.3) — one Durable Object instance per
   * agent DID (keyed by didHash). Optional in this type (not in a real
   * deployment's wrangler.toml) so the existing plain-Node test harness in
   * test-utils/make-app.ts — which never runs inside the actual Workers
   * runtime and so cannot construct a real DurableObjectNamespace — stays
   * valid for every route that doesn't touch the relay. routes/relay.ts
   * itself checks for its absence and fails closed with a clear error
   * rather than crashing.
   */
  AGENT_RELAY?: DurableObjectNamespace;
  /** Operator secret. Must be ≥ 32 chars or every admin route answers 503 — see secrets.ts. */
  ADMIN_SECRET: string;
  /**
   * Optional: key material for credential JWTs (routes/credential.ts). When
   * unset, the credential key is derived from ADMIN_SECRET instead; setting
   * it lets admin access and credentials rotate independently.
   */
  CREDENTIAL_SECRET?: string;
  IPFS_GATEWAY: string;
  /**
   * Optional comma-separated https gateways tried after IPFS_GATEWAY when
   * fetching a manifest (see ipfs-gateways.ts). Declared in wrangler.toml so
   * no third-party gateway is used without being listed there.
   */
  IPFS_FALLBACK_GATEWAYS?: string;
  /** Pinata JWT for authenticated manifest fetching (avoids public-gateway rate limits) */
  PINATA_JWT?: string;
  /**
   * The registry's Ed25519 signing seed (32 bytes, hex or base64url) — signs
   * audit anchors and revocation status (registry-signing.ts). Unset or
   * malformed, those routes and the key document answer 503 (fail closed).
   */
  REGISTRY_SIGNING_KEY?: string;
  /** The seed REGISTRY_SIGNING_KEY replaced; published as retired so old signatures verify. */
  REGISTRY_SIGNING_KEY_PREVIOUS?: string;
}

// ─── Hono context variables ───────────────────────────────────────────────────
export type HonoEnv = {
  Bindings: Env;
  Variables: {
    repo: RegistryRepository;
    keyHash: string;
    orgName: string;
    /** Ed25519 org signing public key (base64), if the org has registered one. */
    orgPublicKeyB64: string | null;
  };
};

// ─── App ─────────────────────────────────────────────────────────────────────
const app = new Hono<HonoEnv>();

app.use(
  "*",
  cors({
    origin: "*",
    // PATCH is used by the visibility routes; without it a browser preflight
    // for them failed even though the routes themselves worked.
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  }),
);

// ─── Request body ceiling ─────────────────────────────────────────────────────
// 64 KiB for every write. Nothing a route here accepts legitimately comes
// close (a manifest is referenced by CID, never uploaded), and an unbounded
// body is memory and CPU an unauthenticated caller can spend before any
// handler runs. Paths that legitimately carry a whole Key Event Log keep
// their own 256 KiB limit (MAX_KEL_BODY_BYTES, enforced in kel.ts / below)
// and are excluded here — a smaller global limit would wrap the stream
// first and the larger per-route one could never apply. SAR publication is
// one of them because a record may carry its agent's KEL as an attachment.
const MAX_BODY_BYTES = 64 * 1024;
const LARGE_BODY_PREFIXES = ["/v1/kel/", "/v1/linkage", "/v1/sar"];
const defaultBodyLimit = bodyLimit({
  maxSize: MAX_BODY_BYTES,
  onError: (c) => c.json({ error: `request body exceeds ${MAX_BODY_BYTES} bytes` }, 413),
});
const largeBodyLimit = bodyLimit({
  maxSize: MAX_KEL_BODY_BYTES,
  onError: (c) => c.json({ error: `request body exceeds ${MAX_KEL_BODY_BYTES} bytes` }, 413),
});
app.use("*", async (c, next) => {
  const m = c.req.method;
  if (m !== "POST" && m !== "PUT" && m !== "PATCH") return next();
  const path = new URL(c.req.url).pathname;
  const limiter = LARGE_BODY_PREFIXES.some((p) => path.startsWith(p)) ? largeBodyLimit : defaultBodyLimit;
  return limiter(c, next);
});

// Inject repository into every request context.
// To migrate: replace D1Repository with PostgresRepository here only.
app.use("*", async (c, next) => {
  c.set("repo", new D1Repository(c.env.DB));
  await next();
});

// Global rate limit: 200 req/min per IP across all /v1/* routes.
// Tight per-endpoint limits are applied in the individual route files.
app.use("/v1/*", globalIpLimiter);

app.route("/health", healthRoutes);
app.route("/v1/signals", signalRoutes);
app.route("/v1/agents", agentRoutes);
// Client ID Metadata Documents, agent JWKS, monitoring summary and the
// audited flag — see routes/agent-identity.ts.
app.route("/v1/agents", agentIdentityRoutes);
app.route("/v1/mcps", mcpRoutes);
app.route("/v1/skills", skillRoutes);
app.route("/v1/auth", keyRoutes);
app.route("/v1/grants", grantRoutes);
// Spaces sit beside grants because that is what they compose: every
// membership writes ordinary grant rows. See routes/spaces.ts.
app.route("/v1/spaces", spaceRoutes);
app.route("/v1/spending", spendingRoutes);
app.route("/v1/credential", credentialRoutes);
app.route("/v1/analytics", analyticsRoutes);
app.route("/v1/models", modelRoutes);
app.route("/v1/routing", routingRoutes);
app.route("/v1/admin", adminRoutes);
app.route("/v1", trustRoutes);
app.route("/v1/sar", sarRoutes);
app.route("/v1/personal-names", personalNameRoutes);
app.route("/v1/relay", relayRoutes);
// Rotatable E-DIDs: Key Event Logs and legacy-DID linkages. See routes/kel.ts.
app.route("/v1/kel", kelRoutes);
app.route("/v1/linkage", linkageRoutes);
app.route("/v1/mandates", mandateRoutes);
app.route("/v1/audit-anchors", auditAnchorRoutes);
app.route("/.well-known", registryKeysRoutes);
// Shared Signals transmitter: configuration, JWKS and stream management (routes/ssf.ts).
app.route("/.well-known", ssfWellKnownRoutes);
app.route("/v1/ssf", ssfRoutes);

app.notFound((c) => c.json({ error: "Not found" }, 404));
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "Internal server error" }, 500);
});

// ─── Scheduled retention (wrangler.toml [triggers] crons) ─────────────────────
// Deletes expired single-use rows and trims accumulating tables; the windows
// and their reasons are in retention.ts. waitUntil keeps the invocation alive
// until the deletes finish without holding the scheduler.
async function scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
  ctx.waitUntil(
    pruneExpired(env.DB).then(
      (removed) => console.log("[retention] pruned", JSON.stringify(removed)),
      (err) => console.error("[retention] run failed:", err),
    ),
  );
  // Shared Signals push deliveries that failed in the request flow (ssf.ts).
  ctx.waitUntil(
    retryPendingPushes(env).then(
      (n) => { if (n > 0) console.log("[ssf] retried", n, "push deliveries"); },
      (err) => console.error("[ssf] retry run failed:", err),
    ),
  );
}

// The Hono app IS the module's fetch handler; `scheduled` rides on the same
// default export because Workers reads both handlers from it. Tests keep
// using the app directly (app.request).
export default Object.assign(app, { scheduled });
