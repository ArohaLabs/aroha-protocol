// Test factory: creates a fully wired Hono app backed by in-memory SQLite.
// Usage:
//   const { app, apiKey, keyHash, env } = await makeApp();
//   const res = await app.request("/v1/agents", { method: "GET" }, env);

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import app from "../index.js";
import { sha256hex } from "../auth.js";
import { openDb } from "./sqlite-d1.js";

/**
 * The real production schema — read from schema.sql, never re-typed here.
 *
 * This used to be a hand-maintained copy, which meant the test database and
 * the production database were two independent guesses at the same thing. The
 * copy drifted into being MORE complete than schema.sql: it had five tables
 * and every migration's columns, while schema.sql had neither. So the suite
 * passed against a schema that no real deployment could ever have, and a
 * bootstrap from schema.sql would have produced a broken registry.
 *
 * Loading the file means a schema mistake now fails the tests instead of
 * waiting to fail in production.
 */
const SCHEMA_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "schema.sql");
export const FULL_SCHEMA = readFileSync(SCHEMA_PATH, "utf8");


/** Test-only registry signing seed (hex). Never used outside the test suite. */
export const TEST_REGISTRY_SIGNING_KEY = "11".repeat(32);

export interface TestApp {
  app: typeof app;
  apiKey: string;
  keyHash: string;
  env: {
    DB: unknown; ADMIN_SECRET: string; IPFS_GATEWAY: string;
    CLOUDFLARE_API_TOKEN: string; CLOUDFLARE_ZONE_ID: string; PROVISION_DOMAIN: string;
    REGISTRY_SIGNING_KEY?: string; REGISTRY_SIGNING_KEY_PREVIOUS?: string;
  };
}

export async function makeApp(orgName = "Test Org"): Promise<TestApp> {
  const { adapter } = openDb(FULL_SCHEMA);

  // Generate and seed a test API key
  const apiKey = "test-api-key-" + Math.random().toString(36).slice(2);
  const keyHash = await sha256hex(apiKey);

  await adapter
    .prepare(`INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`)
    .bind(keyHash, orgName, Date.now())
    .run();

  const env = {
    DB: adapter as unknown as D1Database,
    ADMIN_SECRET: "test-admin-secret-0123456789abcdefghijklmn",
    IPFS_GATEWAY: "http://localhost:5001/ipfs",
    CLOUDFLARE_API_TOKEN: "test-cf-token",
    CLOUDFLARE_ZONE_ID: "test-cf-zone",
    PROVISION_DOMAIN: "firms.aroha-labs.com",
    // A fixed, test-only Ed25519 seed so signed routes (registry-signing.ts)
    // work; tests that need the unconfigured (503) path delete it.
    REGISTRY_SIGNING_KEY: TEST_REGISTRY_SIGNING_KEY as string | undefined,
    REGISTRY_SIGNING_KEY_PREVIOUS: undefined as string | undefined,
  };

  return { app, apiKey, keyHash, env };
}
