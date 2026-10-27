// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parseEnv } from "node:util";
import { extractPublicKey, type DIDDocument } from "@aroha-sdk/core/identity";

// ─── Colours ──────────────────────────────────────────────────────────────────
const GREEN  = (s: string) => `\x1b[32m${s}\x1b[0m`;
const RED    = (s: string) => `\x1b[31m${s}\x1b[0m`;
const YELLOW = (s: string) => `\x1b[33m${s}\x1b[0m`;
const BOLD   = (s: string) => `\x1b[1m${s}\x1b[0m`;
const DIM    = (s: string) => `\x1b[2m${s}\x1b[0m`;

function pass(label: string, detail = "") {
  console.log(`  ${GREEN("✓")}  ${label.padEnd(18)} ${DIM(detail)}`);
}

function fail(label: string, detail: string, hint: string) {
  console.log(`  ${RED("✗")}  ${label.padEnd(18)} ${detail}`);
  console.log(`          ${YELLOW("→")} ${hint}`);
}

function warn(label: string, detail: string, hint: string) {
  console.log(`  ${YELLOW("!")}  ${label.padEnd(18)} ${detail}`);
  console.log(`          ${YELLOW("→")} ${hint}`);
}

// ─── Checks ───────────────────────────────────────────────────────────────────

function checkNode(): boolean {
  const version = process.versions.node;
  const [major] = version.split(".").map(Number);
  if (major >= 22) {
    pass("Node.js", `v${version}`);
    return true;
  }
  fail("Node.js", `v${version} (need ≥22)`, "Install Node.js 22+  →  https://nodejs.org");
  return false;
}

function checkEnv(): { did: string | null; hasKey: boolean; ok: boolean } {
  const cwd = process.cwd();
  const envPath = join(cwd, ".env");

  if (!existsSync(envPath)) {
    warn(".env", "not found", "Run `aroha init --yes` to generate one, or create .env manually.");
    return { did: null, hasKey: false, ok: true }; // missing .env is a warning, not a failure
  }

  // Node's built-in dotenv parser (the one behind `node --env-file`): strips
  // matching quotes, `export `, inline `# comments`, whitespace and CR.
  const env = parseEnv(readFileSync(envPath, "utf8"));

  const did = env.AROHA_AGENT_DID || null;
  const key = env.AROHA_PRIVATE_KEY ?? null;

  let ok = true;
  if (!did) {
    fail(".env DID", "AROHA_AGENT_DID not set", "Add AROHA_AGENT_DID=did:aroha:<name> to your .env");
    ok = false;
  } else {
    pass(".env", `AROHA_AGENT_DID=${did}`);
  }

  const hasKey = !!key && key.length > 0;
  if (!hasKey) {
    warn(".env key", "AROHA_PRIVATE_KEY is empty", "Set AROHA_PRIVATE_KEY to your Ed25519 private key (base64). For dev, an ephemeral key is fine.");
  }

  return { did, hasKey, ok };
}

/**
 * Check the DID document served at /.well-known/aroha-agent.json the way
 * core consumes it (`ArohaClient.fetchDIDDocument` + `extractPublicKey`).
 * Returns null when usable, otherwise what is wrong.
 */
export function didDocumentProblem(doc: unknown, expectedDid?: string | null): string | null {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return "response is not a JSON object";
  const d = doc as Record<string, unknown>;
  if (typeof d.id !== "string" || !d.id.startsWith("did:")) return "DID document has no `id` DID";
  if (expectedDid && d.id !== expectedDid) return `DID document id ${d.id} does not match AROHA_AGENT_DID=${expectedDid}`;
  if (!Array.isArray(d.verificationMethod) || d.verificationMethod.length === 0) {
    return "DID document has no verificationMethod";
  }
  try {
    const key = extractPublicKey(d as unknown as DIDDocument);
    if (key.length !== 32) return `verificationMethod key is ${key.length} bytes, expected a 32-byte Ed25519 key`;
  } catch (err) {
    return `no usable public key: ${(err as Error).message}`;
  }
  return null;
}

/** An @aroha-sdk/run manifest: no DID document fields at all. */
function isRunManifest(doc: unknown): boolean {
  if (!doc || typeof doc !== "object") return false;
  const d = doc as Record<string, unknown>;
  return "arohaProtocolVersion" in d && !("id" in d) && !("verificationMethod" in d);
}

async function checkEndpoint(endpoint: string, expectedDid?: string | null): Promise<boolean> {
  const wellKnown = `${endpoint.replace(/\/$/, "")}/.well-known/aroha-agent.json`;
  const start = Date.now();

  let doc: { id?: string };
  try {
    const res = await fetch(wellKnown);
    if (!res.ok) {
      fail("Endpoint", `HTTP ${res.status} from ${wellKnown}`, `Ensure your agent server is running at ${endpoint}`);
      return false;
    }
    doc = await res.json() as { id?: string };
  } catch (err) {
    fail("Endpoint", String(err), `Check that your agent is running at ${endpoint}\nRun: npm run dev`);
    return false;
  }

  const ms = Date.now() - start;
  if (isRunManifest(doc)) {
    warn("Endpoint", `serves an agent manifest, not a DID document  ${ms}ms`,
      "DID and key not checked. Agents built with @aroha-sdk/run serve a manifest at this path.");
    return true;
  }
  const problem = didDocumentProblem(doc, expectedDid);
  if (problem) {
    fail("DID document", problem, `Serve the agent's DID document (id = its DID, with an Ed25519 verificationMethod) at ${wellKnown}`);
    return false;
  }
  pass("DID document", `${doc.id}  ${ms}ms`);
  return true;
}

async function checkRoundTrip(endpoint: string): Promise<void> {
  const arohaV1 = `${endpoint.replace(/\/$/, "")}/aroha/v1`;
  const start = Date.now();

  // Send a minimal unauthenticated ping — a well-formed agent should return 400
  // with a structured error (not a raw crash). This proves the server is alive
  // and parsing JSON.
  try {
    const res = await fetch(arohaV1, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "ArohaRequest", from: "did:aroha:doctor", to: "did:aroha:target", correlationId: "doctor-test", issuedAt: new Date().toISOString(), nonce: "test", body: { capability: "doctor-ping", params: {} } }),
    });
    const ms = Date.now() - start;
    if (res.status === 400 || res.status === 401 || res.status === 200) {
      pass("Round-trip", `${res.status} in ${ms}ms`);
    } else {
      warn("Round-trip", `Unexpected status ${res.status}`, "Agent returned an unexpected status code for a test request.");
    }
  } catch (err) {
    fail("Round-trip", String(err), `POST ${arohaV1} failed — is the agent running?`);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export async function runDoctor(endpoint?: string): Promise<void> {
  console.log(`\n${BOLD("aroha doctor")} — environment check\n`);

  let ok = true;

  ok = checkNode() && ok;
  const env = checkEnv();
  ok = env.ok && ok;

  if (endpoint) {
    console.log();
    const alive = await checkEndpoint(endpoint, env.did);
    ok = alive && ok;
    if (alive) {
      await checkRoundTrip(endpoint);
    }
  } else {
    console.log(`\n  ${DIM("Tip: run `aroha doctor <endpoint>` to also test connectivity.")}`);
    console.log(`  ${DIM("     e.g. aroha doctor http://localhost:3001")}`);
  }

  console.log();
  if (ok) {
    console.log(`  ${GREEN("✓")} All checks passed.\n`);
  } else {
    console.log(`  ${RED("✗")} Some checks failed — see hints above.\n`);
    process.exit(1);
  }
}
