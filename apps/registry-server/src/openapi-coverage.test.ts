// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Every route this Worker serves is in the published OpenAPI contract
// (packages/aroha-registry/openapi.yaml). The contract had drifted to six
// documented paths while the Worker served dozens, and several documented
// shapes were wrong — an integrator reading the spec could not have found
// the challenge step registration requires. Walking the router keeps the
// two from drifting apart again: adding a route without documenting it
// fails here.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import app from "./index.js";

const SPEC_PATH = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "packages", "aroha-registry", "openapi.yaml");
/**
 * `paths:` → { path: { method: true } }, read straight off the YAML's
 * indentation (two spaces for a path, four for its methods). A full YAML
 * parser is not a dependency of this package, and the spec's layout is
 * fixed by convention; a structural change that breaks this reading makes
 * the sanity test below fail rather than pass vacuously.
 */
function specPaths(text: string): Record<string, Record<string, true>> {
  const paths: Record<string, Record<string, true>> = {};
  let inPaths = false;
  let current: string | null = null;
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    if (/^\S/.test(line)) { inPaths = line.startsWith("paths:"); current = null; continue; }
    if (!inPaths) continue;
    const p = /^  (\/\S*):\s*$/.exec(line);
    if (p) { current = p[1]!; paths[current] = {}; continue; }
    const m = /^    (get|post|put|patch|delete):/.exec(line);
    if (m && current) paths[current]![m[1]!] = true;
  }
  return paths;
}
const spec = { paths: specPaths(readFileSync(SPEC_PATH, "utf8")) };

/**
 * Routes deliberately left out of the public contract. Keep this short and
 * say why for each — an entry here is a route integrators cannot discover.
 */
const INTERNAL: ReadonlyArray<{ method: string; path: string; why: string }> = [
  { method: "GET", path: "/health/caps", why: "operator debug probe of IPFS gateways (admin secret); not an API" },
];

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

/**
 * Parameter NAMES are not part of a path's identity in OpenAPI —
 * /v1/agents/{did} and /v1/agents/{didHash} are the same template, and a
 * spec may only list it once. Compare shapes, not names.
 */
const shape = (p: string) => p.replace(/\{\w+\}/g, "{}");

function served(): Array<{ method: string; path: string }> {
  const seen = new Set<string>();
  const out: Array<{ method: string; path: string }> = [];
  for (const r of (app as unknown as { routes: Array<{ method: string; path: string }> }).routes) {
    if (!METHODS.has(r.method)) continue; // middleware registrations are method "ALL"
    const path = r.path.replace(/\/$/, "") || "/";
    // Hono :param → OpenAPI {param}
    const openapiPath = path.replace(/:(\w+)/g, "{$1}");
    const key = `${r.method} ${shape(openapiPath)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ method: r.method, path: openapiPath });
  }
  return out;
}

describe("openapi.yaml covers every served route", () => {
  it("finds routes to check (router walk sanity)", () => {
    expect(served().length).toBeGreaterThan(40);
    expect(Object.keys(spec.paths).length).toBeGreaterThan(40);
  });

  const specOps = new Set<string>();
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const m of Object.keys(ops)) if (METHODS.has(m.toUpperCase())) specOps.add(`${m.toUpperCase()} ${shape(path)}`);
  }

  it("documents each route with a matching path and method", () => {
    const missing = served()
      .filter((r) => !INTERNAL.some((i) => i.method === r.method && i.path === r.path))
      .filter((r) => !specOps.has(`${r.method} ${shape(r.path)}`))
      .map((r) => `${r.method} ${r.path}`);
    expect(missing, `undocumented routes:\n${missing.join("\n")}`).toEqual([]);
  });

  it("documents no path the Worker does not serve (except the self-hosted /healthz)", () => {
    const servedKeys = new Set(served().map((r) => `${r.method} ${shape(r.path)}`));
    const extra = [...specOps].filter((k) => !servedKeys.has(k) && k !== "GET /healthz");
    expect(extra).toEqual([]);
  });
});
