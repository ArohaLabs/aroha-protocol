#!/usr/bin/env node
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Type-checks every ```ts / ```typescript block in the root README and in
// every workspace package README against the BUILT packages (dist/*.d.ts) —
// the same declarations an npm-installed consumer compiles against.
//
// How it works:
//   1. Each fenced block becomes its own module under .readme-check/ (a
//      gitignored scratch dir at the repo root, so node_modules lookups for
//      third-party types work).
//   2. `@aroha-sdk/*` specifiers are mapped (tsconfig `paths`) to each
//      workspace package's dist/*.d.ts, built from its package.json
//      "exports" — so a README importing a subpath that is not exported
//      fails, exactly as it would for a user.
//   3. Free variables — README snippets deliberately lean on context such as
//      "assume you already have humanPrivateKey" — are found from the
//      compiler's own "Cannot find name" diagnostics and declared in a
//      prelude as `declare const x: any` (plus a same-named `any` type), then
//      the block is re-checked. Everything else — missing exports, wrong
//      argument types, wrong arity, non-existent properties on SDK return
//      types — is a real failure.
//   4. Third-party modules that are not installed in this repo (e.g. a web
//      framework a snippet uses for illustration) get an ambient
//      `declare module "x";` shim. Missing `@aroha-sdk/*` modules or subpaths
//      are never shimmed.
//
// A block that is intentionally not a program (pseudo-code, a type sketch
// for a future API) can opt out with an HTML comment on the line directly
// above the fence:  <!-- readme-check: skip -->
// Use it sparingly; every skip is printed in the summary.
//
// Requires `npm run build` first.
//
// Usage: node scripts/check-readme-examples.mjs [--keep]   (--keep leaves .readme-check/ for debugging)

import { readFileSync, existsSync, readdirSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(ROOT, "package.json"));
const ts = require("typescript");

const KEEP = process.argv.includes("--keep");
const WORK = join(ROOT, ".readme-check");
const WORKSPACE_DIRS = ["packages", "agents", "apps"];
const FENCE_RE = /^```(ts|typescript)\s*$/;
const SKIP_MARKER = "<!-- readme-check: skip -->";
// cannot find name / namespace; 18004 = shorthand property `{ x }` with no `x` in scope
const MISSING_NAME_CODES = new Set([2304, 2552, 2582, 2503, 18004]);
const MISSING_MODULE_CODES = new Set([2307, 2792]);
const MAX_ROUNDS = 5;

// ─── Workspace packages and their exported entry points ──────────────────────

function workspacePackages() {
  const out = [];
  for (const ws of WORKSPACE_DIRS) {
    const base = join(ROOT, ws);
    if (!existsSync(base)) continue;
    for (const d of readdirSync(base, { withFileTypes: true })) {
      if (!d.isDirectory()) continue;
      const dir = join(base, d.name);
      const pj = join(dir, "package.json");
      if (!existsSync(pj)) continue;
      try {
        const json = JSON.parse(readFileSync(pj, "utf8"));
        if (json.name) out.push({ dir, json });
      } catch { /* unreadable package.json — not a workspace package */ }
    }
  }
  return out;
}

/** "./dist/x/index.js" → "<dir>/dist/x/index.d.ts" */
function declFor(dir, target) {
  if (typeof target !== "string") {
    target = target?.types ?? target?.import ?? target?.default ?? target?.require;
    if (typeof target !== "string") return null;
  }
  const rel = target.replace(/^\.\//, "");
  const dts = rel.endsWith(".d.ts") ? rel : rel.replace(/\.(m?js|cjs)$/, ".d.ts");
  return join(dir, dts);
}

function buildPaths(pkgs) {
  const paths = {};
  const missingBuild = [];
  for (const { dir, json } of pkgs) {
    if (!json.name.startsWith("@aroha-sdk/") && json.name !== "create-aroha-agent") continue;
    const entries = {};
    if (json.exports && typeof json.exports === "object" && !Array.isArray(json.exports)) {
      const keys = Object.keys(json.exports);
      if (keys.every((k) => k.startsWith("."))) {
        for (const k of keys) entries[k] = declFor(dir, json.exports[k]);
      } else {
        entries["."] = declFor(dir, json.exports);
      }
    } else if (typeof json.exports === "string") {
      entries["."] = declFor(dir, json.exports);
    }
    if (!entries["."]) {
      const t = json.types ?? json.typings ?? json.main;
      if (t) entries["."] = declFor(dir, t);
    }
    for (const [sub, dts] of Object.entries(entries)) {
      if (!dts || sub.includes("*") || sub.endsWith(".json")) continue;
      const spec = sub === "." ? json.name : `${json.name}/${sub.replace(/^\.\//, "")}`;
      if (!existsSync(dts)) {
        missingBuild.push(`${spec} → ${relative(ROOT, dts)}`);
        continue;
      }
      paths[spec] = [dts];
    }
  }
  return { paths, missingBuild };
}

// ─── README blocks ───────────────────────────────────────────────────────────

function extractBlocks(text) {
  const lines = text.split(/\r?\n/);
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    if (!FENCE_RE.test(lines[i])) continue;
    const startLine = i + 2; // 1-based line of the block's first code line
    const skip = i > 0 && lines[i - 1].trim() === SKIP_MARKER;
    const body = [];
    i++;
    while (i < lines.length && !/^```\s*$/.test(lines[i])) body.push(lines[i++]);
    blocks.push({ startLine, code: body.join("\n"), skip });
  }
  return blocks;
}

function readmes(pkgs) {
  const list = [join(ROOT, "README.md")];
  for (const { dir } of pkgs) {
    if (!dir.startsWith(join(ROOT, "packages"))) continue;
    const p = join(dir, "README.md");
    if (existsSync(p)) list.push(p);
  }
  return list;
}

// ─── Compile loop ────────────────────────────────────────────────────────────

function preludeFor(names) {
  return [...names].sort().map((n) => `declare const ${n}: any; type ${n} = any;`).join(" ");
}

function writeUnit(unit) {
  const prelude = preludeFor(unit.freeNames);
  // Prelude goes on ONE line so README line = file line - 1 + startLine - 1.
  writeFileSync(unit.file, `${prelude}\n${unit.code}\nexport {};\n`);
}

const { paths, missingBuild } = buildPaths(workspacePackages());
if (Object.keys(paths).length === 0) {
  console.error("No built @aroha-sdk declarations found — run `npm run build` first.");
  process.exit(2);
}
if (missingBuild.length > 0) {
  // Not fatal: packages outside scripts/build-ordered.mjs are not built by
  // `npm run build`. A README that imports one fails below with
  // "Cannot find module", which is the accurate signal.
  console.log(`note: no built declarations for ${missingBuild.length} entry point(s): ${missingBuild.join("; ")}\n`);
}

rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });

const units = [];
const skipped = [];
let n = 0;
for (const readme of readmes(workspacePackages())) {
  const rel = relative(ROOT, readme).replace(/\\/g, "/");
  for (const b of extractBlocks(readFileSync(readme, "utf8"))) {
    if (b.skip) { skipped.push(`${rel}:${b.startLine}`); continue; }
    const file = join(WORK, `block-${String(++n).padStart(3, "0")}.ts`);
    units.push({ readme: rel, startLine: b.startLine, code: b.code, file, freeNames: new Set() });
  }
}

const shimFile = join(WORK, "shims.d.ts");
const shimmed = new Set();
const writeShims = () =>
  writeFileSync(shimFile, [...shimmed].sort().map((m) => `declare module "${m}";`).join("\n") + "\n");

const compilerOptions = {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  lib: ["lib.es2022.d.ts"],
  types: ["node"],
  typeRoots: [join(ROOT, "node_modules", "@types")],
  strict: true,
  noImplicitAny: false,
  noEmit: true,
  skipLibCheck: true,
  esModuleInterop: true,
  allowSyntheticDefaultImports: true,
  isolatedModules: false,
  baseUrl: ROOT,
  paths,
};

let diagnostics = [];
for (let round = 1; round <= MAX_ROUNDS; round++) {
  for (const u of units) writeUnit(u);
  writeShims();
  const program = ts.createProgram([...units.map((u) => u.file), shimFile], compilerOptions);
  diagnostics = ts.getPreEmitDiagnostics(program).filter((d) => d.file && d.file.fileName.includes(".readme-check"));

  let changed = false;
  for (const d of diagnostics) {
    const msg = ts.flattenDiagnosticMessageText(d.messageText, "\n");
    const unit = units.find((u) => resolve(u.file) === resolve(d.file.fileName));
    if (!unit) continue;
    if (MISSING_NAME_CODES.has(d.code)) {
      const m = /(?:name|property) '([A-Za-z_$][\w$]*)'/.exec(msg);
      if (m && !unit.freeNames.has(m[1])) { unit.freeNames.add(m[1]); changed = true; }
    } else if (MISSING_MODULE_CODES.has(d.code)) {
      const m = /module '([^']+)'/.exec(msg);
      if (m && !m[1].startsWith("@aroha-sdk/") && !m[1].startsWith(".") && !shimmed.has(m[1])) {
        shimmed.add(m[1]); changed = true;
      }
    }
  }
  if (!changed) break;
}

// ─── Report ──────────────────────────────────────────────────────────────────

const byUnit = new Map();
for (const d of diagnostics) {
  const unit = units.find((u) => resolve(u.file) === resolve(d.file.fileName));
  if (!unit) continue;
  const { line } = d.file.getLineAndCharacterOfPosition(d.start ?? 0);
  // file line 0 is the prelude; file line k (k ≥ 1) is README line startLine + k - 1
  const readmeLine = line === 0 ? unit.startLine : unit.startLine + line - 1;
  const msg = ts.flattenDiagnosticMessageText(d.messageText, "\n      ");
  if (!byUnit.has(unit.readme)) byUnit.set(unit.readme, []);
  byUnit.get(unit.readme).push(`${unit.readme}:${readmeLine}  TS${d.code}: ${msg}`);
}

const readmeNames = [...new Set(units.map((u) => u.readme))];
let failures = 0;
for (const r of readmeNames) {
  const count = units.filter((u) => u.readme === r).length;
  const errs = byUnit.get(r) ?? [];
  if (errs.length === 0) {
    console.log(`ok    ${r} (${count} block${count === 1 ? "" : "s"})`);
  } else {
    failures += errs.length;
    console.log(`FAIL  ${r}`);
    for (const e of errs) console.log(`      ${e}`);
  }
}
if (skipped.length) console.log(`\nskipped (readme-check: skip): ${skipped.join(", ")}`);
if (shimmed.size) console.log(`third-party modules shimmed as any: ${[...shimmed].sort().join(", ")}`);
console.log(`\n${units.length} blocks in ${readmeNames.length} READMEs type-checked, ${failures} error${failures === 1 ? "" : "s"}.`);

if (!KEEP) rmSync(WORK, { recursive: true, force: true });
process.exit(failures > 0 ? 1 : 0);
