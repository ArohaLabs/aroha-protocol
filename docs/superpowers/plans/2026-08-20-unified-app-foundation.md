<!-- Copyright (c) 2026 Aroha Labs
     SPDX-License-Identifier: Apache-2.0 -->

# Unified App — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the guardrails and the provider seam that the UI port depends on, changing no user-visible behaviour.

**Architecture:** Three independent pieces. A headless screen harness that drives the compiled runtime through Chrome DevTools Protocol, so a broken screen fails a test instead of white-screening a customer. A `KnowledgeProvider` interface with today's `KnowledgeStore` behind it, so a second implementation can be added later without touching call sites. An offline Ed25519 licence reader, which decides which provider is selected.

**Tech Stack:** TypeScript, Bun (compiled binary), Vitest, `ws` + Chrome DevTools Protocol, `@aroha-sdk/core` Ed25519 primitives.

**Spec:** `docs/superpowers/specs/2026-08-20-unified-desktop-app-design.md`

## Global Constraints

- No UI module may exceed **800 lines**. Spec §4.1.
- The entire UI is **one parse unit**: a syntax error anywhere blanks all of it. Spec §4.2.
- Guardrails are built and passing against the **current** screens before any porting begins. Spec §4.3.
- The base install ships **no Python**. Spec §3.
- Provider selection must never present degraded retrieval as normal. Spec §5.3 case 4.
- The licence gates the add-on **only**, and is not claimed to be a control over anything else. Spec §6.
- Run tests from `apps/aroha-runtime` with `npx vitest run <path>`.
- Commit messages: imperative mood, explain *why*, no attribution line beyond the existing `Co-Authored-By` convention.

---

## File Structure

| File | Responsibility |
|---|---|
| `apps/aroha-runtime/test/harness/browser.ts` | Start headless Chrome, attach CDP, evaluate expressions, screenshot. No knowledge of Aroha. |
| `apps/aroha-runtime/test/harness/runtime.ts` | Start the compiled binary on a temp workspace, parse its `--json` handshake, stop it. |
| `apps/aroha-runtime/test/harness/index.ts` | Compose the two into `withApp()`, the single entry point tests use. |
| `apps/aroha-runtime/src/ui/screens.test.ts` | Landmark assertions for every screen, driven through `withApp()`. |
| `apps/aroha-runtime/src/ui/modules.test.ts` | Every UI module emits parseable JavaScript, individually. |
| `apps/aroha-runtime/src/host/provider.ts` | `KnowledgeProvider`, `RetrievalHit`, `ProviderStatus`, `BuiltinProvider`. |
| `apps/aroha-runtime/src/host/provider.test.ts` | The contract suite. Later run against `AddonProvider` unchanged. |
| `apps/aroha-runtime/src/host/licence.ts` | `readLicence()`, `verifyLicence()`, `Licence`. |
| `apps/aroha-runtime/src/host/licence.test.ts` | Signature, expiry, tamper, absence. |

Modified: `src/host/runtime.ts` (return providers), `src/host/handler.ts` (consume the interface), `src/gateway/server.ts` (knowledge routes via the provider).

---

## Task 1: Browser harness

**Files:**
- Create: `apps/aroha-runtime/test/harness/browser.ts`
- Test: exercised by Task 3; no test of its own (it is test infrastructure)

**Interfaces:**
- Produces: `launchBrowser(): Promise<Browser>` where `Browser = { evaluate<T>(expr: string): Promise<T>; screenshot(path: string): Promise<void>; navigate(url: string): Promise<void>; consoleErrors(): string[]; close(): Promise<void> }`

- [ ] **Step 1: Add the dev dependency**

```bash
cd apps/aroha-runtime
npm install --save-dev ws @types/ws
```

- [ ] **Step 2: Write the harness**

Create `test/harness/browser.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Headless Chrome over the DevTools Protocol.
//
// The runtime's UI had no browser harness at all — page.test.ts says so in its
// own header — so every UI test asserted what the HTML CONTAINED, never what it
// did when loaded. That gap is why a single unescaped newline could blank the
// entire interface and no test noticed.
//
// Deliberately knows nothing about Aroha: it starts a browser, evaluates
// expressions, and reports errors. Composing it with a runtime is index.ts's job.

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";

/** Where Chrome lives, per platform. First hit wins. */
const CANDIDATES = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].filter((p): p is string => Boolean(p));

export interface Browser {
  navigate(url: string): Promise<void>;
  evaluate<T>(expression: string): Promise<T>;
  screenshot(path: string): Promise<void>;
  consoleErrors(): string[];
  close(): Promise<void>;
}

function chromePath(): string {
  const { existsSync } = require("node:fs") as typeof import("node:fs");
  const found = CANDIDATES.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      `No Chrome found. Set CHROME_PATH, or install Chrome. Looked in:\n  ${CANDIDATES.join("\n  ")}`,
    );
  }
  return found;
}

export async function launchBrowser(): Promise<Browser> {
  const profile = mkdtempSync(join(tmpdir(), "aroha-cdp-"));
  // Port 0 is not supported by --remote-debugging-port in a way we can read
  // back reliably, so a port is chosen and the DevTools endpoint polled.
  const port = 9500 + Math.floor(Math.random() * 400);
  const child = spawn(
    chromePath(),
    [
      "--headless=new",
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  const target = await waitForTarget(port);
  const ws = new WebSocket(target, { maxPayload: 64 * 1024 * 1024 });
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => resolve());
    ws.once("error", reject);
  });

  let id = 0;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  const errors: string[] = [];

  ws.on("message", (raw: Buffer) => {
    const msg = JSON.parse(raw.toString()) as {
      id?: number; error?: unknown; result?: unknown; method?: string; params?: unknown;
    };
    if (msg.id !== undefined && pending.has(msg.id)) {
      const p = pending.get(msg.id)!;
      pending.delete(msg.id);
      msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
    if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params as { exceptionDetails?: { exception?: { description?: string } } };
      errors.push(d.exceptionDetails?.exception?.description ?? "unknown exception");
    }
  });

  const send = (method: string, params: Record<string, unknown> = {}) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      const n = ++id;
      pending.set(n, { resolve: resolve as (v: unknown) => void, reject });
      ws.send(JSON.stringify({ id: n, method, params }));
    });

  await send("Page.enable");
  await send("Runtime.enable");
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1280, height: 900, deviceScaleFactor: 1, mobile: false,
  });

  return {
    async navigate(url) {
      await send("Page.navigate", { url });
      // The UI boots, fetches agents, and renders. Polling for readiness is
      // done by the caller via waitFor(); this only covers document load.
      await new Promise((r) => setTimeout(r, 1200));
    },
    async evaluate<T>(expression: string): Promise<T> {
      const res = (await send("Runtime.evaluate", {
        expression, awaitPromise: true, returnByValue: true,
      })) as { exceptionDetails?: { exception?: { description?: string } }; result?: { value?: T } };
      if (res.exceptionDetails) {
        throw new Error(res.exceptionDetails.exception?.description ?? "evaluate failed");
      }
      return res.result?.value as T;
    },
    async screenshot(path) {
      const { data } = (await send("Page.captureScreenshot", { format: "png" })) as { data: string };
      writeFileSync(path, Buffer.from(data, "base64"));
    },
    consoleErrors: () => [...errors],
    async close() {
      ws.close();
      child.kill();
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

/** Poll the DevTools endpoint until a page target appears. */
async function waitForTarget(port: number): Promise<string> {
  const deadline = Date.now() + 30_000;
  let lastError = "";
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`);
      const targets = (await res.json()) as Array<{ type: string; webSocketDebuggerUrl: string }>;
      const page = targets.find((t) => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Chrome DevTools did not come up on ${port}. Last error: ${lastError}`);
}
```

- [ ] **Step 3: Verify it compiles**

Run: `npx tsc --noEmit`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add apps/aroha-runtime/test/harness/browser.ts apps/aroha-runtime/package.json package-lock.json
git commit -m "test(runtime): a headless browser harness, which did not exist

page.test.ts states in its own header that this project has no browser or DOM
harness, so every UI test asserted what the HTML contained rather than what it
did when loaded. That is the gap a single unescaped newline walked through
yesterday to blank the entire interface.

Knows nothing about Aroha on purpose: start a browser, evaluate expressions,
report uncaught errors. Composing it with a running runtime comes next."
```

---

## Task 2: Runtime harness

**Files:**
- Create: `apps/aroha-runtime/test/harness/runtime.ts`

**Interfaces:**
- Produces: `startRuntime(): Promise<RuntimeHandle>` where `RuntimeHandle = { url: string; token: string; port: number; home: string; stop(): Promise<void> }`

- [ ] **Step 1: Write it**

Create `test/harness/runtime.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Start the COMPILED runtime on a throwaway workspace.
//
// Compiled, not `bun run src/cli.ts`, because the two have already diverged
// once: a dependency that resolved fine under Node failed inside the compiled
// binary, and only running the real artifact surfaced it. A UI harness that
// tests something customers never run would repeat that mistake.

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export interface RuntimeHandle {
  url: string;
  token: string;
  port: number;
  home: string;
  stop(): Promise<void>;
}

/** The compiled binary for this platform, as scripts/compile.mjs names them. */
function binaryPath(): string {
  const root = resolve(__dirname, "..", "..");
  const name =
    process.platform === "win32" ? "aroha-windows-x64.exe"
    : process.platform === "darwin" ? (process.arch === "arm64" ? "aroha-darwin-arm64" : "aroha-darwin-x64")
    : (process.arch === "arm64" ? "aroha-linux-arm64" : "aroha-linux-x64");
  const path = join(root, "dist", "bin", name);
  if (!existsSync(path)) {
    throw new Error(
      `Compiled runtime not found at ${path}.\n` +
      `Build it first:  cd apps/aroha-runtime && node scripts/compile.mjs`,
    );
  }
  return path;
}

export async function startRuntime(): Promise<RuntimeHandle> {
  const home = mkdtempSync(join(tmpdir(), "aroha-harness-"));
  const child: ChildProcess = spawn(
    binaryPath(),
    ["up", "--port", "0", "--json"],
    { env: { ...process.env, AROHA_HOME: home }, stdio: ["ignore", "pipe", "pipe"] },
  );

  // The --json contract: exactly one line of JSON on stdout once listening.
  const handshake = await new Promise<{ url: string; token: string; port: number }>((res, rej) => {
    const timer = setTimeout(() => rej(new Error("runtime did not report a handshake within 60s")), 60_000);
    let buffered = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      buffered += chunk.toString();
      const line = buffered.split("\n").find((l) => l.trim().startsWith("{"));
      if (line) {
        clearTimeout(timer);
        res(JSON.parse(line) as { url: string; token: string; port: number });
      }
    });
    child.on("error", rej);
    child.on("exit", (code) => rej(new Error(`runtime exited early with code ${code}`)));
  });

  return {
    ...handshake,
    home,
    async stop() {
      child.kill();
      // The workspace holds a lock file the next test would trip over.
      await new Promise((r) => setTimeout(r, 300));
      rmSync(home, { recursive: true, force: true });
    },
  };
}
```

- [ ] **Step 2: Verify the port-0 assumption**

The harness passes `--port 0`. Confirm the runtime accepts it and reports the real port:

Run: `node scripts/compile.mjs && AROHA_HOME=$(mktemp -d) ./dist/bin/aroha-windows-x64.exe up --port 0 --json | head -1`
Expected: one line of JSON whose `port` is a real, non-zero port.

If it rejects `0`, change `binaryPath`'s caller to pick a random port in 20000–30000 instead, and note why in a comment.

- [ ] **Step 3: Verify it compiles**

Run: `npx tsc --noEmit`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add apps/aroha-runtime/test/harness/runtime.ts
git commit -m "test(runtime): start the compiled binary for tests, not the source

Compiled rather than 'bun run src/cli.ts' because the two have diverged before:
a dependency that resolved under Node failed inside the compiled binary, and
only running the real artifact found it. A harness that exercises something
customers never run would repeat that."
```

---

## Task 3: `withApp()` and the first screen assertions

**Files:**
- Create: `apps/aroha-runtime/test/harness/index.ts`
- Create: `apps/aroha-runtime/src/ui/screens.test.ts`

**Interfaces:**
- Consumes: `launchBrowser()` (Task 1), `startRuntime()` (Task 2)
- Produces: `withApp(fn: (app: App) => Promise<void>): Promise<void>` where `App = Browser & { waitFor(expr: string, timeoutMs?: number): Promise<void> }`

- [ ] **Step 1: Write the composition**

Create `test/harness/index.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { launchBrowser, type Browser } from "./browser.js";
import { startRuntime } from "./runtime.js";

export interface App extends Browser {
  /** Poll until `expression` evaluates truthy, or fail with what it last saw. */
  waitFor(expression: string, timeoutMs?: number): Promise<void>;
}

/**
 * Run `fn` against a live app: a compiled runtime on a throwaway workspace,
 * loaded in a real browser.
 *
 * Both are torn down even when the body throws — a leaked Chrome or a held
 * workspace lock makes every later test in the file fail for the wrong reason.
 */
export async function withApp(fn: (app: App) => Promise<void>): Promise<void> {
  const runtime = await startRuntime();
  const browser = await launchBrowser();
  try {
    await browser.navigate(runtime.url);
    const app: App = {
      ...browser,
      async waitFor(expression, timeoutMs = 15_000) {
        const deadline = Date.now() + timeoutMs;
        let last: unknown = undefined;
        while (Date.now() < deadline) {
          last = await browser.evaluate(`(() => { try { return ${expression}; } catch { return undefined; } })()`);
          if (last) return;
          await new Promise((r) => setTimeout(r, 200));
        }
        throw new Error(`waitFor timed out after ${timeoutMs}ms: ${expression} (last value: ${JSON.stringify(last)})`);
      },
    };
    await fn(app);
  } finally {
    await browser.close();
    await runtime.stop();
  }
}
```

- [ ] **Step 2: Write the failing screen test**

Create `src/ui/screens.test.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Landmark assertions for every screen, through a real browser against the
// compiled binary.
//
// Written BEFORE the doc-intel port, deliberately. A harness written afterwards
// describes whatever was built; written first, it describes what the product
// already does, and so can tell you when the port breaks it.

import { describe, it, expect } from "vitest";
import { withApp } from "../../test/harness/index.js";

describe("screens — the app loads at all", () => {
  it("renders the shell with its navigation, and throws nothing", async () => {
    await withApp(async (app) => {
      await app.waitFor(`document.querySelectorAll("#nav .nav-item").length > 0`);

      const nav = await app.evaluate<string[]>(`
        [...document.querySelectorAll("#nav .nav-item span")]
          .map(e => e.textContent).filter(t => t && !/^\\d+$/.test(t))
      `);
      expect(nav).toContain("Agents");
      expect(nav).toContain("MCP servers");

      // An uncaught exception blanks the whole UI, so it is a failure here
      // even when the landmarks happen to have rendered before it fired.
      expect(app.consoleErrors()).toEqual([]);
    });
  }, 120_000);

  it("renders the agents screen with at least the default agent", async () => {
    await withApp(async (app) => {
      await app.waitFor(`document.querySelectorAll(".card").length > 0`);
      const names = await app.evaluate<string[]>(
        `[...document.querySelectorAll(".card-name")].map(e => e.textContent)`,
      );
      expect(names.length).toBeGreaterThan(0);
      expect(app.consoleErrors()).toEqual([]);
    });
  }, 120_000);

  it("loads the typeface it was designed for, rather than falling back", async () => {
    await withApp(async (app) => {
      await app.waitFor(`document.fonts && document.fonts.status === "loaded"`);
      const applied = await app.evaluate<boolean>(`document.fonts.check("16px 'Public Sans'")`);
      expect(applied).toBe(true);
    });
  }, 120_000);
});
```

- [ ] **Step 3: Run it — it must fail for the right reason**

Run: `npx vitest run src/ui/screens.test.ts`
Expected: FAIL with "Compiled runtime not found at ... Build it first", because no binary has been built yet.

This is the correct first failure: it proves the harness reaches the binary check rather than silently passing.

- [ ] **Step 4: Build the binary and re-run**

Run: `node scripts/compile.mjs && npx vitest run src/ui/screens.test.ts`
Expected: PASS, 3 tests.

- [ ] **Step 5: Prove the harness can actually fail**

Temporarily break the UI to confirm the harness is not vacuously passing. In `src/ui/page.ts`, find `const nav = document.getElementById("nav");` and change `"nav"` to `"nav-broken"`. Then:

Run: `node scripts/compile.mjs && npx vitest run src/ui/screens.test.ts`
Expected: FAIL — `waitFor timed out`, and/or a console error.

Revert the change, rebuild, and confirm PASS again. Do not commit the broken state.

- [ ] **Step 6: Commit**

```bash
git add apps/aroha-runtime/test/harness/index.ts apps/aroha-runtime/src/ui/screens.test.ts
git commit -m "test(ui): assert every screen renders, in a real browser

The first test of this UI that loads it rather than reading it. Written before
the doc-intel port on purpose: a harness written afterwards describes whatever
was built, while one written first describes what the product already does and
can therefore tell you when the port breaks it.

Mutation-checked by pointing the nav lookup at a missing id and confirming the
suite fails, so it is not passing vacuously."
```

---

## Task 4: Per-module parse tests

**Files:**
- Create: `apps/aroha-runtime/src/ui/modules.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: nothing later tasks import. It is a standing guard.

- [ ] **Step 1: Write the test**

Create `src/ui/modules.test.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Every UI module must emit parseable JavaScript on its own.
//
// page.test.ts already checks the assembled script parses. That catches a
// break but not where it is: the failure arrives as "Unexpected EOF" against
// 3,000 lines with no line number that means anything. Checking each module
// separately turns the same failure into the name of one file.
//
// This matters more as the port lands: the spec caps modules at 800 lines
// (§4.1) precisely so a parse failure names a small place.

import { describe, it, expect } from "vitest";
import { MARKDOWN_PARSER_JS } from "./markdown.js";

/**
 * Modules that contribute executable JavaScript to the page.
 *
 * Ported screens are added here as they land. A module that contributes only
 * CSS (styles.ts) or data (font.ts, templates.ts) is not listed: it has no
 * JavaScript to parse, and asserting otherwise would be theatre.
 */
const JS_MODULES: Array<{ name: string; source: string }> = [
  { name: "markdown.ts", source: MARKDOWN_PARSER_JS },
];

describe("ui modules — each parses independently", () => {
  for (const mod of JS_MODULES) {
    it(`${mod.name} is valid JavaScript`, () => {
      expect(() => new Function(mod.source)).not.toThrow();
    });

    it(`${mod.name} contains no unescaped newline inside a string literal`, () => {
      // The specific failure that blanked the UI on 2026-08-19: the page is a
      // plain template literal, so a single-escaped \n in the SOURCE becomes a
      // real newline in the OUTPUT, terminating whatever string it sat in.
      // A real newline between two quotes on the same line is the signature.
      const lines = mod.source.split("\n");
      for (const [i, line] of lines.entries()) {
        const quotes = (line.match(/(?<!\\)"/g) ?? []).length;
        expect(
          quotes % 2,
          `${mod.name}:${i + 1} has an odd number of unescaped double quotes, ` +
            `which usually means a string literal was split across lines:\n  ${line}`,
        ).toBe(0);
      }
    });
  }
});
```

- [ ] **Step 2: Run it**

Run: `npx vitest run src/ui/modules.test.ts`
Expected: PASS, 2 tests.

- [ ] **Step 3: Prove it catches the real bug**

Append a deliberately broken module to `JS_MODULES` temporarily:

```ts
  { name: "broken-fixture", source: 'const x = "a\nb";' },
```

Run: `npx vitest run src/ui/modules.test.ts`
Expected: FAIL on both assertions for `broken-fixture`.

Remove the fixture and confirm PASS. Do not commit the fixture.

- [ ] **Step 4: Commit**

```bash
git add apps/aroha-runtime/src/ui/modules.test.ts
git commit -m "test(ui): parse each UI module on its own, not just the whole page

page.test.ts checks the assembled script parses, which catches a break but not
where it is — the failure arrives as 'Unexpected EOF' against 3,000 lines. Per
module, the same failure names one file.

Also asserts the specific shape that blanked the UI yesterday: an odd number of
unescaped quotes on a line, which is what a string split across lines looks
like. Verified against a fixture carrying that exact defect."
```

---

## Task 5: `KnowledgeProvider` and `BuiltinProvider`

**Files:**
- Create: `apps/aroha-runtime/src/host/provider.ts`
- Create: `apps/aroha-runtime/src/host/provider.test.ts`

**Interfaces:**
- Consumes: `KnowledgeStore` from `./knowledge.js` — `add(name, text, vectors?, embedModel?)`, `list()`, `search(query, limit, queryVector?)`, `contextFor(query, limit, queryVector?)`, `status()`, `remove(docId)`; `Hit = { docId, docName, text }`.
- Produces: `KnowledgeProvider`, `RetrievalHit`, `ProviderStatus`, `BuiltinProvider`.

- [ ] **Step 1: Write the failing contract test**

Create `src/host/provider.test.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The provider contract, run against BuiltinProvider today and against
// AddonProvider unchanged when it exists.
//
// Running identical assertions against both implementations is what stops the
// free and paid paths drifting into two products with one name (spec §8).

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveWorkspace, ensureWorkspace } from "../workspace/paths.js";
import { KnowledgeStore } from "./knowledge.js";
import { BuiltinProvider, type KnowledgeProvider } from "./provider.js";

let root: string;
let provider: KnowledgeProvider;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "aroha-provider-"));
  const ws = ensureWorkspace(resolveWorkspace(root));
  provider = new BuiltinProvider(new KnowledgeStore(ws, "agent"));
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("KnowledgeProvider contract", () => {
  it("reports which implementation is answering", async () => {
    const status = await provider.status();
    expect(status.kind).toBe("builtin");
  });

  it("starts empty, and says so with zeroes rather than by throwing", async () => {
    const status = await provider.status();
    expect(status.docCount).toBe(0);
    expect(status.chunkCount).toBe(0);
    expect(await provider.list()).toEqual([]);
  });

  it("adds a document and finds it again", async () => {
    await provider.add("Rate card", "Late invoices carry 2% interest. Annual leave is 28 days.");
    const status = await provider.status();
    expect(status.docCount).toBe(1);
    expect(status.chunkCount).toBeGreaterThan(0);

    const hits = await provider.search("interest on late invoices", 4);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].docName).toBe("Rate card");
    expect(hits[0].text).toContain("2%");
  });

  it("returns nothing for a query with no corpus, rather than failing", async () => {
    expect(await provider.search("anything at all", 4)).toEqual([]);
    expect(await provider.contextFor("anything at all", 4)).toBe("");
  });

  it("omits enrichment it cannot provide, rather than inventing it", async () => {
    // page and artifacts belong to the add-on. The built-in provider must
    // leave them undefined — a fabricated page number is worse than none,
    // because the UI would render it as a citation.
    await provider.add("Rate card", "Late invoices carry 2% interest.");
    const [hit] = await provider.search("interest", 1);
    expect(hit.page).toBeUndefined();
    expect(hit.artifacts).toBeUndefined();
  });

  it("removes a document and stops returning it", async () => {
    const doc = await provider.add("Rate card", "Late invoices carry 2% interest.");
    expect(doc).not.toBeNull();
    expect(await provider.remove(doc!.id)).toBe(true);
    expect((await provider.status()).docCount).toBe(0);
    expect(await provider.search("interest", 4)).toEqual([]);
  });

  it("reports a removal that removed nothing as false", async () => {
    expect(await provider.remove("no-such-doc")).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `npx vitest run src/host/provider.test.ts`
Expected: FAIL — `Cannot find module './provider.js'`.

- [ ] **Step 3: Write the implementation**

Create `src/host/provider.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * One interface over retrieval, with two implementations behind it.
 *
 * The free engine (BuiltinProvider, wrapping KnowledgeStore) and the paid one
 * (AddonProvider, added later) differ in what they can find, not in how they
 * are asked. That is what lets one set of document screens serve both tiers —
 * spec §5.2 — instead of the interface forking and the UI forking after it.
 *
 * Async throughout, including where the built-in implementation is synchronous.
 * The add-on answers over HTTP, and an interface that were sync here would have
 * to be rewritten the moment the second implementation arrived.
 */

import type { KnowledgeStore, KnowledgeDoc } from "./knowledge.js";

/**
 * One retrieved passage.
 *
 * The enrichment fields are optional and are ABSENT from the built-in
 * provider, never faked. A page number the engine did not determine would be
 * rendered by the UI as a citation, which would make the free tier lie rather
 * than simply offer less.
 */
export interface RetrievalHit {
  docId: string;
  docName: string;
  text: string;
  /** Add-on only: 1-based source page. */
  page?: number;
  /** Add-on only: figures and tables supporting this passage. */
  artifacts?: Array<{ kind: "figure" | "table"; caption?: string; ref: string }>;
  /** Add-on only: post-rerank score. */
  score?: number;
}

export interface ProviderStatus {
  kind: "builtin" | "addon";
  docCount: number;
  chunkCount: number;
  /** Built-in: dense vectors are contributing. Add-on: always true. */
  hybrid: boolean;
  embedModel?: string;
  /** Add-on only, and only while it is running. */
  addonVersion?: string;
}

export interface KnowledgeProvider {
  add(name: string, text: string): Promise<KnowledgeDoc | null>;
  list(): Promise<KnowledgeDoc[]>;
  search(query: string, limit?: number): Promise<RetrievalHit[]>;
  contextFor(query: string, limit?: number): Promise<string>;
  status(): Promise<ProviderStatus>;
  remove(docId: string): Promise<boolean>;
}

/** How the caller turns a query into a vector, when it can. */
export type EmbedQuery = (text: string) => Promise<number[] | null>;

/**
 * The free engine: today's KnowledgeStore, unchanged, behind the interface.
 *
 * Embedding is injected rather than reached for, because whether an embedding
 * model exists is a property of the install, not of retrieval — and the
 * add-on will not need this hook at all.
 */
export class BuiltinProvider implements KnowledgeProvider {
  constructor(
    private store: KnowledgeStore,
    private embedQuery?: EmbedQuery,
  ) {}

  async add(name: string, text: string): Promise<KnowledgeDoc | null> {
    return this.store.add(name, text);
  }

  async list(): Promise<KnowledgeDoc[]> {
    return this.store.list();
  }

  async search(query: string, limit = 4): Promise<RetrievalHit[]> {
    const vector = await this.vectorFor(query);
    return this.store.search(query, limit, vector).map((h) => ({
      docId: h.docId,
      docName: h.docName,
      text: h.text,
    }));
  }

  async contextFor(query: string, limit = 4): Promise<string> {
    const vector = await this.vectorFor(query);
    return this.store.contextFor(query, limit, vector);
  }

  async status(): Promise<ProviderStatus> {
    const s = this.store.status();
    return {
      kind: "builtin",
      docCount: s.docCount,
      chunkCount: s.chunkCount,
      hybrid: s.hybrid,
      embedModel: s.embedModel,
    };
  }

  async remove(docId: string): Promise<boolean> {
    return this.store.remove(docId);
  }

  /**
   * A vector for the query, or undefined.
   *
   * A failed or absent embedding degrades to lexical retrieval; it must never
   * be why a question goes unanswered.
   */
  private async vectorFor(query: string): Promise<number[] | undefined> {
    if (!this.embedQuery) return undefined;
    try {
      return (await this.embedQuery(query)) ?? undefined;
    } catch {
      return undefined;
    }
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/host/provider.test.ts`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add apps/aroha-runtime/src/host/provider.ts apps/aroha-runtime/src/host/provider.test.ts
git commit -m "feat(runtime): one interface over retrieval, two implementations behind it

The free engine and the paid one will differ in what they can find, not in how
they are asked. That is what lets one set of document screens serve both tiers
rather than the interface forking and the UI forking after it.

Async throughout, including where the built-in path is synchronous: the add-on
answers over HTTP, and a sync interface would need rewriting the moment the
second implementation arrived.

Enrichment fields are absent from the built-in provider rather than faked. A
page number nothing determined would be rendered as a citation, which makes the
free tier lie instead of simply offering less — there is a test for it."
```

---

## Task 6: Route the runtime through the provider

**Files:**
- Modify: `apps/aroha-runtime/src/host/runtime.ts` — `knowledgeFor` (line 96), `describe` (line 157), `mount` (line 196)
- Modify: `apps/aroha-runtime/src/host/handler.ts` — `KnowledgeHooks` (line 53), retrieval block (lines 233–247)
- Modify: `apps/aroha-runtime/src/gateway/server.ts` — knowledge routes (line 292)

**Interfaces:**
- Consumes: `BuiltinProvider`, `KnowledgeProvider`, `RetrievalHit` (Task 5)
- Produces: `AgentRuntime.providerFor(slug): KnowledgeProvider | null`

- [ ] **Step 1: Write the failing test**

Append to `src/host/provider.test.ts`:

```ts
describe("AgentRuntime — provider wiring", () => {
  it("hands out a provider per agent, not a raw store", async () => {
    const { AgentRuntime } = await import("./runtime.js");
    const { AgentStore } = await import("./store.js");
    const ws = ensureWorkspace(resolveWorkspace(root));
    const runtime = new AgentRuntime(new AgentStore(ws), {} as never, undefined, ws);
    await runtime.create({ name: "Advisor", systemPrompt: "x", model: "m" });

    const provider = runtime.providerFor("advisor");
    expect(provider).not.toBeNull();
    expect((await provider!.status()).kind).toBe("builtin");
  });

  it("returns null when there is no workspace to hold documents", async () => {
    const { AgentRuntime } = await import("./runtime.js");
    const { AgentStore } = await import("./store.js");
    const ws = ensureWorkspace(resolveWorkspace(root));
    const runtime = new AgentRuntime(new AgentStore(ws), {} as never);
    expect(runtime.providerFor("nobody")).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/provider.test.ts`
Expected: FAIL — `runtime.providerFor is not a function`.

- [ ] **Step 3: Add `providerFor` to the runtime**

In `src/host/runtime.ts`, add the import and the method next to `knowledgeFor`:

```ts
import { BuiltinProvider, type KnowledgeProvider } from "./provider.js";
```

```ts
  /**
   * This agent's retrieval, behind the interface.
   *
   * knowledgeFor() stays for the routes that manage documents directly — they
   * need KnowledgeStore's own shape. Everything that RETRIEVES goes through
   * here, so the add-on can be swapped in at one place rather than at every
   * call site.
   */
  providerFor(slug: string): KnowledgeProvider | null {
    const store = this.knowledgeFor(slug);
    if (!store) return null;
    return new BuiltinProvider(store, async (text) => {
      const result = await this.embedTexts([text]);
      return result ? result.vectors[0] : null;
    });
  }
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/provider.test.ts`
Expected: PASS, 9 tests.

- [ ] **Step 5: Route the handler through the provider**

In `src/host/handler.ts`, change the `KnowledgeHooks` type to carry a provider instead of a store, and rewrite the retrieval block (lines 233–247):

```ts
import type { KnowledgeProvider } from "./provider.js";

export interface KnowledgeHooks {
  provider: KnowledgeProvider;
}
```

```ts
    // An agent with no documents has nothing to search, and saying so on every
    // turn is noise dressed as transparency.
    if (knowledge) {
      const status = await knowledge.provider.status();
      if (status.chunkCount > 0) {
        const stepId = nextStepId();
        yield { type: "step", id: stepId, kind: "retrieval", label: "Searching knowledge", status: "running" };

        const hits = await knowledge.provider.search(ctx.message, 4);
        systemPrompt += await knowledge.provider.contextFor(ctx.message, 4);

        yield {
          type: "step", id: stepId, kind: "retrieval",
          label: hits.length > 0
            ? `Found ${hits.length} ${hits.length === 1 ? "passage" : "passages"}`
            : "No matching passages",
          detail: hits.length > 0
            ? [...new Set(hits.map((h) => h.docName))].join(", ")
            : undefined,
          status: "done",
        };
      }
    }
```

In `src/host/runtime.ts`'s `mount`, replace the `knowledge` hook object:

```ts
    const knowledge = ws ? { provider: this.providerFor(record.slug)! } : undefined;
```

- [ ] **Step 6: Run the whole suite**

Run: `npx tsc --noEmit && npx vitest run`
Expected: typecheck clean; all tests pass. Fix any call site the compiler names — `gateway/server.ts:292` uses `knowledgeFor` for document management and should keep doing so.

- [ ] **Step 7: Verify behaviour did not change, live**

Run:
```bash
node scripts/compile.mjs
npx vitest run src/ui/screens.test.ts
```
Expected: PASS. The screens harness from Task 3 is the regression net here — retrieval is reachable from the UI, and this task rewrote its path.

- [ ] **Step 8: Commit**

```bash
git add apps/aroha-runtime/src/host apps/aroha-runtime/src/gateway
git commit -m "refactor(runtime): retrieve through the provider, not the store

Everything that RETRIEVES now goes through KnowledgeProvider, so the paid
engine can be swapped in at one place instead of at every call site.
knowledgeFor() stays for the routes that MANAGE documents — they need the
store's own shape, and pretending otherwise would widen the interface to suit
one caller.

No behaviour change: same retrieval, same step events, same context. The screen
harness added earlier is what makes that claim checkable rather than asserted."
```

---

## Task 7: Offline licence verification

**Files:**
- Create: `apps/aroha-runtime/src/host/licence.ts`
- Create: `apps/aroha-runtime/src/host/licence.test.ts`

**Interfaces:**
- Consumes: `signCanonical`, `verifyCanonicalSignature` from `@aroha-sdk/core`.
- Produces: `readLicence(ws)`, `verifyLicence(licence, publicKey)`, `Licence`, `LicenceState`.

- [ ] **Step 1: Write the failing test**

Create `src/host/licence.test.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPair, signCanonical } from "@aroha-sdk/core";
import { resolveWorkspace, ensureWorkspace, type Workspace } from "../workspace/paths.js";
import { readLicence, verifyLicence, type Licence } from "./licence.js";

let root: string;
let ws: Workspace;
let publicKey: Uint8Array;
let privateKey: Uint8Array;

async function issue(overrides: Partial<Licence> = {}): Promise<Licence> {
  const body = {
    customer: "Acme LLP",
    entitlements: ["knowledge.addon"],
    issuedAt: new Date("2026-01-01").toISOString(),
    expiresAt: new Date("2027-01-01").toISOString(),
    ...overrides,
  };
  const signature = await signCanonical(body as unknown as Record<string, unknown>, privateKey);
  return { ...body, signature } as Licence;
}

beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), "aroha-licence-"));
  ws = ensureWorkspace(resolveWorkspace(root));
  const pair = await generateKeyPair();
  publicKey = pair.publicKey;
  privateKey = pair.privateKey;
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("licence", () => {
  it("reads nothing when no licence is installed, without failing", () => {
    expect(readLicence(ws)).toBeNull();
  });

  it("accepts a licence signed by the issuing key", async () => {
    const licence = await issue();
    expect(await verifyLicence(licence, publicKey, new Date("2026-06-01"))).toEqual({
      valid: true, entitlements: ["knowledge.addon"], customer: "Acme LLP",
    });
  });

  it("refuses a licence whose body was edited after signing", async () => {
    const licence = await issue();
    const tampered = { ...licence, entitlements: ["knowledge.addon", "everything"] };
    const result = await verifyLicence(tampered, publicKey, new Date("2026-06-01"));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("refuses a licence signed by some other key", async () => {
    const other = await generateKeyPair();
    const licence = await issue();
    const result = await verifyLicence(licence, other.publicKey, new Date("2026-06-01"));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("refuses an expired licence, and says when it expired", async () => {
    const licence = await issue();
    const result = await verifyLicence(licence, publicKey, new Date("2027-06-01"));
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("treats an unparseable licence file as no licence, not as a crash", () => {
    writeFileSync(join(ws.root, "licence.json"), "{ not json");
    expect(readLicence(ws)).toBeNull();
  });

  it("round-trips through the file it will actually be installed as", async () => {
    const licence = await issue();
    writeFileSync(join(ws.root, "licence.json"), JSON.stringify(licence, null, 2));
    const read = readLicence(ws);
    expect(read).not.toBeNull();
    expect((await verifyLicence(read!, publicKey, new Date("2026-06-01"))).valid).toBe(true);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/licence.test.ts`
Expected: FAIL — `Cannot find module './licence.js'`.

- [ ] **Step 3: Write the implementation**

Create `src/host/licence.ts`:

```ts
// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The licence, read from disk and verified offline.
 *
 * ── What this is, and what it is not ─────────────────────────────────────
 *
 * It gates the retrieval add-on: whether the runtime will start that process
 * and use it. It is NOT a control over anything else, and nothing here
 * pretends otherwise. The base runtime is intended to become open source, at
 * which point any client-side check in it is removable in one commit.
 *
 * The enforcement that actually holds is elsewhere and is physical: the add-on
 * is installed only on entitled machines (spec §9, decision 3). What is not
 * shipped cannot be unlocked. This file records the entitlement and its expiry
 * so the product can behave correctly and say true things about its own state.
 *
 * Verified offline by design. The delivery model is per-laptop installs into
 * enterprises, some air-gapped; a licence that needed to phone home would fail
 * exactly where it is most needed.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { verifyCanonicalSignature } from "@aroha-sdk/core";
import type { Workspace } from "../workspace/paths.js";

export interface Licence {
  customer: string;
  entitlements: string[];
  issuedAt: string;
  expiresAt: string;
  /** Ed25519 over the canonicalised body, excluding this field. */
  signature: string;
}

export type LicenceState =
  | { valid: true; entitlements: string[]; customer: string }
  | { valid: false; reason: string };

/** The entitlement that unlocks the retrieval add-on. */
export const ADDON_ENTITLEMENT = "knowledge.addon";

/**
 * The installed licence, or null.
 *
 * Null covers absent AND unreadable. An unparseable licence is no licence:
 * failing closed costs a customer one support call, while failing open would
 * grant entitlements from a file nothing could read.
 */
export function readLicence(ws: Workspace): Licence | null {
  const path = join(ws.root, "licence.json");
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<Licence>;
    if (
      typeof parsed.customer !== "string" ||
      !Array.isArray(parsed.entitlements) ||
      typeof parsed.issuedAt !== "string" ||
      typeof parsed.expiresAt !== "string" ||
      typeof parsed.signature !== "string"
    ) {
      return null;
    }
    return parsed as Licence;
  } catch {
    return null;
  }
}

/**
 * Is this licence signed by the issuing key, and still in date?
 *
 * `now` is injected so expiry is testable without waiting a year.
 */
export async function verifyLicence(
  licence: Licence,
  issuerPublicKey: Uint8Array,
  now: Date = new Date(),
): Promise<LicenceState> {
  const { signature, ...body } = licence;

  const signed = await verifyCanonicalSignature(
    body as unknown as Record<string, unknown>,
    signature,
    issuerPublicKey,
  );
  if (!signed) {
    return { valid: false, reason: "Licence signature does not verify against the issuing key." };
  }

  const expiresAt = new Date(licence.expiresAt);
  if (Number.isNaN(expiresAt.getTime())) {
    return { valid: false, reason: "Licence expiry date is not a date." };
  }
  if (expiresAt <= now) {
    return { valid: false, reason: `Licence expired on ${expiresAt.toISOString().slice(0, 10)}.` };
  }

  return { valid: true, entitlements: licence.entitlements, customer: licence.customer };
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/licence.test.ts`
Expected: PASS, 7 tests.

- [ ] **Step 5: Run the whole suite**

Run: `npx tsc --noEmit && npx vitest run`
Expected: typecheck clean; all tests pass.

- [ ] **Step 6: Commit**

```bash
git add apps/aroha-runtime/src/host/licence.ts apps/aroha-runtime/src/host/licence.test.ts
git commit -m "feat(runtime): read and verify the licence offline

Gates the retrieval add-on and nothing else, and the module says so rather than
implying broader enforcement it cannot deliver: the base runtime is intended to
be open source, where any client-side check is removable in one commit. The
control that holds is that the add-on is installed only on entitled machines.

Offline by construction. Delivery is per-laptop installs into enterprises, some
air-gapped; a licence that phoned home would fail exactly where it matters.

An unparseable licence is treated as no licence — failing closed costs a support
call, failing open would grant entitlements from a file nothing could read."
```

---

## Task 8: Provider selection, and saying so honestly

**Files:**
- Modify: `apps/aroha-runtime/src/host/runtime.ts` — `providerFor`
- Modify: `apps/aroha-runtime/src/main.ts` — startup reporting
- Test: `apps/aroha-runtime/src/host/provider.test.ts`

**Interfaces:**
- Consumes: `readLicence`, `verifyLicence`, `ADDON_ENTITLEMENT` (Task 7); `BuiltinProvider` (Task 5)
- Produces: `AgentRuntime.retrievalTier(): "builtin" | "addon-entitled"`

- [ ] **Step 1: Write the failing test**

Append to `src/host/provider.test.ts`:

```ts
describe("retrieval tier", () => {
  it("is builtin when no licence is installed", async () => {
    const { AgentRuntime } = await import("./runtime.js");
    const { AgentStore } = await import("./store.js");
    const ws = ensureWorkspace(resolveWorkspace(root));
    const runtime = new AgentRuntime(new AgentStore(ws), {} as never, undefined, ws);
    expect(runtime.retrievalTier()).toBe("builtin");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/host/provider.test.ts`
Expected: FAIL — `runtime.retrievalTier is not a function`.

- [ ] **Step 3: Implement**

In `src/host/runtime.ts`:

```ts
import { readLicence, verifyLicence, ADDON_ENTITLEMENT } from "./licence.js";
```

```ts
  /**
   * Which retrieval tier this install is entitled to.
   *
   * "addon-entitled" means the licence permits the add-on — NOT that it is
   * installed or running. Selecting the AddonProvider is a separate decision
   * made once that process is known healthy, because a paying customer whose
   * add-on is down must get working retrieval and an explanation, never an
   * error page (spec §5.3 case 4).
   */
  retrievalTier(): "builtin" | "addon-entitled" {
    if (!this.workspace) return "builtin";
    const licence = readLicence(this.workspace);
    if (!licence) return "builtin";
    // Verification is async; this accessor is not. The licence is read at
    // startup into this cache by primeLicence(), so the hot path stays sync.
    return this.licenceEntitlements.includes(ADDON_ENTITLEMENT) ? "addon-entitled" : "builtin";
  }

  /** Verify the installed licence once, at startup. */
  async primeLicence(issuerPublicKey: Uint8Array): Promise<void> {
    this.licenceEntitlements = [];
    if (!this.workspace) return;
    const licence = readLicence(this.workspace);
    if (!licence) return;
    const state = await verifyLicence(licence, issuerPublicKey);
    if (state.valid) this.licenceEntitlements = state.entitlements;
    else console.warn(`[licence] not in effect: ${state.reason}`);
  }
```

Add the field alongside the other private state:

```ts
  private licenceEntitlements: string[] = [];
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx vitest run src/host/provider.test.ts`
Expected: PASS, 10 tests.

- [ ] **Step 5: Report the tier at startup**

In `src/main.ts`, after the guard-rules line added previously, add:

```ts
  // Said out loud, because a customer paying for the add-on should be able to
  // see at a glance whether it is in effect — and because silence would make
  // "entitled but not installed" indistinguishable from "working".
  if (runtime.retrievalTier() === "addon-entitled") {
    note("  Retrieval: add-on entitled (not yet installed — using built-in)");
  }
```

- [ ] **Step 6: Verify the whole suite and the live binary**

Run:
```bash
npx tsc --noEmit && npx vitest run
node scripts/compile.mjs && npx vitest run src/ui/screens.test.ts
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add apps/aroha-runtime/src
git commit -m "feat(runtime): decide the retrieval tier from the licence

'addon-entitled' means the licence permits the add-on, not that it is installed
or running — those are separate facts and conflating them is how a customer
ends up staring at an error page because a background process died. Selecting
the add-on provider happens later, once it is known healthy.

Reported at startup, because silence makes 'entitled but not installed'
indistinguishable from 'working', and the difference is what the customer is
paying for."
```

---

## Task 9: Document the harness so it is used

**Files:**
- Modify: `apps/aroha-runtime/README.md`

- [ ] **Step 1: Add the section**

Under Development, add:

```markdown
### UI tests

`src/ui/screens.test.ts` drives the COMPILED binary in a real headless Chrome
and asserts each screen renders. It needs two things:

    node scripts/compile.mjs      # the tests run the artifact, not the source
    # Chrome, found automatically, or set CHROME_PATH

Skipped rather than failed where Chrome is absent, so a contributor without it
still gets a green suite from everything else.

Why the compiled binary: the source and the artifact have diverged before — a
dependency that resolved under Node failed inside `bun build --compile`, and
only running the real thing found it.

`src/ui/modules.test.ts` checks each UI module parses on its own. The whole
interface is one `<script>`, so a syntax error anywhere blanks all of it; per
module, the failure names one file instead of one three-thousand-line string.
```

- [ ] **Step 2: Make the skip real**

In `src/ui/screens.test.ts`, replace `describe(` with a guarded form:

```ts
import { existsSync } from "node:fs";

/** Chrome present? Absent is a skip, not a failure — see README. */
const CHROME = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
].filter((p): p is string => Boolean(p)).some((p) => existsSync(p));

describe.skipIf(!CHROME)("screens — the app loads at all", () => {
```

- [ ] **Step 3: Verify both paths**

Run: `npx vitest run src/ui/screens.test.ts`
Expected: PASS.

Run: `CHROME_PATH=/nonexistent npx vitest run src/ui/screens.test.ts`
Expected: the suite is skipped, and the run is green. (The other candidate paths must also be absent for this to skip on a machine with Chrome installed; on such a machine, confirm the guard by temporarily emptying the `CHROME` array instead.)

- [ ] **Step 4: Commit**

```bash
git add apps/aroha-runtime/README.md apps/aroha-runtime/src/ui/screens.test.ts
git commit -m "docs(runtime): say how to run the UI tests, and skip them cleanly

The screen tests need a compiled binary and a Chrome, and a contributor with
neither should get a green suite from everything else rather than a wall of
failures about their environment. Skipped, not failed — and the README says
what to install to un-skip them."
```

---

## Self-review

**Spec coverage.**

| Spec section | Task |
|---|---|
| §4.1 module pattern, 800-line cap | Constraint; enforced from Plan 2 onward, guarded by Task 4 |
| §4.2 one parse unit | Task 4 |
| §4.3 guardrails before porting | Tasks 1–4, all before any port work |
| §5.1 provider interface | Task 5 |
| §5.3 provider selection | Task 8 (tier); cases 3–4 need `AddonProvider`, Plan 3 |
| §6 licence | Tasks 7, 8 |
| §8 provider contract suite | Task 5 |
| §2.2 runtime already serves the agent family | No task needed — verified during the survey |

Not covered here by design: the screen port (Plan 2), `AddonProvider` and process supervision (Plan 3), desktop packaging (Plan 3), addressing UI (Plan 2, §9.1).

**Placeholder scan.** No TBD, TODO, "handle errors appropriately", or "similar to Task N". Every code step carries the code.

**Type consistency.** `KnowledgeProvider`, `RetrievalHit`, `ProviderStatus`, `BuiltinProvider`, `EmbedQuery`, `Licence`, `LicenceState`, `ADDON_ENTITLEMENT`, `providerFor`, `retrievalTier`, `primeLicence` are used with the same names and shapes throughout. `KnowledgeHooks` changes shape in Task 6 and every consumer named there is updated in the same task.

**One risk called out.** Task 6 rewrites the retrieval path that the whole product depends on. It is placed after Task 3 deliberately, so the screen harness exists to catch a regression rather than being written afterwards to describe one.
