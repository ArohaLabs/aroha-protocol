// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { AROHA_SDK_RANGES, TOOLCHAIN } from "./templates/versions.js";
import { providerTemplate } from "./templates/provider.js";
import { createAppTemplate } from "./templates/create-app.js";
import { orchestratorTemplate } from "./templates/orchestrator.js";
import { bridgePackageJson } from "./templates/bridge.js";
import { a2aConverterTemplate } from "./templates/converters/a2a.js";
import { mcpConverterTemplate } from "./templates/converters/mcp.js";
import { agntcyConverterTemplate } from "./templates/converters/agntcy.js";
import { langchainConverterTemplate } from "./templates/converters/langchain.js";

const PACKAGES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** name → version for every package in this monorepo's packages/ directory. */
function workspaceVersions(): Map<string, string> {
  const out = new Map<string, string>();
  for (const dir of readdirSync(PACKAGES_DIR)) {
    const pj = join(PACKAGES_DIR, dir, "package.json");
    if (!existsSync(pj)) continue;
    const pkg = JSON.parse(readFileSync(pj, "utf8")) as { name: string; version: string };
    out.set(pkg.name, pkg.version);
  }
  return out;
}

/**
 * Packages developed in ArohaLabs/aroha-extensions, not in this repository.
 * They stay published on npm, so templates may depend on them; their ranges
 * are pinned to the last published version instead of a local package.json.
 */
const PUBLISHED_ELSEWHERE: Record<string, string> = {
  "@aroha-sdk/orchestrator": "1.4.0",
};

describe("scaffolded dependency ranges track the workspace", () => {
  const versions = workspaceVersions();
  for (const [name, version] of Object.entries(PUBLISHED_ELSEWHERE)) {
    if (!versions.has(name)) versions.set(name, version);
  }

  for (const [name, range] of Object.entries(AROHA_SDK_RANGES)) {
    it(`${name} is ^<workspace version>`, () => {
      const v = versions.get(name);
      expect(v, `${name} not found under packages/`).toBeDefined();
      expect(range).toBe(`^${v}`);
    });
  }

  it("uses @types/node for Node 22", () => {
    expect(TOOLCHAIN["@types/node"]).toMatch(/^\^22\./);
  });
});

function allPackageJsons(): Array<[string, Record<string, Record<string, string> | undefined>]> {
  const sets: Array<[string, Map<string, string>]> = [
    ["provider", providerTemplate({ name: "p", port: 3001, capabilities: ["search-x", "book-x"] })],
    ["create-app", createAppTemplate({ name: "app" })],
    ["orchestrator", orchestratorTemplate({ name: "o", port: 3000, apiPort: 3010 })],
    ["a2a", a2aConverterTemplate({ name: "a", port: 3000, a2aEndpoint: "http://x" })],
    ["mcp", mcpConverterTemplate({ name: "m", port: 3000, mcpEndpoint: "http://x" })],
    ["agntcy", agntcyConverterTemplate({ name: "g", port: 3000, agntcyEndpoint: "http://x" })],
    ["langchain", langchainConverterTemplate({ name: "l", port: 3000, language: "typescript" })],
  ];
  const out: Array<[string, Record<string, Record<string, string> | undefined>]> = [];
  for (const [label, files] of sets) {
    for (const [path, content] of files) {
      if (path.endsWith("package.json")) out.push([`${label}:${path}`, JSON.parse(content)]);
    }
  }
  out.push(["bridge:package.json", JSON.parse(bridgePackageJson("acme", "Acme"))]);
  return out;
}

describe("generated package.json files", () => {
  for (const [label, pkg] of allPackageJsons()) {
    it(`${label} uses current @aroha-sdk ranges, no ts-node, @types/node ^22`, () => {
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      for (const [dep, range] of Object.entries(deps)) {
        if (dep.startsWith("@aroha-sdk/") && dep in AROHA_SDK_RANGES) {
          expect(range).toBe(AROHA_SDK_RANGES[dep as keyof typeof AROHA_SDK_RANGES]);
        }
      }
      expect(deps["ts-node"]).toBeUndefined();
      if (deps["@types/node"]) expect(deps["@types/node"]).toBe(TOOLCHAIN["@types/node"]);
      const scripts = (pkg.scripts ?? {}) as Record<string, string>;
      expect(Object.values(scripts).join(" ")).not.toContain("ts-node");
    });
  }
});

describe("provider template", () => {
  const files = providerTemplate({ name: "flight", port: 3001, capabilities: ["search-flights", "book-flight"] });

  it("persists the private key instead of generating a new DID every run", () => {
    const server = files.get("src/server.ts")!;
    const identity = files.get("src/identity.ts")!;
    expect(server).not.toContain("generateDID(");
    expect(server).toContain("loadOrCreateIdentity(");
    expect(identity).toContain("AROHA_PRIVATE_KEY");
    expect(identity).toContain("saveKeyToEnvFile");
    expect(files.get(".gitignore")).toContain(".env");
  });

  it("gates on the full mandate chain to a configured root, bound to the sender DID", () => {
    const mandate = files.get("src/mandate.ts")!;
    expect(mandate).toContain("verifyMandateChain(token, resolveContentAddressedKey, {");
    expect(mandate).toContain("expectedRoot: ROOT_DID");
    expect(mandate).toContain("expectedGrantee: envelope.from");
    expect(mandate).toContain("result.chainVerified !== true");
    expect(mandate).toContain("AROHA_MANDATE_ROOT_DID");
    // Must not gate money on a single-key leaf check.
    expect(mandate).not.toMatch(/\bverifyMandate\(/);
    expect(files.get(".env.example")).toContain("AROHA_MANDATE_ROOT_DID=");
    expect(files.get("src/server.ts")).toContain("mandateMiddleware");
  });

  it("does not use the nonexistent rbacPolicy option or DIDIdentity type", () => {
    expect(files.get("src/server.ts")).not.toContain("rbacPolicy");
    expect(files.get("src/manifest.ts")).not.toContain("DIDIdentity");
  });
});

describe("generated ArohaServer setup", () => {
  it("never uses the nonexistent rbacPolicy option or ArohaErrorCode.UpstreamError", () => {
    const all = [
      providerTemplate({ name: "p", port: 1, capabilities: ["x"] }),
      orchestratorTemplate({ name: "o", port: 1, apiPort: 2 }),
      a2aConverterTemplate({ name: "a", port: 1, a2aEndpoint: "http://x" }),
      mcpConverterTemplate({ name: "m", port: 1, mcpEndpoint: "http://x" }),
      agntcyConverterTemplate({ name: "g", port: 1, agntcyEndpoint: "http://x" }),
      langchainConverterTemplate({ name: "l", port: 1, language: "typescript" }),
    ];
    for (const files of all) {
      for (const [path, content] of files) {
        expect(content, path).not.toContain("rbacPolicy");
        expect(content, path).not.toContain("UpstreamError");
      }
    }
  });
});

describe("create-app orchestrator", () => {
  it("reuses a persisted identity", () => {
    const files = createAppTemplate({ name: "app" });
    expect(files.get("orchestrator/src/index.ts")).toContain("loadOrCreateIdentity(");
    expect(files.has("orchestrator/src/identity.ts")).toBe(true);
    expect(files.get(".env.example")).toContain("AROHA_PRIVATE_KEY");
  });
});

describe("template security defaults (T3/P5)", () => {
  it("create-app enables devMode only when NODE_ENV is exactly 'development'", () => {
    const all = [...createAppTemplate({ name: "demo" }).values()].join("\n");
    expect(all).not.toContain('NODE_ENV !== "production"');
    expect(all).toContain('NODE_ENV === "development"');
  });

  it("no generated file bakes in a live Aroha hostname", () => {
    const outputs = [
      ...createAppTemplate({ name: "demo" }).values(),
      ...orchestratorTemplate({ name: "demo", port: 4000, apiPort: 4001 }).values(),
      ...providerTemplate({ name: "demo", port: 4002, capabilities: ["x"] }).values(),
    ].join("\n");
    expect(outputs).not.toMatch(/registry\.aroha-labs\.com|ipfs\.aroha-labs\.com|workers\.dev/);
  });
});
