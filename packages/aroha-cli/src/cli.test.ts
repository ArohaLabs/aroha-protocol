// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { a2aConverterTemplate } from "./templates/converters/a2a.js";
import { mcpConverterTemplate } from "./templates/converters/mcp.js";

// ─── A2A converter template ───────────────────────────────────────────────────

describe("a2aConverterTemplate", () => {
  it("returns a map with the expected files", () => {
    const files = a2aConverterTemplate({
      name: "my-agent",
      port: 3000,
      a2aEndpoint: "http://localhost:8080",
    });

    expect(files.has("package.json")).toBe(true);
    expect(files.has("tsconfig.json")).toBe(true);
    expect(files.has("src/server.ts")).toBe(true);
    expect(files.has("src/a2a-adapter.ts")).toBe(true);
    expect(files.has("MIGRATION.md")).toBe(true);
  });

  it("embeds the agent name in package.json", () => {
    const files = a2aConverterTemplate({ name: "flight-agent", port: 4000, a2aEndpoint: "http://a2a.local" });
    const pkg = JSON.parse(files.get("package.json")!);
    expect(pkg.name).toBe("flight-agent");
    expect(pkg.dependencies["@aroha-sdk/core"]).toBeTruthy();
    expect(pkg.dependencies["@aroha-sdk/a2a-bridge"]).toBeTruthy();
  });

  it("embeds the port in server.ts", () => {
    const files = a2aConverterTemplate({ name: "test", port: 5001, a2aEndpoint: "http://upstream" });
    const server = files.get("src/server.ts")!;
    expect(server).toContain("5001");
  });

  it("embeds the a2a endpoint in adapter.ts", () => {
    const files = a2aConverterTemplate({ name: "test", port: 3000, a2aEndpoint: "http://my-a2a-agent:9000" });
    const adapter = files.get("src/a2a-adapter.ts")!;
    expect(adapter).toContain("http://my-a2a-agent:9000");
  });

  it("MIGRATION.md references the agent name", () => {
    const files = a2aConverterTemplate({ name: "booking-bridge", port: 3000, a2aEndpoint: "http://upstream" });
    const md = files.get("MIGRATION.md")!;
    expect(md).toContain("booking-bridge");
  });
});

// ─── MCP converter template ───────────────────────────────────────────────────

describe("mcpConverterTemplate", () => {
  it("returns a map with the expected files", () => {
    const files = mcpConverterTemplate({
      name: "mcp-agent",
      port: 3001,
      mcpEndpoint: "http://localhost:8081",
    });

    expect(files.has("package.json")).toBe(true);
    expect(files.has("src/server.ts")).toBe(true);
    expect(files.has("src/mcp-adapter.ts")).toBe(true);
  });

  it("includes @aroha-sdk/mcp-bridge as a dependency", () => {
    const files = mcpConverterTemplate({ name: "mcp-agent", port: 3001, mcpEndpoint: "http://localhost:8081" });
    const pkg = JSON.parse(files.get("package.json")!);
    expect(pkg.dependencies["@aroha-sdk/mcp-bridge"]).toBeTruthy();
  });

  it("embeds the MCP endpoint in the adapter", () => {
    const files = mcpConverterTemplate({ name: "test", port: 3001, mcpEndpoint: "http://my-mcp-server:8080" });
    const adapter = files.get("src/mcp-adapter.ts")!;
    expect(adapter).toContain("http://my-mcp-server:8080");
  });
});
