// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { telemetryEndpoint, isTelemetryEnabled, telemetryStatus, track } from "./telemetry.js";

describe("telemetry has no built-in destination", () => {
  const saved = { ...process.env };
  beforeEach(() => {
    delete process.env.AROHA_TELEMETRY_ENDPOINT;
    process.env.AROHA_TELEMETRY = "1";
  });
  afterEach(() => {
    process.env = { ...saved };
    vi.restoreAllMocks();
  });

  it("is off, and sends nothing, when no endpoint is configured — even if opted in", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null));
    expect(telemetryEndpoint()).toBe(null);
    expect(isTelemetryEnabled()).toBe(false);
    track("init");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a non-https endpoint", () => {
    process.env.AROHA_TELEMETRY_ENDPOINT = "http://collector.example.com/v1";
    expect(telemetryEndpoint()).toBe(null);
  });

  it("sends only to the operator's https endpoint", () => {
    process.env.AROHA_TELEMETRY_ENDPOINT = "https://collector.example.com/v1";
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null));
    track("doctor");
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(String(fetchSpy.mock.calls[0][0])).toBe("https://collector.example.com/v1");
  });

  it("status explains that nothing is sent without an endpoint", () => {
    expect(telemetryStatus()).toMatch(/no collection endpoint and sends nothing/);
    process.env.AROHA_TELEMETRY_ENDPOINT = "https://collector.example.com/v1";
    expect(telemetryStatus()).toMatch(/^Telemetry: on, sending to https:\/\/collector\.example\.com\/v1/);
  });

  it("the CLI never prompts for telemetry at startup", () => {
    const telemetrySrc = readFileSync(fileURLToPath(new URL("./telemetry.ts", import.meta.url)), "utf8");
    const cliSrc = readFileSync(fileURLToPath(new URL("../cli.ts", import.meta.url)), "utf8");
    expect(telemetrySrc).not.toContain("promptTelemetryIfNeeded");
    expect(telemetrySrc).not.toContain("node:readline");
    expect(cliSrc).not.toContain("promptTelemetryIfNeeded");
  });
});
