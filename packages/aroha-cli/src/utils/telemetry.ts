// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Operator-configured, opt-in CLI telemetry. Off and destination-less by default.
 *
 * ── There is no built-in endpoint ──────────────────────────────────────────
 *
 * This used to POST to telemetry.aroha.dev, a domain the project does not
 * own. Whoever held that domain would have received every opted-in user's
 * command stream, under a privacy promise nobody here could keep. So the CLI
 * ships with NO destination: nothing is sent unless an operator points it at
 * an endpoint they control with AROHA_TELEMETRY_ENDPOINT (https only), and
 * the machine is opted in (`aroha telemetry on`, or AROHA_TELEMETRY=1).
 *
 * There is no startup prompt: asking people to opt in to collection that,
 * by default, goes nowhere would be its own small dishonesty. An operator who
 * configures an endpoint opts their machines in explicitly.
 *
 * What is sent when enabled: the command name, `--flag` names (no values),
 * the Node.js version and a random per-machine session ID. Never agent
 * names, DIDs, keys, file paths or project names. What the endpoint does with
 * the request (IP logging, retention) is up to whoever runs it.
 *
 * Opt out: `aroha telemetry off`, or AROHA_TELEMETRY=0.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";

const CONFIG_DIR  = join(homedir(), ".aroha");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
/**
 * Where events go — only ever an operator-configured https URL, or nowhere.
 * Read per call so a test or a shell can set it without a reload.
 */
export function telemetryEndpoint(): string | null {
  const raw = process.env.AROHA_TELEMETRY_ENDPOINT?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    // Plain http would put the command stream on the wire in clear.
    return url.protocol === "https:" ? url.toString() : null;
  } catch {
    return null;
  }
}

interface ArohaConfig {
  telemetry?: "enabled" | "disabled";
  sessionId?: string;
  promptedAt?: string;
}

function readConfig(): ArohaConfig {
  if (!existsSync(CONFIG_FILE)) return {};
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, "utf8")) as ArohaConfig;
  } catch {
    return {};
  }
}

function writeConfig(config: ArohaConfig): void {
  try {
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  } catch {
    // Non-fatal — telemetry config write failure should never break the CLI
  }
}

/** Returns true if telemetry is opted in. */
export function isTelemetryEnabled(): boolean {
  if (telemetryEndpoint() === null) return false;
  if (process.env.AROHA_TELEMETRY === "0") return false;
  if (process.env.AROHA_TELEMETRY === "1") return true;
  const config = readConfig();
  return config.telemetry === "enabled";
}

/** Human-readable state, for `aroha telemetry` / `aroha telemetry status`. */
export function telemetryStatus(): string {
  const endpoint = telemetryEndpoint();
  if (endpoint === null) {
    return (
      "Telemetry: off. This CLI ships with no collection endpoint and sends nothing.\n" +
      "It can only be enabled by setting AROHA_TELEMETRY_ENDPOINT to an https URL you control."
    );
  }
  return isTelemetryEnabled()
    ? `Telemetry: on, sending to ${endpoint} (command names, flag names, Node version).`
    : `Telemetry: off (endpoint configured: ${endpoint}). Run "aroha telemetry on" to opt in.`;
}

/** Enable or disable telemetry explicitly. */
export function setTelemetry(enabled: boolean): void {
  if (enabled && telemetryEndpoint() === null) {
    console.log(
      "\x1b[2mTelemetry has no destination: this CLI ships without a collection endpoint.\n" +
      "Set AROHA_TELEMETRY_ENDPOINT to an https URL you control to enable it.\x1b[0m",
    );
    return;
  }
  const config = readConfig();
  writeConfig({
    ...config,
    telemetry: enabled ? "enabled" : "disabled",
    sessionId: enabled ? (config.sessionId ?? randomUUID()) : undefined,
  });
  console.log(enabled ? "\x1b[32m✓ Telemetry enabled.\x1b[0m" : "\x1b[2mTelemetry disabled.\x1b[0m");
}

/** Fire-and-forget telemetry event. Never throws, never blocks. */
export function track(command: string, flags: string[] = []): void {
  const endpoint = telemetryEndpoint();
  if (endpoint === null || !isTelemetryEnabled()) return;

  const config = readConfig();
  const payload = {
    event: "cli_command",
    command,
    flags: flags.filter((f) => f.startsWith("--")).map((f) => f.split("=")[0]),
    nodeVersion: process.versions.node,
    sessionId: config.sessionId,
  };

  // Best-effort POST — ignore all errors
  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(3000),
  }).catch(() => {});
}
