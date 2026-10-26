// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi, beforeAll, afterAll, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateDID } from "@aroha-sdk/core";
import { runDoctor } from "./doctor.js";

const DID = "did:aroha:doctor-test";

// What the stub agent serves at /.well-known/aroha-agent.json; set per test.
let wellKnownBody: unknown = {};
let server: Server;
let endpoint: string;
let dir: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (req.method === "GET" && req.url === "/.well-known/aroha-agent.json") {
      res.end(JSON.stringify(wellKnownBody));
      return;
    }
    res.statusCode = 400;
    res.end(JSON.stringify({ error: "bad request" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  endpoint = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
  dir = mkdtempSync(join(tmpdir(), "aroha-doctor-"));
  writeFileSync(join(dir, ".env"), `AROHA_AGENT_DID=${DID}\nAROHA_PRIVATE_KEY=x\n`);
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => vi.restoreAllMocks());

/** Run `aroha doctor <endpoint>` in a directory whose .env names DID; capture output and exit code. */
async function doctor(): Promise<{ out: string; exitCode: number | undefined }> {
  vi.spyOn(process, "cwd").mockReturnValue(dir);
  const lines: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => { lines.push(args.join(" ")); });
  let exitCode: number | undefined;
  vi.spyOn(process, "exit").mockImplementation(((code?: number) => { exitCode = code; }) as never);
  await runDoctor(endpoint);
  return { out: lines.join("\n"), exitCode };
}

describe("aroha doctor — DID document check", () => {
  it("fails when the JSON has the right id but no verification method", async () => {
    wellKnownBody = { "@context": ["https://www.w3.org/ns/did/v1"], id: DID, capabilities: [] };
    const { out, exitCode } = await doctor();
    expect(exitCode).toBe(1);
    expect(out).toContain("no verificationMethod");
  });

  it("fails when the document's id is not the DID in .env", async () => {
    const other = await generateDID("someone-else", `${endpoint}/aroha/v1`);
    wellKnownBody = other.document;
    const { out, exitCode } = await doctor();
    expect(exitCode).toBe(1);
    expect(out).toContain(`does not match AROHA_AGENT_DID=${DID}`);
  });

  it("fails when the verification method has no usable key", async () => {
    const { document } = await generateDID("doctor-test", `${endpoint}/aroha/v1`);
    wellKnownBody = {
      ...document,
      verificationMethod: [{ ...document.verificationMethod[0], publicKeyMultibase: "not-a-key" }],
    };
    const { out, exitCode } = await doctor();
    expect(exitCode).toBe(1);
    expect(out).toContain("no usable public key");
  });

  it("passes a DID document whose id matches and whose key core can extract", async () => {
    const { document } = await generateDID("doctor-test", `${endpoint}/aroha/v1`);
    expect(document.id).toBe(DID);
    wellKnownBody = document;
    const { out, exitCode } = await doctor();
    expect(exitCode).toBeUndefined();
    expect(out).toContain("DID document");
    expect(out).toContain("All checks passed");
  });

  it("warns, without failing, when the endpoint serves an @aroha-sdk/run manifest", async () => {
    wellKnownBody = { arohaProtocolVersion: "1.0", name: "Quickstart Agent" };
    const { out, exitCode } = await doctor();
    expect(exitCode).toBeUndefined();
    expect(out).toContain("serves an agent manifest, not a DID document");
  });
});
