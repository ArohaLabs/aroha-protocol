// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import { generateKeyPair, generateDid } from "@aroha-sdk/core";
import { buildSar, type SignedAgentRecord } from "./sar.js";
import { publishSar, querySar } from "./sar-index-client.js";

let honestIndex: Server;
let honestUrl: string;
/** Stores exactly what was POSTed, unmodified — the honest index. */
let stored: SignedAgentRecord[] = [];

let forgingIndex: Server;
let forgingUrl: string;

async function startJsonServer(handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => void) {
  const server = createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return { server, url };
}

function readBody(req: import("node:http").IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => resolve(raw));
  });
}

beforeAll(async () => {
  ({ server: honestIndex, url: honestUrl } = await startJsonServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://placeholder.invalid");
    if (url.pathname === "/v1/sar" && req.method === "POST") {
      const record = JSON.parse(await readBody(req)) as SignedAgentRecord;
      stored.push(record);
      res.writeHead(201).end();
      return;
    }
    if (url.pathname === "/v1/sar" && req.method === "GET") {
      const cap = url.searchParams.get("capability");
      const records = cap ? stored.filter((r) => r.capabilities.includes(cap)) : stored;
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ records }));
      return;
    }
    res.writeHead(404).end();
  }));

  // A malicious index: returns a record with a tampered capability list,
  // impersonating an agent whose real DID it does not control the key for.
  ({ server: forgingIndex, url: forgingUrl } = await startJsonServer(async (req, res) => {
    if (req.url?.startsWith("/v1/sar") && req.method === "GET") {
      const forged = stored[0] ? { ...stored[0], capabilities: ["drain-wallet"] } : null;
      res.writeHead(200, { "content-type": "application/json" }).end(
        JSON.stringify({ records: forged ? [forged] : [] }),
      );
      return;
    }
    res.writeHead(404).end();
  }));
});

afterAll(async () => {
  await new Promise<void>((r) => honestIndex.close(() => r()));
  await new Promise<void>((r) => forgingIndex.close(() => r()));
});

describe("publishSar", () => {
  it("publishes to a real index and it's actually stored", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    const sar = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["book-flight"] });

    const results = await publishSar([honestUrl], sar);
    expect(results).toEqual([{ indexUrl: honestUrl, ok: true }]);
    expect(stored.some((r) => r.did === did)).toBe(true);
  });

  it("reports per-index failure without throwing when one index is unreachable", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    const sar = await buildSar({ did, privateKey: kp.privateKey });

    const results = await publishSar([honestUrl, "http://127.0.0.1:1"], sar);
    const honest = results.find((r) => r.indexUrl === honestUrl);
    const dead = results.find((r) => r.indexUrl === "http://127.0.0.1:1");
    expect(honest?.ok).toBe(true);
    expect(dead?.ok).toBe(false);
  });
});

describe("querySar — federation security properties (spec §7.3)", () => {
  it("returns a genuinely published, verifiable record", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    const sar = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["unique-marker-a"] });
    await publishSar([honestUrl], sar);

    const results = await querySar([honestUrl], { capability: "unique-marker-a" });
    expect(results.some((r) => r.did === did)).toBe(true);
  });

  it("an index can omit — an empty/unreachable index just contributes nothing", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    const sar = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["unique-marker-b"] });
    await publishSar([honestUrl], sar);

    // A second, entirely silent index (never published to) plus a dead one —
    // the real record from the honest index must still come through.
    const { url: emptyUrl, server: emptyServer } = await startJsonServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ records: [] }));
    });
    try {
      const results = await querySar([honestUrl, emptyUrl, "http://127.0.0.1:1"], {
        capability: "unique-marker-b",
      });
      expect(results.some((r) => r.did === did)).toBe(true);
    } finally {
      await new Promise<void>((r) => emptyServer.close(() => r()));
    }
  });

  it("an index cannot forge — a tampered record from a malicious index is silently dropped", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    const sar = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["real-capability"] });
    stored.length = 0;
    await publishSar([honestUrl], sar);

    // forgingIndex serves the same record with "capabilities" mutated to
    // "drain-wallet" — the signature no longer matches, so it must be
    // dropped rather than returned as if it were genuine.
    const results = await querySar([forgingUrl]);
    expect(results.some((r) => r.did === did && r.capabilities.includes("drain-wallet"))).toBe(false);
  });

  it("dedupes across indexes, keeping the newest record per DID", async () => {
    const kp = await generateKeyPair();
    const did = generateDid(kp.publicKey);
    stored.length = 0;

    const older = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["v1"] });
    await new Promise((r) => setTimeout(r, 5));
    const newer = await buildSar({ did, privateKey: kp.privateKey, capabilities: ["v2"] });

    const { url: secondIndexUrl, server: secondIndex } = await startJsonServer(async (req, res) => {
      if (req.url?.startsWith("/v1/sar") && req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ records: [newer] }));
        return;
      }
      res.writeHead(404).end();
    });
    try {
      await publishSar([honestUrl], older);
      const results = await querySar([honestUrl, secondIndexUrl]);
      const mine = results.filter((r) => r.did === did);
      expect(mine).toHaveLength(1);
      expect(mine[0].capabilities).toEqual(["v2"]);
    } finally {
      await new Promise<void>((r) => secondIndex.close(() => r()));
    }
  });
});
