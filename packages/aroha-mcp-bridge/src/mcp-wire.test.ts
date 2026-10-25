// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * wrapMcp's MCP-on-the-wire mode: a stock MCP SDK client (2026-07-28 and a
 * 2025-era one) lists and calls the wrapped tools over Streamable HTTP; the
 * mandate gate reads `_meta["aroha/mandate"]` with a holder proof bound to the
 * agent, the tool, the arguments and a single-use nonce.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { PublicKeyResolver } from "@aroha-sdk/core";
import { issueIntentMandate } from "@aroha-sdk/credentials";
import { wrapMcp, presentMandate, MANDATE_META_KEY, type McpToolDefinition } from "./index.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const BRIDGE_DID = "did:aroha:wire-agent";
const HOLDER_DID = "did:aroha:wire-caller";
const HUMAN_DID = "did:aroha:wire-human";
const PORT = 35871;

let holderPriv: Uint8Array, holderPub: Uint8Array, humanPriv: Uint8Array, humanPub: Uint8Array;
let token: string;
let stop: () => void;
let runs = 0;

const tool: McpToolDefinition = {
  name: "search",
  description: "search things",
  inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] },
};

beforeAll(async () => {
  holderPriv = ed.utils.randomPrivateKey();
  holderPub = await ed.getPublicKeyAsync(holderPriv);
  humanPriv = ed.utils.randomPrivateKey();
  humanPub = await ed.getPublicKeyAsync(humanPriv);
  const resolver: PublicKeyResolver = async (did) => (did === HOLDER_DID ? holderPub : did === HUMAN_DID ? humanPub : null);
  token = (await issueIntentMandate(HUMAN_DID, HOLDER_DID, { spendLimitUsd: 10, currency: "USD" }, humanPriv, 600_000)).token;
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  const agent = await wrapMcp([tool], {
    name: "wire",
    port: PORT,
    did: BRIDGE_DID,
    resolvePublicKey: resolver,
    requireMandate: true,
    expectedRoot: HUMAN_DID,
    mcp: {},
    handlers: { search: async (args) => { runs++; return { content: [{ type: "text", text: `found ${String(args.q)}` }] }; } },
  });
  ({ stop } = await agent.start());
});

afterAll(() => stop?.());

async function client(mode: "modern" | "legacy"): Promise<Client> {
  const c = new Client({ name: "stock", version: "1" }, { versionNegotiation: mode === "modern" ? { mode: { pin: "2026-07-28" } } : { mode: "legacy" } });
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${PORT}/mcp`)));
  return c;
}

const textOf = (r: { content: unknown[] }) => (r.content[0] as { text: string }).text;

describe("wrapMcp MCP-on-the-wire mode", () => {
  it("lists the wrapped tools to a 2026-07-28 client and refuses a call without a mandate", async () => {
    const c = await client("modern");
    expect(c.getNegotiatedProtocolVersion()).toBe("2026-07-28");
    const tools = await c.listTools();
    expect(tools.tools.map((t) => t.name)).toEqual(["search"]);
    const r = await c.callTool({ name: "search", arguments: { q: "x" } });
    expect(r.isError).toBe(true);
    expect(textOf(r)).toMatch(/No mandate presented/);
    expect(runs).toBe(0);
    await c.close();
  });

  it("runs a call whose _meta presents the mandate, once", async () => {
    const c = await client("modern");
    const args = { q: "flights" };
    const meta = await presentMandate({ token, holderDid: HOLDER_DID, holderPrivateKey: holderPriv, audience: BRIDGE_DID, tool: "search", args });
    expect(Object.keys(meta)).toEqual([MANDATE_META_KEY]);
    const r = await c.callTool({ name: "search", arguments: args, _meta: meta });
    expect(r.isError).toBeFalsy();
    expect(textOf(r)).toBe("found flights");

    const replay = await c.callTool({ name: "search", arguments: args, _meta: meta });
    expect(replay.isError).toBe(true);
    expect(textOf(replay)).toMatch(/already used/);
    await c.close();
  });

  it("refuses a presentation made for other arguments or another agent", async () => {
    const c = await client("modern");
    const other = await presentMandate({ token, holderDid: HOLDER_DID, holderPrivateKey: holderPriv, audience: BRIDGE_DID, tool: "search", args: { q: "a" } });
    const r1 = await c.callTool({ name: "search", arguments: { q: "b" }, _meta: other });
    expect(r1.isError).toBe(true);
    expect(textOf(r1)).toMatch(/does not verify/);
    const elsewhere = await presentMandate({ token, holderDid: HOLDER_DID, holderPrivateKey: holderPriv, audience: "did:aroha:someone-else", tool: "search", args: { q: "b" } });
    const r2 = await c.callTool({ name: "search", arguments: { q: "b" }, _meta: elsewhere });
    expect(r2.isError).toBe(true);
    await c.close();
  });

  it("serves a 2025-era client too", async () => {
    const c = await client("legacy");
    const args = { q: "legacy" };
    const meta = await presentMandate({ token, holderDid: HOLDER_DID, holderPrivateKey: holderPriv, audience: BRIDGE_DID, tool: "search", args });
    const r = await c.callTool({ name: "search", arguments: args, _meta: meta });
    expect(textOf(r)).toBe("found legacy");
    await c.close();
  });

  it("refuses to serve MCP without a mandate gate on a non-loopback host", async () => {
    const agent = await wrapMcp([tool], {
      name: "open", port: PORT + 1, host: "0.0.0.0", resolvePublicKey: async () => null, mcp: {},
      handlers: { search: async () => ({ content: [{ type: "text", text: "" }] }) },
    });
    await expect(agent.start()).rejects.toThrow(/no caller authentication/);
  });
});
