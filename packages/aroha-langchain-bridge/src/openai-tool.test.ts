// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * arohaCapabilityToOpenAITool against the OpenAI function-calling contract:
 *
 *  1. The generated definition obeys the Chat Completions function-tool
 *     rules (name pattern and length, `parameters` as a JSON Schema object,
 *     nothing extra on the wire, no `strict` since the bridge does not offer it).
 *  2. End to end: the definition goes through the official `openai` npm
 *     client to a local stub of /v1/chat/completions, the stub answers with a
 *     tool call, and the tool call is executed through the bridge against a
 *     real Aroha provider (signed ArohaRequest over HTTP on 127.0.0.1).
 *
 * This proves "OpenAI function-tool compatible". It does not exercise
 * AutoGen or Semantic Kernel themselves.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createServer, type Server, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import OpenAI from "openai";
import { ArohaClient, generateDID, type ArohaServer } from "@aroha-sdk/core";
import {
  arohaCapabilityToOpenAITool, langChainAgentToArohaProvider, toolNameFor, OPENAI_FUNCTION_NAME_PATTERN,
  type ArohaCapabilityToToolOptions,
} from "./bridge.js";
import type { LangChainToolLike, OpenAIFunctionLike } from "./types.js";

// ─── The OpenAI function-tool rules, as a checker ────────────────────────────

const JSON_SCHEMA_TYPES = new Set(["object", "array", "string", "number", "integer", "boolean", "null"]);

/** Problems with a JSON Schema node, per the subset OpenAI function parameters use. */
function schemaProblems(s: unknown, path: string): string[] {
  if (!s || typeof s !== "object" || Array.isArray(s)) return [`${path} is not a schema object`];
  const node = s as Record<string, unknown>;
  const out: string[] = [];
  const types = Array.isArray(node.type) ? node.type : node.type === undefined ? [] : [node.type];
  for (const t of types) if (!JSON_SCHEMA_TYPES.has(t as string)) out.push(`${path}.type ${String(t)} is not a JSON Schema type`);
  if (node.properties !== undefined) {
    if (!node.properties || typeof node.properties !== "object" || Array.isArray(node.properties)) out.push(`${path}.properties is not an object`);
    else for (const [k, v] of Object.entries(node.properties)) out.push(...schemaProblems(v, `${path}.properties.${k}`));
  }
  if (node.required !== undefined) {
    if (!Array.isArray(node.required) || node.required.some((r) => typeof r !== "string")) out.push(`${path}.required is not a string array`);
    else for (const r of node.required) if (!(node.properties as Record<string, unknown> | undefined)?.[r]) out.push(`${path}.required names ${r}, which is not a property`);
  }
  if (node.items !== undefined) out.push(...schemaProblems(node.items, `${path}.items`));
  if (node.enum !== undefined && !Array.isArray(node.enum)) out.push(`${path}.enum is not an array`);
  return out;
}

/** Strict-mode (Structured Outputs) constraints, for a definition that sets strict: true. */
function strictProblems(s: Record<string, unknown>, path: string): string[] {
  const out: string[] = [];
  if (s.type === "object" || (Array.isArray(s.type) && s.type.includes("object"))) {
    if (s.additionalProperties !== false) out.push(`${path}.additionalProperties must be false`);
    const props = Object.keys((s.properties as object) ?? {});
    const req = (s.required as string[]) ?? [];
    for (const p of props) if (!req.includes(p)) out.push(`${path}.required must list ${p}`);
  }
  for (const [k, v] of Object.entries((s.properties as Record<string, Record<string, unknown>>) ?? {})) out.push(...strictProblems(v, `${path}.properties.${k}`));
  if (s.items) out.push(...strictProblems(s.items as Record<string, unknown>, `${path}.items`));
  return out;
}

/** Problems with a Chat Completions `tools[]` entry as it goes over the wire. */
function openAIToolProblems(tool: unknown): string[] {
  const wire = JSON.parse(JSON.stringify(tool)) as Record<string, unknown>;
  const out: string[] = [];
  const extra = Object.keys(wire).filter((k) => k !== "type" && k !== "function");
  if (extra.length) out.push(`unexpected top-level keys: ${extra.join(", ")}`);
  if (wire.type !== "function") out.push(`type is ${String(wire.type)}, not "function"`);
  const fn = wire.function as Record<string, unknown> | undefined;
  if (!fn || typeof fn !== "object") return [...out, "function is missing"];
  const fnExtra = Object.keys(fn).filter((k) => !["name", "description", "parameters", "strict"].includes(k));
  if (fnExtra.length) out.push(`unexpected function keys: ${fnExtra.join(", ")}`);
  if (typeof fn.name !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(fn.name)) out.push(`name ${JSON.stringify(fn.name)} does not match ^[a-zA-Z0-9_-]{1,64}$`);
  if (fn.description !== undefined && typeof fn.description !== "string") out.push("description is not a string");
  if (fn.parameters !== undefined) {
    const p = fn.parameters as Record<string, unknown>;
    if (!p || typeof p !== "object" || p.type !== "object") out.push('parameters is not a JSON Schema with type "object"');
    else out.push(...schemaProblems(p, "parameters"));
    if (fn.strict === true) out.push(...strictProblems(p, "parameters"));
  }
  if (fn.strict !== undefined && fn.strict !== null && typeof fn.strict !== "boolean") out.push("strict is not a boolean");
  return out;
}

const stubClient = { send: vi.fn() } as unknown as ArohaClient;
const opts = (extra: Partial<ArohaCapabilityToToolOptions> = {}): ArohaCapabilityToToolOptions => ({
  endpoint: "http://127.0.0.1:9/aroha/v1", agentDID: "did:aroha:remote", callerDID: "did:aroha:caller",
  callerPrivateKey: new Uint8Array(32), description: "Search available flights", client: stubClient, ...extra,
});

const flightSchema = {
  type: "object",
  properties: {
    origin: { type: "string", description: "IATA code" },
    destination: { type: "string", description: "IATA code" },
    passengers: { type: "integer" },
    cabin: { type: "string", enum: ["economy", "business"] },
  },
  required: ["origin", "destination"],
};

describe("arohaCapabilityToOpenAITool: OpenAI function-tool rules", () => {
  it("produces a valid definition with and without a parameters schema", () => {
    const withSchema = arohaCapabilityToOpenAITool("search-flights", opts({ schema: flightSchema }));
    expect(openAIToolProblems(withSchema)).toEqual([]);
    expect(JSON.parse(JSON.stringify(withSchema))).toEqual({
      type: "function",
      function: { name: "search-flights", description: "Search available flights", parameters: flightSchema },
    });
    // No schema: `parameters` is omitted (OpenAI reads that as "no parameters"), not sent as null.
    const bare = arohaCapabilityToOpenAITool("ping", opts());
    expect(openAIToolProblems(bare)).toEqual([]);
    expect("parameters" in JSON.parse(JSON.stringify(bare)).function).toBe(false);
  });

  it("does not set strict (the bridge does not offer strict mode)", () => {
    const t = arohaCapabilityToOpenAITool("search-flights", opts({ schema: flightSchema }));
    expect((t.function as Record<string, unknown>).strict).toBeUndefined();
    // The checker's strict rules do flag this schema, so a caller who adds
    // strict: true themselves must also tighten the schema.
    expect(openAIToolProblems({ ...t, function: { ...t.function, strict: true } })).toEqual(
      expect.arrayContaining(["parameters.additionalProperties must be false", "parameters.required must list passengers"]),
    );
  });

  it("maps any capability id to a valid function name, keeping distinct long ids distinct", () => {
    const ids = [
      "search-flights", "com.example.travel/search flights", "ünïcode:cap", "a",
      "x".repeat(64), "x".repeat(65), `${"long.capability.name.".repeat(5)}one`, `${"long.capability.name.".repeat(5)}two`,
    ];
    const names = ids.map((id) => arohaCapabilityToOpenAITool(id, opts()).function.name);
    for (const n of names) expect(n).toMatch(OPENAI_FUNCTION_NAME_PATTERN);
    expect(names[4]).toBe("x".repeat(64)); // 64 is allowed as-is
    expect(names[5]).toHaveLength(64);
    expect(names[6]).not.toBe(names[7]);
    expect(toolNameFor(ids[6])).toBe(names[6]); // deterministic
    for (const id of ids) expect(openAIToolProblems(arohaCapabilityToOpenAITool(id, opts()))).toEqual([]);
  });

  it("refuses inputs that cannot become a valid definition", () => {
    expect(() => arohaCapabilityToOpenAITool("", opts())).toThrow(/non-empty/);
    expect(() => arohaCapabilityToOpenAITool("x", opts({ schema: { type: "string" } }))).toThrow(/type "object"/);
    expect(() => arohaCapabilityToOpenAITool("x", opts({ schema: [] as unknown as Record<string, unknown> }))).toThrow(/type "object"/);
  });

  it("the checker itself rejects the classic mistakes", () => {
    const fn = (f: Record<string, unknown>) => ({ type: "function", function: { name: "ok", ...f } });
    expect(openAIToolProblems(fn({ name: "has space" }))).not.toEqual([]);
    expect(openAIToolProblems(fn({ name: "n".repeat(65) }))).not.toEqual([]);
    expect(openAIToolProblems(fn({ parameters: { type: "string" } }))).not.toEqual([]);
    expect(openAIToolProblems(fn({ parameters: { type: "object", required: ["a"], properties: {} } }))).not.toEqual([]);
    expect(openAIToolProblems({ ...fn({}), extra: 1 })).not.toEqual([]);
  });
});

// ─── End to end: openai client → stub → tool call → bridge → Aroha agent ─────

describe("arohaCapabilityToOpenAITool end to end with the openai client", () => {
  let provider: ArohaServer;
  let endpoint: string;
  let stub: Server;
  let stubBase: string;
  const requests: Array<Record<string, unknown>> = [];
  const remoteCalls: unknown[] = [];
  let fnTool: OpenAIFunctionLike;
  let agent: Awaited<ReturnType<typeof generateDID>>;
  let caller: Awaited<ReturnType<typeof generateDID>>;

  const readJson = (req: IncomingMessage) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); } catch (e) { reject(e); } });
      req.on("error", reject);
    });

  beforeAll(async () => {
    // A real Aroha provider exposing one tool as the "search-flights" capability.
    agent = await generateDID("flight-agent", "http://127.0.0.1");
    caller = await generateDID("llm-host", "http://127.0.0.1");
    const remoteTool: LangChainToolLike = {
      name: "search-flights", description: "Search flights", schema: flightSchema,
      async call(input) {
        remoteCalls.push(input);
        const p = input as { origin: string; destination: string };
        return JSON.stringify({ flights: [{ id: "NZ99", from: p.origin, to: p.destination }] });
      },
    };
    vi.spyOn(console, "log").mockImplementation(() => {});
    provider = langChainAgentToArohaProvider([remoteTool], {
      agentDID: agent.did, agentPrivateKey: agent.privateKey, port: 0, didDocument: agent.document,
      resolvePublicKey: async (did: string) => (did === caller.did ? caller.publicKey : null),
    });
    await provider.start();
    const port = ((provider as unknown as { server: Server }).server.address() as AddressInfo).port;
    endpoint = `http://127.0.0.1:${port}/aroha/v1`;
    fnTool = arohaCapabilityToOpenAITool("search-flights", {
      endpoint, agentDID: agent.did, callerDID: caller.did, callerPrivateKey: caller.privateKey,
      description: "Search available flights", schema: flightSchema,
    });

    // A stub of POST /v1/chat/completions: the first turn answers with a call
    // to the first tool offered, the second turn (carrying the tool result)
    // answers with text.
    stub = createServer(async (req, res) => {
      const body = await readJson(req);
      requests.push({ ...body, _path: req.url, _auth: req.headers.authorization });
      const messages = body.messages as Array<Record<string, unknown>>;
      const last = messages[messages.length - 1];
      const tools = (body.tools as Array<{ function: { name: string } }>) ?? [];
      const message = last.role === "tool"
        ? { role: "assistant", content: `Found: ${String(last.content)}`, refusal: null }
        : {
            role: "assistant", content: null, refusal: null,
            tool_calls: [{ id: "call_1", type: "function", function: { name: tools[0].function.name, arguments: JSON.stringify({ origin: "AKL", destination: "NRT" }) } }],
          };
      const out = JSON.stringify({
        id: `chatcmpl-${requests.length}`, object: "chat.completion", created: 1, model: body.model,
        choices: [{ index: 0, message, finish_reason: last.role === "tool" ? "stop" : "tool_calls", logprobs: null }],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      });
      res.writeHead(200, { "content-type": "application/json", "content-length": String(Buffer.byteLength(out)) });
      res.end(out);
    });
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    stubBase = `http://127.0.0.1:${(stub.address() as AddressInfo).port}/v1`;
  });

  afterAll(async () => {
    stub?.close();
    await provider?.stop();
    vi.restoreAllMocks();
  });

  it("the openai client sends the bridge's definition unchanged, and the tool call runs through Aroha", async () => {
    const openai = new OpenAI({ apiKey: "sk-test", baseURL: stubBase, maxRetries: 0 });
    const tools = [fnTool] as unknown as OpenAI.Chat.Completions.ChatCompletionTool[];
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [{ role: "user", content: "Flights AKL to NRT?" }];

    const first = await openai.chat.completions.create({ model: "gpt-test", messages, tools });
    // What went over the wire is exactly the definition, without invoke().
    expect(requests[0]._path).toBe("/v1/chat/completions");
    expect(requests[0].tools).toEqual([{ type: "function", function: { name: "search-flights", description: "Search available flights", parameters: flightSchema } }]);
    expect(openAIToolProblems((requests[0].tools as unknown[])[0])).toEqual([]);

    // Execute the returned tool call through the bridge.
    const call = first.choices[0].message.tool_calls![0] as { id: string; type: "function"; function: { name: string; arguments: string } };
    expect(call.function.name).toBe(fnTool.function.name);
    const result = await fnTool.invoke(JSON.parse(call.function.arguments));
    expect(remoteCalls).toEqual([{ origin: "AKL", destination: "NRT" }]);
    expect(result).toEqual({ flights: [{ id: "NZ99", from: "AKL", to: "NRT" }] });

    // Hand the result back; the client accepts the tool message and the model answers.
    const second = await openai.chat.completions.create({
      model: "gpt-test", tools,
      messages: [...messages, first.choices[0].message, { role: "tool", tool_call_id: call.id, content: JSON.stringify(result) }],
    });
    const sentBack = (requests[1].messages as Array<Record<string, unknown>>).at(-1);
    expect(sentBack).toEqual({ role: "tool", tool_call_id: "call_1", content: JSON.stringify(result) });
    expect(second.choices[0].message.content).toContain("NZ99");
  });

  it("an Aroha-side refusal surfaces from invoke() so the host can report it as the tool result", async () => {
    // A capability the agent does not have: ArohaError from the provider.
    const missing = arohaCapabilityToOpenAITool("no-such-capability", {
      endpoint, agentDID: agent.did, callerDID: caller.did, callerPrivateKey: caller.privateKey, description: "missing",
    });
    await expect(missing.invoke({})).rejects.toThrow(/Unknown capability/);
    // A caller the agent cannot verify: the request is refused before any tool runs.
    const stranger = await generateDID("stranger", "http://127.0.0.1");
    const unverified = arohaCapabilityToOpenAITool("search-flights", {
      endpoint, agentDID: agent.did, callerDID: stranger.did, callerPrivateKey: stranger.privateKey, description: "d",
    });
    const before = remoteCalls.length;
    await expect(unverified.invoke({ origin: "AKL", destination: "NRT" })).rejects.toThrow();
    expect(remoteCalls.length).toBe(before);
  });
});
