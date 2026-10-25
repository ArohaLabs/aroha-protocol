// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * MCP Tasks extension (io.modelcontextprotocol/tasks, 2026-07-28) over the
 * HTTP transport with OAuth, driven with raw JSON-RPC (the stock 2.3.1 client
 * has no task runtime):
 *   - negotiation: advertised in server/discover; a task only for a request
 *     that declares the extension; -32021 for tasks/* without it
 *   - aroha_call becomes a task whose result is the synchronous result
 *   - one user (or one client of the same user) can never read, update or
 *     cancel another's task — indistinguishable from a task that never existed
 *   - cancellation aborts the outbound call; terminal states do not change
 *   - TTL expiry, per-user and process-wide bounds
 *   - the approval round trip still runs first; tasks/update cannot approve
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { buildEnvelope, type ArohaEnvelope } from "@aroha-sdk/core/messages";
import { generateDid } from "@aroha-sdk/core/identity";
import { loadConfig } from "./config.js";
import { FilePrincipalKeyStore } from "./keystore.js";
import { createRuntime } from "./server.js";
import { startHttpServer, type RunningHttpServer } from "./http.js";
import { TASKS_EXTENSION, TaskStore } from "./tasks.js";
import { startFakeAs, freePort, type FakeAs } from "./test-utils/fake-as.js";

ed.etc.sha512Sync = (...m: Parameters<typeof sha512>) => sha512(...m);

const CLIENT_A = "https://client-a.example/cimd.json";
const CLIENT_B = "https://client-b.example/cimd.json";
const TTL_MS = 60_000;
const PER_USER = 3;

let as: FakeAs;
let backend: Server;
let mcp: RunningHttpServer;
let keysDir: string;
let publicUrl: string;
let agentDid: string;
let clockOffset = 0;
/** Agent behaviour: hold responses until released. */
let hold = false;
const held: Array<() => void> = [];
let agentRequests = 0;
let agentAborted = 0;

beforeAll(async () => {
  const agentKey = ed.utils.randomPrivateKey();
  agentDid = generateDid(await ed.getPublicKeyAsync(agentKey));
  backend = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "GET" && url.pathname.startsWith("/v1/agents/")) {
      const addr = backend.address();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ did: agentDid, endpoint: `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/agent` }));
      return;
    }
    if (req.method === "POST" && url.pathname === "/agent/aroha/v1") {
      let raw = "";
      for await (const c of req) raw += c;
      agentRequests++;
      res.on("close", () => { if (!res.writableEnded) agentAborted++; });
      const request = JSON.parse(raw) as ArohaEnvelope;
      if (hold) await new Promise<void>((r) => held.push(r));
      if (res.destroyed) return;
      const reply = await buildEnvelope("ArohaResponse", agentDid, request.from,
        { capability: "echo", result: { echoed: (request.body as { params?: unknown }).params } } as never,
        request.correlationId, agentKey);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(reply));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => backend.listen(0, "127.0.0.1", () => r()));
  const addr = backend.address();

  as = await startFakeAs({});
  keysDir = mkdtempSync(join(tmpdir(), "aroha-mcp-tasks-"));
  const port = await freePort();
  publicUrl = `http://127.0.0.1:${port}/mcp`;
  const config = loadConfig({
    AROHA_MCP_TRANSPORT: "http",
    AROHA_MCP_PORT: String(port),
    AROHA_MCP_PUBLIC_URL: publicUrl,
    AROHA_MCP_AUTH_ISSUER: as.issuer,
    AROHA_MCP_KEY_DIR: keysDir,
    AROHA_ALLOW_PRIVATE_ENDPOINTS: "1", // the test agent listens on loopback
    AROHA_REGISTRY_URL: `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`,
    AROHA_MCP_TASKS_PER_USER: String(PER_USER),
    AROHA_MCP_TASKS_MAX: "5",
    AROHA_MCP_TASK_TTL_SECONDS: String(TTL_MS / 1000),
  });
  const tasks = new TaskStore({ ...config.tasks!, now: () => Date.now() + clockOffset });
  mcp = await startHttpServer({ runtime: createRuntime(config, new FilePrincipalKeyStore(config.keysDir), { tasks }), log: () => {} });
});

afterAll(async () => {
  release();
  await mcp?.close();
  await as?.close();
  await new Promise<void>((r) => { backend?.close(() => r()); backend?.closeAllConnections?.(); });
  // keysDir came from mkdtempSync above.
  if (keysDir) rmSync(keysDir, { recursive: true, force: true });
});

afterEach(() => {
  release();
  clockOffset = 0;
});

function release(): void {
  hold = false;
  while (held.length) held.shift()!();
}

// ─── raw JSON-RPC ─────────────────────────────────────────────────────────────

interface RpcMessage { result?: Record<string, unknown> & { resultType?: string }; error?: { code: number; message: string; data?: unknown } }
let nextId = 1;

async function token(sub: string, clientId = CLIENT_A): Promise<string> {
  return as.mint({ sub, aud: publicUrl, client_id: clientId });
}

async function rpc(bearer: string, method: string, params: Record<string, unknown>, opts: { tasks?: boolean } = {}): Promise<RpcMessage> {
  const name = method === "tools/call" ? params.name : method.startsWith("tasks/") ? params.taskId : undefined;
  const res = await fetch(publicUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${bearer}`,
      "MCP-Protocol-Version": "2026-07-28",
      "Mcp-Method": method,
      ...(typeof name === "string" ? { "Mcp-Name": name } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "2.0", id: nextId++, method,
      params: {
        ...params,
        _meta: {
          ...((params._meta as Record<string, unknown> | undefined) ?? {}),
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientInfo": { name: "raw", version: "0" },
          "io.modelcontextprotocol/clientCapabilities": {
            elicitation: { form: {} },
            ...(opts.tasks ? { extensions: { [TASKS_EXTENSION]: {} } } : {}),
          },
        },
      },
    }),
  });
  const text = await res.text();
  if ((res.headers.get("content-type") ?? "").includes("text/event-stream")) {
    const data = text.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6));
    return JSON.parse(data[data.length - 1]) as RpcMessage;
  }
  return JSON.parse(text) as RpcMessage;
}

const call = (bearer: string, args: Record<string, unknown>, opts: { tasks?: boolean } = { tasks: true }, extra: Record<string, unknown> = {}) =>
  rpc(bearer, "tools/call", { name: "aroha_call", arguments: { agentDid, capability: "echo", params: { q: 1 }, ...args }, ...extra }, opts);
const getTask = (bearer: string, taskId: string) => rpc(bearer, "tasks/get", { taskId }, { tasks: true });
const cancelTask = (bearer: string, taskId: string) => rpc(bearer, "tasks/cancel", { taskId }, { tasks: true });
const updateTask = (bearer: string, taskId: string, inputResponses: Record<string, unknown>) =>
  rpc(bearer, "tasks/update", { taskId, inputResponses }, { tasks: true });

async function until<T>(f: () => Promise<T>, done: (v: T) => boolean): Promise<T> {
  for (let i = 0; i < 200; i++) {
    const v = await f();
    if (done(v)) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error("condition not reached");
}

async function untilHeld(n: number): Promise<void> {
  await until(async () => held.length, (k) => k >= n);
}

const terminal = (m: RpcMessage) => ["completed", "failed", "cancelled"].includes(String(m.result?.status));
const textOf = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]).text;

// ─── tests ────────────────────────────────────────────────────────────────────

describe("MCP Tasks extension on aroha_call", () => {
  it("advertises the extension and answers synchronously when the request does not declare it", async () => {
    const t = await token("alice");
    const discover = await rpc(t, "server/discover", {});
    expect((discover.result?.capabilities as { extensions?: Record<string, unknown> }).extensions?.[TASKS_EXTENSION]).toEqual({});

    const sync = await call(t, {}, { tasks: false });
    expect(sync.result?.resultType).toBe("complete");
    expect(sync.result?.taskId).toBeUndefined();
    expect(JSON.parse(textOf(sync.result)).result).toEqual({ echoed: { q: 1 } });
  });

  it("returns a task handle and serves the synchronous result through tasks/get", async () => {
    const t = await token("alice");
    const created = await call(t, { params: { q: 2 } });
    const r = created.result!;
    expect(r.resultType).toBe("task");
    expect(r.status).toBe("working");
    expect(typeof r.taskId).toBe("string");
    expect((r.taskId as string).length).toBeGreaterThanOrEqual(43); // 256 random bits, base64url
    expect(r.ttlMs).toBe(TTL_MS);
    expect(r.pollIntervalMs).toBeGreaterThan(0);
    expect(Number.isNaN(Date.parse(String(r.createdAt)))).toBe(false);
    expect(Number.isNaN(Date.parse(String(r.lastUpdatedAt)))).toBe(false);

    const done = await until(() => getTask(t, r.taskId as string), terminal);
    expect(done.result?.resultType).toBe("complete");
    expect(done.result?.status).toBe("completed");
    expect(done.result?.taskId).toBe(r.taskId);
    const out = JSON.parse(textOf(done.result?.result)) as { success: boolean; result: unknown; receiptId: string };
    expect(out.success).toBe(true);
    expect(out.result).toEqual({ echoed: { q: 2 } });

    const receipt = await rpc(t, "tools/call", { name: "aroha_get_receipt", arguments: { receiptId: out.receiptId } });
    expect(JSON.parse(textOf(receipt.result)).taskId).toBe(r.taskId);
  });

  it("answers -32021 to tasks/* from a client that did not declare the extension", async () => {
    const t = await token("alice");
    const created = await call(t, {});
    const taskId = created.result!.taskId as string;
    for (const method of ["tasks/get", "tasks/cancel"]) {
      const m = await rpc(t, method, { taskId }, { tasks: false });
      expect(m.error?.code).toBe(-32021);
      expect((m.error?.data as { requiredCapabilities: unknown }).requiredCapabilities).toEqual({ extensions: { [TASKS_EXTENSION]: {} } });
    }
    const u = await rpc(t, "tasks/update", { taskId, inputResponses: {} }, { tasks: false });
    expect(u.error?.code).toBe(-32021);
    await until(() => getTask(t, taskId), terminal);
  });

  it("never lets another user, or another client of the same user, see, update or cancel a task", async () => {
    hold = true;
    const alice = await token("alice");
    const created = await call(alice, {});
    const taskId = created.result!.taskId as string;
    await untilHeld(1);

    const neverExisted = await getTask(alice, "A".repeat(43));
    expect(neverExisted.error?.code).toBe(-32602);

    for (const intruder of [await token("bob"), await token("alice", CLIENT_B)]) {
      const g = await getTask(intruder, taskId);
      expect(g.error).toEqual({ code: -32602, message: "Failed to retrieve task: Task not found" });
      expect(g.result).toBeUndefined();
      const c = await cancelTask(intruder, taskId);
      expect(c.error?.code).toBe(-32602);
      const u = await updateTask(intruder, taskId, {});
      expect(u.error?.code).toBe(-32602);
    }
    const stillWorking = await getTask(alice, taskId);
    expect(stillWorking.result?.status).toBe("working");

    release();
    const done = await until(() => getTask(alice, taskId), terminal);
    expect(done.result?.status).toBe("completed");
  });

  it("cancels: aborts the outbound call, reports cancelled, and stays cancelled", async () => {
    hold = true;
    const t = await token("carol");
    const abortedBefore = agentAborted;
    const created = await call(t, {});
    const taskId = created.result!.taskId as string;
    await untilHeld(1);

    const ack = await cancelTask(t, taskId);
    expect(ack.error).toBeUndefined();
    expect(ack.result?.resultType).toBe("complete");
    const g = await getTask(t, taskId);
    expect(g.result?.status).toBe("cancelled");
    expect(g.result?.result).toBeUndefined();
    await until(async () => agentAborted, (n) => n > abortedBefore);

    release();
    await new Promise((r) => setTimeout(r, 50));
    expect((await getTask(t, taskId)).result?.status).toBe("cancelled");
    // Cancelling a terminal task is acknowledged and changes nothing.
    expect((await cancelTask(t, taskId)).result?.resultType).toBe("complete");
    expect((await cancelTask(t, "no-such-task")).error?.code).toBe(-32602);
  });

  it("acknowledges tasks/update without effect, and refuses unknown or malformed updates", async () => {
    const t = await token("dave");
    const created = await call(t, {});
    const taskId = created.result!.taskId as string;
    const ack = await updateTask(t, taskId, { aroha_approval: { action: "accept", content: { approve: true } } });
    expect(ack.result?.resultType).toBe("complete");
    expect((await updateTask(t, "no-such-task", {})).error?.code).toBe(-32602);
    expect((await rpc(t, "tasks/update", { taskId }, { tasks: true })).error?.code).toBe(-32602);
    await until(() => getTask(t, taskId), terminal);
  });

  it("expires tasks after their TTL, aborting one still running", async () => {
    const t = await token("erin");
    const finished = (await call(t, {})).result!.taskId as string;
    await until(() => getTask(t, finished), terminal);

    hold = true;
    const abortedBefore = agentAborted;
    const running = (await call(t, {})).result!.taskId as string;
    await untilHeld(1);

    clockOffset = TTL_MS + 1;
    expect((await getTask(t, finished)).error).toEqual({ code: -32602, message: "Failed to retrieve task: Task has expired" });
    expect((await getTask(t, finished)).error?.message).toMatch(/Task not found/); // discarded
    expect((await getTask(t, running)).error?.message).toMatch(/Task has expired/);
    await until(async () => agentAborted, (n) => n > abortedBefore);
    expect((await cancelTask(t, running)).error?.code).toBe(-32602);
  });

  it("bounds tasks per user and per process, dropping finished tasks before refusing", async () => {
    hold = true;
    const frank = await token("frank");
    const ids: string[] = [];
    for (let i = 0; i < PER_USER; i++) ids.push((await call(frank, {})).result!.taskId as string);
    await untilHeld(PER_USER);
    const over = await call(frank, {});
    expect(over.result?.resultType).toBe("complete");
    expect(over.result?.isError).toBe(true);
    expect(textOf(over.result)).toMatch(/not started/);

    // Another user still has room until the process-wide cap (5) is reached.
    const grace = await token("grace");
    const g1 = (await call(grace, {})).result!;
    expect(g1.resultType).toBe("task");
    const g2 = (await call(grace, {})).result!;
    expect(g2.resultType).toBe("task");
    await untilHeld(PER_USER + 2);
    const full = await call(grace, {});
    expect(full.result?.isError).toBe(true);
    expect(textOf(full.result)).toMatch(/task limit/);

    release();
    for (const id of ids) await until(() => getTask(frank, id), terminal);
    await until(() => getTask(grace, g1.taskId as string), terminal);
    await until(() => getTask(grace, g2.taskId as string), terminal);
    // At the cap with only finished tasks: the oldest finished one makes room.
    const again = await call(frank, {});
    expect(again.result?.resultType).toBe("task");
    await until(() => getTask(frank, again.result!.taskId as string), terminal);
    const kept = await Promise.all(ids.map((id) => getTask(frank, id)));
    expect(kept.filter((m) => m.error?.code === -32602).length).toBeGreaterThanOrEqual(1);
    expect(kept.filter((m) => m.result).length).toBeLessThanOrEqual(PER_USER - 1);
  });

  it("runs the approval round trip before creating a task; a declined approval creates none", async () => {
    const t = await token("heidi");
    const before = agentRequests;
    const first = await call(t, { spendLimitUsd: 5 });
    expect(first.result?.resultType).toBe("input_required");
    expect(first.result?.taskId).toBeUndefined();
    const state = first.result!.requestState as string;
    expect(agentRequests).toBe(before); // nothing sent before approval

    const declined = await call(t, { spendLimitUsd: 5 }, { tasks: true }, {
      inputResponses: { aroha_approval: { action: "accept", content: { approve: false } } }, requestState: state,
    });
    expect(declined.result?.resultType).toBe("complete");
    expect(declined.result?.isError).toBe(true);
    expect(declined.result?.taskId).toBeUndefined();
    expect(agentRequests).toBe(before);

    // An approval for different arguments does not carry over.
    const mismatched = await call(t, { spendLimitUsd: 500 }, { tasks: true }, {
      inputResponses: { aroha_approval: { action: "accept", content: { approve: true } } }, requestState: state,
    });
    expect(mismatched.result?.isError).toBe(true);
    expect(agentRequests).toBe(before);

    const approved = await call(t, { spendLimitUsd: 5 }, { tasks: true }, {
      inputResponses: { aroha_approval: { action: "accept", content: { approve: true } } }, requestState: state,
    });
    expect(approved.result?.resultType).toBe("task");
    const done = await until(() => getTask(t, approved.result!.taskId as string), terminal);
    const out = JSON.parse(textOf(done.result?.result)) as { actionReceipt: { approval?: { approvalId?: string } } };
    expect(out.actionReceipt.approval?.approvalId).toBeTruthy();
    expect(agentRequests).toBe(before + 1);
  });
  it("refuses a task-notification subscription from a client that did not declare the extension", async () => {
    const t = await token("ivan");
    const listen = (declare: boolean) => fetch(publicUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json", Accept: "application/json, text/event-stream", Authorization: `Bearer ${t}`,
        "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "subscriptions/listen",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 12, method: "subscriptions/listen",
        params: {
          notifications: { taskIds: ["x"] },
          _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { name: "raw", version: "0" },
            "io.modelcontextprotocol/clientCapabilities": declare ? { extensions: { [TASKS_EXTENSION]: {} } } : {},
          },
        },
      }),
    });
    const refused = await listen(false);
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual({
      jsonrpc: "2.0", id: 12,
      error: { code: -32021, message: "Missing required client capability", data: { requiredCapabilities: { extensions: { [TASKS_EXTENSION]: {} } } } },
    });
    // A declaring client gets the SDK's stream (no task notifications are sent; polling only).
    const accepted = await listen(true);
    expect(accepted.status).toBe(200);
    await accepted.body?.cancel();
  });
});

describe("tasks configuration", () => {
  const base = { AROHA_MCP_TRANSPORT: "http", AROHA_MCP_ALLOW_UNAUTHENTICATED: "1", AROHA_REGISTRY_URL: "http://127.0.0.1:9/r" };
  it("is on by default with bounded limits, can be turned off, and refuses unbounded values", () => {
    expect(loadConfig(base).tasks).toEqual({ ttlMs: 900_000, maxPerUser: 32, maxTotal: 1000, pollIntervalMs: 1000 });
    const off = loadConfig({ ...base, AROHA_MCP_TASKS: "0" });
    expect(off.tasks).toBeUndefined();
    expect(createRuntime(off, new FilePrincipalKeyStore(keysDir)).tasks).toBeUndefined();
    expect(() => loadConfig({ ...base, AROHA_MCP_TASK_TTL_SECONDS: "0" })).toThrow(/TTL/);
    expect(() => loadConfig({ ...base, AROHA_MCP_TASK_TTL_SECONDS: "999999" })).toThrow(/TTL/);
    expect(() => loadConfig({ ...base, AROHA_MCP_TASKS_PER_USER: "1.5" })).toThrow(/PER_USER/);
    expect(() => loadConfig({ ...base, AROHA_MCP_TASKS_PER_USER: "10", AROHA_MCP_TASKS_MAX: "5" })).toThrow(/TASKS_MAX/);
  });
});
