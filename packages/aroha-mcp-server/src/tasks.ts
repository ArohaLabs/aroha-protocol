// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * MCP Tasks extension (`io.modelcontextprotocol/tasks`), server side.
 *
 * Spec followed: modelcontextprotocol/ext-tasks, specification/2026-07-28/tasks.md
 * and schema/2026-07-28/schema.ts (status Stable). The v2 TypeScript SDK
 * (2.3.1) routes the method names and the `resultType: "task"` discriminator
 * but ships no task runtime, so this module is that runtime:
 *
 *   - Negotiation: the server lists the extension in its `server/discover`
 *     capabilities; a `CreateTaskResult` is returned only when the request's
 *     own `clientCapabilities.extensions` names it. `tasks/get`, `tasks/update`
 *     and `tasks/cancel` from a client that did not declare it get `-32021`.
 *   - Creation is server-directed. `aroha_call` (the one tool that waits on a
 *     remote agent) becomes a task AFTER its approval round trip (MRTR) has
 *     resolved on the original request, as the spec recommends; the task runs
 *     exactly the code the synchronous call would, with the same approval and
 *     mandate. A task never enters `input_required`, so `tasks/update` has
 *     nothing to satisfy and is acknowledged without effect: approvals cannot
 *     be smuggled in through it.
 *   - Isolation: a task belongs to the principal and OAuth client that created
 *     it. Any other caller gets the same `-32602` "not found" as for an id that
 *     never existed, so a task id reveals nothing to anyone else. Ids are 256
 *     random bits.
 *   - Bounds: a fixed lifetime (`ttlMs`) from creation, after which a task is
 *     aborted if still running and discarded; a per-owner and a process-wide
 *     cap. At a cap the oldest finished task is dropped; when every task is
 *     still running, a new one is refused.
 *   - Cancellation is honoured: the outbound request is aborted and the task
 *     becomes `cancelled`. Terminal states never change afterwards.
 *
 * Not implemented: `notifications/tasks` (the spec makes them optional; polling
 * is the default). State is in memory, per process: a deployment with several
 * instances must route on the `Mcp-Name` header, which carries the task id.
 */

import { randomBytes } from "node:crypto";
import {
  CLIENT_CAPABILITIES_META_KEY,
  MissingRequiredClientCapabilityError,
  ProtocolError,
  ProtocolErrorCode,
  fromJsonSchema,
  type CallToolResult,
  type McpServer,
  type ServerContext,
} from "@modelcontextprotocol/server";

export const TASKS_EXTENSION = "io.modelcontextprotocol/tasks";

export type TaskStatus = "working" | "input_required" | "completed" | "failed" | "cancelled";

const TERMINAL: ReadonlySet<TaskStatus> = new Set(["completed", "failed", "cancelled"]);

interface TaskRecord {
  taskId: string;
  owner: string;
  status: TaskStatus;
  statusMessage?: string;
  createdAtMs: number;
  lastUpdatedAtMs: number;
  result?: CallToolResult;
  error?: { code: number; message: string };
  controller: AbortController;
}

/** The wire `Task` (plus the status-specific `result` / `error`). */
export interface TaskView {
  taskId: string;
  status: TaskStatus;
  statusMessage?: string;
  createdAt: string;
  lastUpdatedAt: string;
  ttlMs: number;
  pollIntervalMs: number;
  result?: CallToolResult;
  error?: { code: number; message: string };
}

export interface TaskStoreOptions {
  ttlMs: number;
  maxPerUser: number;
  maxTotal: number;
  pollIntervalMs: number;
  /** Clock (tests). */
  now?: () => number;
  /** Local diagnostics. */
  log?: (line: string) => void;
}

export class TaskLimitError extends Error {}

/** The owner key of a task: the principal and the OAuth client that made it. */
export function taskOwner(principal: string, clientId: string | undefined): string {
  return JSON.stringify([principal, clientId ?? ""]);
}

/** Bounded, per-owner, in-memory task state. */
export class TaskStore {
  private readonly tasks = new Map<string, TaskRecord>();
  private readonly now: () => number;

  constructor(readonly options: TaskStoreOptions) {
    this.now = options.now ?? Date.now;
  }

  get size(): number {
    return this.tasks.size;
  }

  /**
   * Create a task and start `run` in the background. The task is in the store
   * (so `tasks/get` resolves) before this returns. Throws TaskLimitError when
   * the owner or the process is at its cap with every task still running.
   */
  create(owner: string, run: (signal: AbortSignal) => Promise<CallToolResult>): TaskView {
    this.sweep();
    this.makeRoom((r) => r.owner === owner, this.options.maxPerUser, "you already have the maximum number of running tasks");
    this.makeRoom(() => true, this.options.maxTotal, "the server is at its task limit");

    const at = this.now();
    const rec: TaskRecord = {
      taskId: randomBytes(32).toString("base64url"),
      owner,
      status: "working",
      statusMessage: "The call is in progress.",
      createdAtMs: at,
      lastUpdatedAtMs: at,
      controller: new AbortController(),
    };
    this.tasks.set(rec.taskId, rec);

    // Started after the record exists; settled results never overwrite a
    // terminal state (a cancel that won the race stays cancelled).
    void Promise.resolve()
      .then(() => run(rec.controller.signal))
      .then(
        (result) => this.settle(rec, { status: "completed", result, statusMessage: result.isError ? "The call finished with an error result." : "The call finished." }),
        (err: unknown) => {
          this.options.log?.(`[aroha-mcp-server] task ${rec.taskId.slice(0, 8)}… failed: ${err instanceof Error ? err.message : String(err)}`);
          this.settle(rec, {
            status: "failed",
            statusMessage: "The call failed inside the server.",
            error: { code: ProtocolErrorCode.InternalError, message: "Internal error" },
          });
        },
      );
    return this.view(rec);
  }

  /** The owner's task, "expired" when its lifetime is over (then discarded), else undefined. */
  lookup(owner: string, taskId: string): TaskView | "expired" | undefined {
    const rec = this.tasks.get(taskId);
    if (!rec || rec.owner !== owner) return undefined;
    if (this.expired(rec)) {
      this.discard(rec);
      return "expired";
    }
    return this.view(rec);
  }

  /** Signal cancellation of the owner's task. Returns false when there is no such task. */
  cancel(owner: string, taskId: string): boolean | "expired" {
    const rec = this.tasks.get(taskId);
    if (!rec || rec.owner !== owner) return false;
    if (this.expired(rec)) {
      this.discard(rec);
      return "expired";
    }
    if (!TERMINAL.has(rec.status)) {
      rec.controller.abort();
      this.settle(rec, { status: "cancelled", statusMessage: "Cancelled at the caller's request." });
    }
    return true;
  }

  /** Abort every running task and forget all state (server shutdown). */
  closeAll(): void {
    for (const rec of this.tasks.values()) rec.controller.abort();
    this.tasks.clear();
  }

  /** Drop expired tasks, aborting the ones still running. */
  sweep(): void {
    for (const rec of [...this.tasks.values()]) if (this.expired(rec)) this.discard(rec);
  }

  private expired(rec: TaskRecord): boolean {
    return this.now() >= rec.createdAtMs + this.options.ttlMs;
  }

  private discard(rec: TaskRecord): void {
    rec.controller.abort();
    this.tasks.delete(rec.taskId);
  }

  private makeRoom(match: (r: TaskRecord) => boolean, cap: number, refusal: string): void {
    const mine = [...this.tasks.values()].filter(match);
    if (mine.length < cap) return;
    // Oldest finished task goes first; running work is never dropped to make room.
    const finished = mine.filter((r) => TERMINAL.has(r.status)).sort((a, b) => a.lastUpdatedAtMs - b.lastUpdatedAtMs);
    for (let i = 0; i <= mine.length - cap && i < finished.length; i++) this.tasks.delete(finished[i].taskId);
    if ([...this.tasks.values()].filter(match).length >= cap) throw new TaskLimitError(refusal);
  }

  private settle(rec: TaskRecord, next: Pick<TaskRecord, "status" | "statusMessage" | "result" | "error">): void {
    if (TERMINAL.has(rec.status) || this.tasks.get(rec.taskId) !== rec) return;
    rec.status = next.status;
    rec.statusMessage = next.statusMessage;
    if (next.result) rec.result = next.result;
    if (next.error) rec.error = next.error;
    rec.lastUpdatedAtMs = Math.max(this.now(), rec.lastUpdatedAtMs);
  }

  private view(rec: TaskRecord): TaskView {
    return {
      taskId: rec.taskId,
      status: rec.status,
      ...(rec.statusMessage ? { statusMessage: rec.statusMessage } : {}),
      createdAt: new Date(rec.createdAtMs).toISOString(),
      lastUpdatedAt: new Date(rec.lastUpdatedAtMs).toISOString(),
      ttlMs: this.options.ttlMs,
      pollIntervalMs: this.options.pollIntervalMs,
      ...(rec.status === "completed" && rec.result ? { result: rec.result } : {}),
      ...(rec.status === "failed" && rec.error ? { error: rec.error } : {}),
    };
  }
}

/** Whether this request's own client capabilities declare the tasks extension. */
export function clientDeclaredTasks(ctx: ServerContext): boolean {
  const envelope = ctx.mcpReq.envelope as Record<string, unknown> | undefined;
  const caps = envelope?.[CLIENT_CAPABILITIES_META_KEY] as { extensions?: Record<string, unknown> } | undefined;
  const ext = caps?.extensions;
  return typeof ext === "object" && ext !== null && Object.hasOwn(ext, TASKS_EXTENSION);
}

/** The `CreateTaskResult` for a new task. */
export function createTaskResult(task: TaskView): Record<string, unknown> {
  return { resultType: "task", ...task };
}

const TASK_ID_PARAMS = fromJsonSchema<{ taskId: string }>({
  type: "object",
  required: ["taskId"],
  properties: { taskId: { type: "string", minLength: 1, maxLength: 256 } },
});


function requireTasksCapability(ctx: ServerContext): void {
  if (!clientDeclaredTasks(ctx)) {
    throw new MissingRequiredClientCapabilityError({ requiredCapabilities: { extensions: { [TASKS_EXTENSION]: {} } } });
  }
}

function notFound(what: "retrieve" | "update" | "cancel", outcome: "expired" | undefined | false): ProtocolError {
  return new ProtocolError(
    ProtocolErrorCode.InvalidParams,
    `Failed to ${what} task: ${outcome === "expired" ? "Task has expired" : "Task not found"}`,
  );
}

/** Register `tasks/get`, `tasks/update` and `tasks/cancel` for one owner. */
export function registerTaskHandlers(server: McpServer, store: TaskStore, owner: string): void {
  server.server.setRequestHandler("tasks/get", { params: TASK_ID_PARAMS }, async ({ taskId }, ctx) => {
    requireTasksCapability(ctx);
    const task = store.lookup(owner, taskId);
    if (task === undefined || task === "expired") throw notFound("retrieve", task);
    return { resultType: "complete", ...task };
  });

  // The SDK lifts `inputResponses` out of the params (as for any MRTR retry)
  // into ctx.mcpReq.inputResponses, so the params schema only names taskId.
  server.server.setRequestHandler("tasks/update", { params: TASK_ID_PARAMS }, async ({ taskId }, ctx) => {
    requireTasksCapability(ctx);
    const responses = ctx.mcpReq.inputResponses;
    if (typeof responses !== "object" || responses === null || Array.isArray(responses)) {
      throw new ProtocolError(ProtocolErrorCode.InvalidParams, "Invalid params for tasks/update: inputResponses is required");
    }
    const task = store.lookup(owner, taskId);
    if (task === undefined || task === "expired") throw notFound("update", task);
    // These tasks never have outstanding inputRequests, so every response is
    // for a key that is not outstanding: ignored, as the spec requires.
    return { resultType: "complete" };
  });

  server.server.setRequestHandler("tasks/cancel", { params: TASK_ID_PARAMS }, async ({ taskId }, ctx) => {
    requireTasksCapability(ctx);
    const outcome = store.cancel(owner, taskId);
    if (outcome !== true) throw notFound("cancel", outcome);
    return { resultType: "complete" };
  });
}
