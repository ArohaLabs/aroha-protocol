// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal scheduler/trigger primitive.
 *
 * An agent manifest's `trigger` field (see ../manifest) was previously inert
 * metadata — nothing in the SDK gave `trigger: "auto"` any actual behavior,
 * so every app wanting "this agent runs itself periodically" had to build
 * that loop from scratch. LocalScheduler is that loop: register a task
 * against a trigger, start it, stop it.
 *
 * Deliberately in-process and dependency-free — no cron-expression parser
 * is bundled here. `{ type: "cron" }` is represented as a config shape so an
 * app can plug in its own cron library (or a host-level cron, e.g. a
 * platform's scheduled-function feature) and still use the same
 * ScheduledTask/trigger vocabulary; LocalScheduler itself only natively
 * *runs* "manual" (call `trigger()` yourself) and "interval" triggers. A
 * full cron engine is a real dependency and failure surface that belongs in
 * an app or a dedicated package, not folded into identity/crypto/messaging
 * core.
 */

export type TriggerConfig =
  | { type: "manual" }
  | { type: "interval"; everyMs: number }
  | { type: "cron"; expression: string };

export interface ScheduledTask {
  id: string;
  trigger: TriggerConfig;
  run: () => Promise<void> | void;
  /** Called if `run` throws — defaults to a no-op (the scheduler stays up either way). */
  onError?: (error: unknown) => void;
}

export class SchedulerError extends Error {}

export class LocalScheduler {
  private readonly tasks = new Map<string, ScheduledTask>();
  private readonly timers = new Map<string, ReturnType<typeof setInterval>>();

  /**
   * Register a task. "interval" triggers start running immediately;
   * "manual" and "cron" tasks are registered but only run when you call
   * `trigger(id)` yourself (cron scheduling being external, per the module
   * doc comment above).
   */
  schedule(task: ScheduledTask): void {
    if (this.tasks.has(task.id)) {
      throw new SchedulerError(`Task "${task.id}" is already scheduled`);
    }
    this.tasks.set(task.id, task);

    if (task.trigger.type === "interval") {
      const timer = setInterval(() => void this.runTask(task), task.trigger.everyMs);
      this.timers.set(task.id, timer);
    }
  }

  /** Run a registered task once, right now, regardless of its trigger type. */
  async trigger(id: string): Promise<void> {
    const task = this.tasks.get(id);
    if (!task) throw new SchedulerError(`No task scheduled with id "${id}"`);
    await this.runTask(task);
  }

  private async runTask(task: ScheduledTask): Promise<void> {
    try {
      await task.run();
    } catch (error) {
      task.onError?.(error);
    }
  }

  /** Stop a task's interval timer (if it has one) and unregister it. */
  stop(id: string): void {
    const timer = this.timers.get(id);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(id);
    }
    this.tasks.delete(id);
  }

  /** Stop every task and clear the scheduler. */
  stopAll(): void {
    for (const id of [...this.tasks.keys()]) this.stop(id);
  }

  list(): ScheduledTask[] {
    return [...this.tasks.values()];
  }
}
