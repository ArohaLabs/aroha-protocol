// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Priority Bulkhead — bounded concurrency with priority ordering.
 *
 * Extends the standard Bulkhead with a min-heap priority queue.
 * Lower priority number = higher importance (runs first).
 *
 *   priority 0 → payment confirmations, saga commits
 *   priority 5 → standard capability requests
 *   priority 10 → background enrichment, read-only lookups
 *
 * When the agent is at capacity, high-priority requests (low number) jump
 * ahead of low-priority requests (high number) in the queue, ensuring
 * critical saga steps get capacity before background work.
 */

export interface PriorityBulkheadConfig {
  /** Maximum concurrent operations. Default: 10 */
  maxConcurrent?: number;
  /** Maximum queued operations (across all priorities). Default: 50 */
  maxQueue?: number;
}

interface QueueItem {
  priority: number;
  resolve: () => void;
}

export class PriorityBulkhead {
  private readonly maxConcurrent: number;
  private readonly maxQueue: number;
  private running = 0;
  private readonly heap: QueueItem[] = [];

  constructor(config: PriorityBulkheadConfig = {}) {
    this.maxConcurrent = config.maxConcurrent ?? 10;
    this.maxQueue      = config.maxQueue      ?? 50;
  }

  /**
   * Execute fn when a concurrency slot is available.
   * Lower priority number = runs sooner when queue is contested.
   *
   * @param fn        The async operation to execute
   * @param priority  Execution priority (0 = highest, 10 = lowest). Default: 5
   */
  async execute<T>(fn: () => Promise<T>, priority = 5): Promise<T> {
    if (this.running >= this.maxConcurrent) {
      if (this.heap.length >= this.maxQueue) {
        throw new PriorityBulkheadRejectedError(this.maxConcurrent, this.maxQueue);
      }
      await new Promise<void>((resolve) => {
        heapPush(this.heap, { priority, resolve });
      });
    }

    this.running++;
    try {
      return await fn();
    } finally {
      this.running--;
      const next = heapPop(this.heap);
      if (next) next.resolve();
    }
  }

  get stats(): { running: number; queued: number } {
    return { running: this.running, queued: this.heap.length };
  }
}

export class PriorityBulkheadRejectedError extends Error {
  constructor(maxConcurrent: number, maxQueue: number) {
    super(
      `PriorityBulkhead full: ${maxConcurrent} concurrent + ${maxQueue} queued. Request rejected.`
    );
    this.name = "PriorityBulkheadRejectedError";
  }
}

// ─── Min-heap helpers (priority queue, no external dep) ──────────────────────

function heapPush(heap: QueueItem[], item: QueueItem): void {
  heap.push(item);
  siftUp(heap, heap.length - 1);
}

function heapPop(heap: QueueItem[]): QueueItem | undefined {
  if (heap.length === 0) return undefined;
  const top = heap[0];
  const last = heap.pop()!;
  if (heap.length > 0) {
    heap[0] = last;
    siftDown(heap, 0);
  }
  return top;
}

function siftUp(heap: QueueItem[], i: number): void {
  while (i > 0) {
    const parent = (i - 1) >> 1;
    if (heap[parent].priority <= heap[i].priority) break;
    [heap[parent], heap[i]] = [heap[i], heap[parent]];
    i = parent;
  }
}

function siftDown(heap: QueueItem[], i: number): void {
  const n = heap.length;
  while (true) {
    let smallest = i;
    const left = 2 * i + 1;
    const right = 2 * i + 2;
    if (left < n && heap[left].priority < heap[smallest].priority) smallest = left;
    if (right < n && heap[right].priority < heap[smallest].priority) smallest = right;
    if (smallest === i) break;
    [heap[i], heap[smallest]] = [heap[smallest], heap[i]];
    i = smallest;
  }
}
