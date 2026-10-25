// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * SpeculativeExecutor — parallel fan-out, first valid response wins.
 *
 * Sends the same request to N agents simultaneously. Uses the first successful
 * response and cancels all others. Dramatically improves both latency (pick the
 * fastest, not a random one) and reliability (1 - (1-p)^N instead of p).
 *
 * Reliability comparison:
 *   N=1, p=0.95 → 95.0%
 *   N=2, p=0.95 → 99.75%
 *   N=3, p=0.95 → 99.99%
 *
 * Tradeoff: wasted capacity on losing agents. Use on critical saga steps only.
 */

export interface SpeculativeResult<T> {
  result: T;
  winnerIndex: number;
  latencyMs: number;
}

export class SpeculativeExecutor {
  /**
   * Execute fn across all candidates in parallel.
   * Returns the first successful result. Cancels in-flight operations
   * for all other candidates via AbortController.
   *
   * @param candidates  Array of items to fan out across
   * @param fn          Called with each candidate and an AbortSignal.
   *                    Must respect signal.aborted for early cancellation.
   * @param timeoutMs   Overall timeout before all are considered failed. Default: 10_000
   */
  static async race<C, T>(
    candidates: C[],
    fn: (candidate: C, signal: AbortSignal) => Promise<T>,
    timeoutMs = 10_000
  ): Promise<SpeculativeResult<T>> {
    if (candidates.length === 0) {
      throw new Error("SpeculativeExecutor.race: no candidates provided");
    }

    const controllers = candidates.map(() => new AbortController());
    const start = Date.now();

    const promises = candidates.map((candidate, i) =>
      fn(candidate, controllers[i].signal)
        .then((result) => ({ result, index: i }))
    );

    // Separate timeout from Promise.any so that "all candidates fail" rejects
    // immediately (via AggregateError from Promise.any) instead of waiting for timeout.
    let timeoutId: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(
        () => reject(new Error(`Speculative execution timed out after ${timeoutMs}ms`)),
        timeoutMs
      );
    });

    try {
      const winner = await Promise.race([Promise.any(promises), timeoutPromise]);
      clearTimeout(timeoutId!);
      const latencyMs = Date.now() - start;

      // Cancel all losers
      for (let i = 0; i < controllers.length; i++) {
        if (i !== winner.index) controllers[i].abort();
      }

      return { result: winner.result, winnerIndex: winner.index, latencyMs };
    } catch (err) {
      clearTimeout(timeoutId!);
      controllers.forEach((c) => c.abort());
      if (err instanceof AggregateError) {
        throw new Error(
          `All ${candidates.length} speculative candidates failed. ` +
          `First error: ${err.errors[0]?.message ?? err.errors[0]}`
        );
      }
      throw err;
    }
  }
}
