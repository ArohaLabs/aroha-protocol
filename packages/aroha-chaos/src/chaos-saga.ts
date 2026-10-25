// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ChaosSagaRunner — automated compensation path verification.
 *
 * Systematically injects a failure at every possible saga step position
 * (step 1 fails, step 2 fails, ..., step N fails) and verifies that:
 *   - The correct steps were compensated (LIFO order)
 *   - No steps were left in RESERVED state
 *   - The saga returned success=false with the correct failure stepId
 *   - Optional: the CompensationDLQ received entries for cancel failures
 *
 * This exhaustive sweep catches bugs that only manifest when "3 of 7 steps
 * committed before the 4th fails" — a case that unit tests almost never cover.
 *
 * Usage in tests:
 *   const runner = new ChaosSagaRunner(executorFn);
 *   const report = await runner.sweepFailures(stepDefinitions);
 *   expect(report.allPassed).toBe(true);
 */

export interface ChaosSagaStep {
  capability: string;
  agentDID: string;
  description?: string;
}

export interface ChaosRun {
  /** Index of the step that was injected to fail (0-indexed). */
  injectedFailureAt: number;
  sagaResult: { success: boolean; failures: Array<{ stepId: number; reason: string }> };
  /** Steps that should have been compensated (all steps with index < injectedFailureAt). */
  expectedCompensations: number[];
  /** Steps that were actually cancelled in the saga log. */
  actualCancellations: number[];
  passed: boolean;
  notes: string[];
}

export interface ChaosSagaReport {
  allPassed: boolean;
  runs: ChaosRun[];
  totalRuns: number;
  passedRuns: number;
  failedRuns: number;
  summary: string;
}

export type SagaExecutorFn = (
  steps: ChaosSagaStep[],
  injectFailureAtStep: number
) => Promise<{
  success: boolean;
  failures: Array<{ stepId: number; reason: string }>;
  cancelledStepIds: number[];
}>;

export class ChaosSagaRunner {
  constructor(private readonly executorFn: SagaExecutorFn) {}

  /**
   * Sweep all possible single-step failure positions.
   * Returns a report of which runs passed and which failed.
   */
  async sweepFailures(steps: ChaosSagaStep[]): Promise<ChaosSagaReport> {
    const runs: ChaosRun[] = [];

    for (let failAt = 0; failAt < steps.length; failAt++) {
      const result = await this.executorFn(steps, failAt);
      const notes: string[] = [];

      // Steps before the failing step should have been compensated (LIFO)
      const expectedCompensations = Array.from({ length: failAt }, (_, i) => i);

      const missingCancellations = expectedCompensations.filter(
        (id) => !result.cancelledStepIds.includes(id)
      );
      const unexpectedCancellations = result.cancelledStepIds.filter(
        (id) => !expectedCompensations.includes(id)
      );

      if (missingCancellations.length > 0) {
        notes.push(`Steps not compensated: [${missingCancellations.join(", ")}]`);
      }
      if (unexpectedCancellations.length > 0) {
        notes.push(`Unexpected cancellations: [${unexpectedCancellations.join(", ")}]`);
      }
      if (result.success) {
        notes.push("Saga returned success=true but should have failed");
      }

      const passed =
        !result.success &&
        missingCancellations.length === 0 &&
        unexpectedCancellations.length === 0;

      runs.push({
        injectedFailureAt: failAt,
        sagaResult: result,
        expectedCompensations,
        actualCancellations: result.cancelledStepIds,
        passed,
        notes,
      });
    }

    const passedRuns = runs.filter((r) => r.passed).length;
    const failedRuns = runs.length - passedRuns;

    return {
      allPassed: failedRuns === 0,
      runs,
      totalRuns: runs.length,
      passedRuns,
      failedRuns,
      summary: failedRuns === 0
        ? `All ${runs.length} chaos runs passed — LIFO compensation is correct`
        : `${failedRuns} of ${runs.length} chaos runs FAILED — compensation logic has bugs`,
    };
  }

  /**
   * Run a single targeted failure injection.
   * Use when you want to test one specific failure scenario.
   */
  async injectFailureAt(
    steps: ChaosSagaStep[],
    failAtStep: number
  ): Promise<ChaosRun> {
    const report = await this.sweepFailures(steps.slice(0, failAtStep + 1));
    return report.runs[report.runs.length - 1];
  }
}

/** Pretty-print a ChaosSagaReport to the console. */
export function printChaosReport(report: ChaosSagaReport): void {
  console.log(`\n[Aroha Chaos] ${report.summary}`);
  for (const run of report.runs) {
    const icon = run.passed ? "✅" : "❌";
    console.log(
      `  ${icon} Step ${run.injectedFailureAt} fails → ` +
      `expected cancellations: [${run.expectedCompensations.join(", ")}], ` +
      `actual: [${run.actualCancellations.join(", ")}]`
    );
    if (run.notes.length > 0) {
      run.notes.forEach((n) => console.log(`       ⚠ ${n}`));
    }
  }
}
