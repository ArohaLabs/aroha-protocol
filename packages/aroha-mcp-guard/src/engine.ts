// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// GuardEngine — the rule engine behind mcp-guard.
// Pure logic, no I/O: given a tool name, decide allow / block / limit / gate.

export type Decision =
  | { action: "allow" }
  | { action: "block"; reason: string }
  | { action: "limit-exceeded"; reason: string; limit: number }
  | { action: "gate"; reason: string };

export interface GuardRules {
  /** Tool-name globs to always deny. */
  block: string[];
  /** Tool-name globs with a max call count per session: [glob, maxCalls]. */
  limits: Array<[string, number]>;
  /** Tool-name globs requiring human approval before each call. */
  gate: string[];
  /**
   * Tool-name globs requiring human approval ONLY when the call is flagged
   * tainted by the caller (design spec §9.1 Layer 3 — provenance tainting).
   * A call is "tainted" when its arguments may have been influenced by
   * untrusted content (a tool result, a remote agent's reply) rather than
   * directly by the user's own request — the caller decides what counts as
   * tainted and passes it via `decide()`'s second argument; GuardEngine
   * itself has no visibility into content provenance.
   *
   * Distinct from `gate` (always requires approval) so an operator can
   * scope human-in-the-loop friction to the actual risk window instead of
   * gating every call to a sensitive-sounding tool regardless of where its
   * arguments came from. Optional and defaults to empty — omitting it (or
   * never passing `tainted: true`) preserves today's behavior exactly.
   */
  gateIfTainted?: string[];
}

/** Convert a simple glob ("delete_*", "*", "repo?") to an anchored RegExp. */
export function globToRegex(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

/**
 * Parse rule flags of the form used by the CLI:
 *   block: "delete_*,drop_*"          → ["delete_*", "drop_*"]
 *   limit: "create_*:5,send_email:1"  → [["create_*", 5], ["send_email", 1]]
 *   gate:  "merge_*"                  → ["merge_*"]
 */
export function parseRules(opts: {
  block?: string[];
  limit?: string[];
  gate?: string[];
  gateIfTainted?: string[];
}): GuardRules {
  const block = (opts.block ?? []).flatMap((v) => v.split(",")).map((s) => s.trim()).filter(Boolean);
  const gate = (opts.gate ?? []).flatMap((v) => v.split(",")).map((s) => s.trim()).filter(Boolean);
  const gateIfTainted = (opts.gateIfTainted ?? []).flatMap((v) => v.split(",")).map((s) => s.trim()).filter(Boolean);
  const limits: Array<[string, number]> = [];
  for (const entry of (opts.limit ?? []).flatMap((v) => v.split(","))) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const colon = trimmed.lastIndexOf(":");
    if (colon === -1) throw new Error(`--limit entry "${trimmed}" must be <glob>:<count>`);
    const glob = trimmed.slice(0, colon).trim();
    const n = Number(trimmed.slice(colon + 1));
    if (!glob || !Number.isInteger(n) || n < 0) {
      throw new Error(`--limit entry "${trimmed}" must be <glob>:<non-negative integer>`);
    }
    limits.push([glob, n]);
  }
  return { block, limits, gate, gateIfTainted };
}

export class GuardEngine {
  private blockRes: RegExp[];
  private gateRes: RegExp[];
  private gateIfTaintedRes: RegExp[];
  private limitRes: Array<{ re: RegExp; glob: string; max: number }>;
  private counts = new Map<string, number>();

  constructor(rules: GuardRules) {
    this.blockRes = rules.block.map(globToRegex);
    this.gateRes = rules.gate.map(globToRegex);
    this.gateIfTaintedRes = (rules.gateIfTainted ?? []).map(globToRegex);
    this.limitRes = rules.limits.map(([glob, max]) => ({ re: globToRegex(glob), glob, max }));
  }

  /**
   * Decide what to do with a tool call. Precedence: block > limit > gate >
   * gateIfTainted (only when `ctx.tainted` is true) > allow.
   * Limit counters only increment for calls that will actually proceed —
   * callers must invoke recordCall() after a gate is approved.
   *
   * @param ctx.tainted design spec §9.1 Layer 3 — set true when this call's
   *   arguments may have been influenced by untrusted content. Only affects
   *   `gateIfTainted` rules; every other rule ignores it. Omitting it (or
   *   passing false) is identical to calling decide(toolName) as before this
   *   parameter existed.
   */
  decide(toolName: string, ctx?: { tainted?: boolean }): Decision {
    for (const re of this.blockRes) {
      if (re.test(toolName)) {
        return { action: "block", reason: `Tool "${toolName}" is blocked by mcp-guard policy` };
      }
    }
    for (const { re, glob, max } of this.limitRes) {
      if (re.test(toolName)) {
        const used = this.counts.get(glob) ?? 0;
        if (used >= max) {
          return {
            action: "limit-exceeded",
            limit: max,
            reason: `Tool "${toolName}" has reached its session limit (${max} call${max === 1 ? "" : "s"}). This is an mcp-guard hard cap, not a transient error — do not retry.`,
          };
        }
      }
    }
    for (const re of this.gateRes) {
      if (re.test(toolName)) {
        return { action: "gate", reason: `Tool "${toolName}" requires human approval` };
      }
    }
    if (ctx?.tainted) {
      for (const re of this.gateIfTaintedRes) {
        if (re.test(toolName)) {
          return {
            action: "gate",
            reason: `Tool "${toolName}" requires human approval — its arguments may have been influenced by untrusted content (design spec §9.1 Layer 3)`,
          };
        }
      }
    }
    return { action: "allow" };
  }

  /** Record that a call actually went through (increments matching limit counters). */
  recordCall(toolName: string): void {
    for (const { re, glob } of this.limitRes) {
      if (re.test(toolName)) {
        this.counts.set(glob, (this.counts.get(glob) ?? 0) + 1);
      }
    }
  }

  /** Session usage snapshot for the exit receipt. */
  usage(): Record<string, { used: number; max: number }> {
    const out: Record<string, { used: number; max: number }> = {};
    for (const { glob, max } of this.limitRes) {
      out[glob] = { used: this.counts.get(glob) ?? 0, max };
    }
    return out;
  }
}
