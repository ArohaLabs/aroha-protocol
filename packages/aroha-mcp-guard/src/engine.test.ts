// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { GuardEngine, parseRules, globToRegex } from "./engine.js";
import { createLineParser } from "./proxy.js";

describe("globToRegex", () => {
  it("matches exact names", () => {
    expect(globToRegex("delete_repo").test("delete_repo")).toBe(true);
    expect(globToRegex("delete_repo").test("delete_repository")).toBe(false);
  });

  it("matches wildcards", () => {
    expect(globToRegex("delete_*").test("delete_repo")).toBe(true);
    expect(globToRegex("delete_*").test("delete_")).toBe(true);
    expect(globToRegex("delete_*").test("create_repo")).toBe(false);
    expect(globToRegex("*").test("anything")).toBe(true);
  });

  it("is case-insensitive and escapes regex metachars", () => {
    expect(globToRegex("Delete_*").test("delete_x")).toBe(true);
    expect(globToRegex("a.b").test("a.b")).toBe(true);
    expect(globToRegex("a.b").test("axb")).toBe(false);
  });
});

describe("parseRules", () => {
  it("splits comma-separated globs", () => {
    const rules = parseRules({ block: ["a,b", "c"] });
    expect(rules.block).toEqual(["a", "b", "c"]);
  });

  it("parses limit entries", () => {
    const rules = parseRules({ limit: ["create_*:5,send:1"] });
    expect(rules.limits).toEqual([["create_*", 5], ["send", 1]]);
  });

  it("rejects malformed limits", () => {
    expect(() => parseRules({ limit: ["create_*"] })).toThrow();
    expect(() => parseRules({ limit: ["x:-1"] })).toThrow();
    expect(() => parseRules({ limit: ["x:abc"] })).toThrow();
  });
});

describe("GuardEngine", () => {
  it("allows unmatched tools", () => {
    const e = new GuardEngine(parseRules({ block: ["delete_*"] }));
    expect(e.decide("read_file").action).toBe("allow");
  });

  it("blocks matching tools", () => {
    const e = new GuardEngine(parseRules({ block: ["delete_*,drop_*"] }));
    expect(e.decide("delete_repo").action).toBe("block");
    expect(e.decide("drop_table").action).toBe("block");
  });

  it("enforces session limits only after recordCall", () => {
    const e = new GuardEngine(parseRules({ limit: ["create_*:2"] }));
    expect(e.decide("create_issue").action).toBe("allow");
    e.recordCall("create_issue");
    expect(e.decide("create_issue").action).toBe("allow");
    e.recordCall("create_issue");
    const third = e.decide("create_issue");
    expect(third.action).toBe("limit-exceeded");
  });

  it("shares one counter across tools matching the same glob", () => {
    const e = new GuardEngine(parseRules({ limit: ["create_*:1"] }));
    e.recordCall("create_issue");
    expect(e.decide("create_pr").action).toBe("limit-exceeded");
  });

  it("gates matching tools", () => {
    const e = new GuardEngine(parseRules({ gate: ["merge_*"] }));
    expect(e.decide("merge_pull_request").action).toBe("gate");
  });

  it("applies precedence block > limit > gate", () => {
    const e = new GuardEngine(
      parseRules({ block: ["x"], limit: ["x:5"], gate: ["x"] })
    );
    expect(e.decide("x").action).toBe("block");

    const e2 = new GuardEngine(parseRules({ limit: ["y:0"], gate: ["y"] }));
    expect(e2.decide("y").action).toBe("limit-exceeded");
  });

  it("a zero limit denies immediately", () => {
    const e = new GuardEngine(parseRules({ limit: ["send_email:0"] }));
    expect(e.decide("send_email").action).toBe("limit-exceeded");
  });

  it("reports usage for the receipt", () => {
    const e = new GuardEngine(parseRules({ limit: ["a:3"] }));
    e.recordCall("a");
    e.recordCall("a");
    expect(e.usage()).toEqual({ a: { used: 2, max: 3 } });
  });

  // ─── gateIfTainted (design spec §9.1 Layer 3) ────────────────────────────

  it("allows a gateIfTainted-matched tool when the call is not flagged tainted", () => {
    const e = new GuardEngine(parseRules({ gateIfTainted: ["pay_*"] }));
    expect(e.decide("pay_invoice").action).toBe("allow");
    expect(e.decide("pay_invoice", { tainted: false }).action).toBe("allow");
  });

  it("gates a gateIfTainted-matched tool when the call is flagged tainted", () => {
    const e = new GuardEngine(parseRules({ gateIfTainted: ["pay_*"] }));
    const decision = e.decide("pay_invoice", { tainted: true });
    expect(decision.action).toBe("gate");
  });

  it("tainted has no effect on tools that don't match any gateIfTainted glob", () => {
    const e = new GuardEngine(parseRules({ gateIfTainted: ["pay_*"] }));
    expect(e.decide("read_file", { tainted: true }).action).toBe("allow");
  });

  it("applies precedence block > limit > gate > gateIfTainted", () => {
    const e = new GuardEngine(parseRules({ gate: ["x"], gateIfTainted: ["x"] }));
    // Static gate always wins regardless of taint — gateIfTainted only adds
    // gating for tools that wouldn't otherwise be gated.
    expect(e.decide("x").action).toBe("gate");
    expect(e.decide("x", { tainted: true }).action).toBe("gate");

    const e2 = new GuardEngine(parseRules({ block: ["y"], gateIfTainted: ["y"] }));
    expect(e2.decide("y", { tainted: true }).action).toBe("block");
  });

  it("omitting gateIfTainted entirely preserves pre-existing decide(toolName) behavior", () => {
    const e = new GuardEngine({ block: [], limits: [], gate: [] });
    expect(e.decide("anything").action).toBe("allow");
    expect(e.decide("anything", { tainted: true }).action).toBe("allow");
  });
});

describe("createLineParser", () => {
  it("handles messages split across chunks", () => {
    const seen: string[] = [];
    const parse = createLineParser((msg) => seen.push(msg.method ?? ""));
    parse('{"jsonrpc":"2.0","me');
    parse('thod":"tools/call"}\n{"jsonrpc":"2.0","method":"ping"}\n');
    expect(seen).toEqual(["tools/call", "ping"]);
  });

  it("handles multiple messages in one chunk and CRLF", () => {
    const seen: string[] = [];
    const parse = createLineParser((msg) => seen.push(msg.method ?? ""));
    parse('{"jsonrpc":"2.0","method":"a"}\r\n{"jsonrpc":"2.0","method":"b"}\n');
    expect(seen).toEqual(["a", "b"]);
  });

  it("passes non-JSON lines through without crashing", () => {
    const raws: string[] = [];
    const parse = createLineParser((_msg, raw) => raws.push(raw));
    parse("not json at all\n");
    expect(raws).toEqual(["not json at all"]);
  });
});
