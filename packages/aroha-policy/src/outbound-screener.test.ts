// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the shared vectors in docs/vectors/outbound-redaction.json. The Python
 * SDK runs the same file — see sdks/aroha-py/tests/test_policy.py.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { OutboundScreener, createOutboundScreener } from "./outbound-screener.js";

const vectorsPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "docs", "vectors", "outbound-redaction.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  cases: Array<{
    name: string;
    input: string;
    expectText: string;
    expectRedactions: Array<{ category: string; count: number }>;
  }>;
};

describe("OutboundScreener — shared vectors", () => {
  const screener = createOutboundScreener();

  for (const v of vectors.cases) {
    it(v.name, () => {
      const result = screener.screen(v.input);
      expect(result.text).toBe(v.expectText);
      expect(result.redactions).toEqual(v.expectRedactions);
    });
  }
});

describe("OutboundScreener behaviour", () => {
  const screener = createOutboundScreener();

  it("reports redacted only when something was replaced", () => {
    expect(screener.screen("nothing here").redacted).toBe(false);
    expect(screener.screen("a@b.com").redacted).toBe(true);
  });

  it("never returns the matched value, only the category", () => {
    // The audit log records this object verbatim (design spec §6.2). If a
    // matched value could reach it, the audit trail would become the largest
    // unredacted store of exactly the identifiers we screened out.
    const result = screener.screen("mail dana.k@example.com now");
    const serialised = JSON.stringify(result.redactions);
    expect(serialised).not.toContain("dana");
    expect(serialised).not.toContain("example.com");
  });

  it("accepts extra rules for domain-specific identifiers", () => {
    const screener = new OutboundScreener({
      extraRules: [{ category: "employee_id", pattern: /\bEMP-\d{6}\b/g }],
    });
    const result = screener.screen("see EMP-004512 for details");
    expect(result.text).toBe("see [REDACTED:EMPLOYEE_ID] for details");
    expect(result.redactions).toEqual([{ category: "employee_id", count: 1 }]);
  });
});
