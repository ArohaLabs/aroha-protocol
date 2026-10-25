// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the shared vectors in docs/vectors/consult-loop.json. The Python SDK
 * runs the same file — see sdks/aroha-py/tests/test_consult.py. If these two
 * suites ever disagree, two Aroha agents disagree about whether a consult
 * chain is legal.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { checkConsultLoop, nextConsultHop, DEFAULT_MAX_CONSULT_HOPS } from "./loop-guard.js";

const vectorsPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "..", "..", "..", "..", "docs", "vectors", "consult-loop.json",
);
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as {
  maxHopsDefault: number;
  checkLoopLimits: Array<{
    name: string; hopCount: number; consultChain: string[]; ownDid: string;
    maxHops: number; expectOk: boolean; expectReasonContains?: string;
  }>;
  nextHop: Array<{
    name: string; hopCount: number; consultChain: string[]; ownDid: string;
    expectHopCount: number; expectChain: string[];
  }>;
};

describe("checkConsultLoop — shared vectors", () => {
  for (const v of vectors.checkLoopLimits) {
    it(v.name, () => {
      const result = checkConsultLoop(
        { hopCount: v.hopCount, consultChain: v.consultChain },
        v.ownDid,
        v.maxHops,
      );
      expect(result.ok).toBe(v.expectOk);
      if (v.expectReasonContains) {
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.reason.toLowerCase()).toContain(v.expectReasonContains.toLowerCase());
        }
      }
    });
  }
});

describe("nextConsultHop — shared vectors", () => {
  for (const v of vectors.nextHop) {
    it(v.name, () => {
      const out = nextConsultHop(v.hopCount, v.consultChain, v.ownDid);
      expect(out.hopCount).toBe(v.expectHopCount);
      expect(out.consultChain).toEqual(v.expectChain);
    });
  }
});

describe("loop guard invariants", () => {
  it("uses the same default the vectors declare", () => {
    expect(DEFAULT_MAX_CONSULT_HOPS).toBe(vectors.maxHopsDefault);
  });

  it("does not mutate the chain it is given", () => {
    const chain = ["did:aroha:zA"];
    nextConsultHop(1, chain, "did:aroha:zB");
    expect(chain).toEqual(["did:aroha:zA"]);
  });
});
