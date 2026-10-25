// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha Policy Middleware — mounts the policy engine into ArohaServer.
 *
 * Runs AFTER envelope signature verification, BEFORE the application handler.
 * Policy violations produce a signed ArohaError envelope with code Aroha_FORBIDDEN.
 * The LLM (and any application code) never runs for rejected requests.
 */

import { type ArohaMiddleware, type ArohaRequestBody } from "@aroha-sdk/core";
import { type IPolicyEngine } from "./types.js";

/**
 * Create a ArohaMiddleware that enforces capability policies.
 *
 * Usage:
 *   const engine = new ArohaPolicyEngine();
 *   engine.addPolicy({ capabilityId: "transfer-funds", maxSpendPerCall: { amount: 500, currency: "USD" } });
 *
 *   const server = new ArohaServer({
 *     middleware: [createPolicyMiddleware(engine)],
 *   });
 */
export function createPolicyMiddleware(engine: IPolicyEngine): ArohaMiddleware {
  return async (envelope, reject) => {
    // Only enforce on ArohaRequest and ArohaReserve — these are the entry points
    if (envelope.type !== "ArohaRequest" && envelope.type !== "ArohaReserve") return;

    const body = envelope.body as ArohaRequestBody;
    const capability = body.capability ?? "";
    const params = body.params ?? {};
    const senderDID = envelope.from;

    const result = await engine.evaluate(capability, params, senderDID);

    if (result.outcome === "deny") {
      reject(
        403,
        "Aroha_FORBIDDEN",
        result.reason ?? `Policy violation: ${result.violatedRule ?? "unknown rule"}`
      );
    }
  };
}

/**
 * Create a strict payload middleware that rejects any ArohaRequest whose
 * body contains non-JSON types (functions, undefined values, circular refs)
 * or whose params contain string values longer than maxStringLength.
 *
 * Use this to close the prompt-injection surface: no agent can embed a
 * long free-text prompt inside a structured Aroha parameter.
 */
export function createStructuredPayloadMiddleware(opts: {
  maxStringLength?: number;
  maxParamDepth?: number;
}): ArohaMiddleware {
  const { maxStringLength = 1024, maxParamDepth = 5 } = opts;

  return async (envelope, reject) => {
    if (envelope.type !== "ArohaRequest" && envelope.type !== "ArohaReserve") return;

    const body = envelope.body as ArohaRequestBody;
    const params = body.params ?? {};

    const violation = checkParams(params, maxStringLength, maxParamDepth, 0);
    if (violation) {
      reject(400, "Aroha_INVALID_PARAMS", violation);
    }
  };
}

function checkParams(
  obj: unknown,
  maxLen: number,
  maxDepth: number,
  depth: number
): string | null {
  if (depth > maxDepth) return `Parameter nesting depth exceeds ${maxDepth}`;
  if (typeof obj === "string" && obj.length > maxLen) {
    return `String parameter exceeds max length of ${maxLen} characters`;
  }
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const err = checkParams(item, maxLen, maxDepth, depth + 1);
      if (err) return err;
    }
  } else if (obj !== null && typeof obj === "object") {
    for (const val of Object.values(obj as Record<string, unknown>)) {
      const err = checkParams(val, maxLen, maxDepth, depth + 1);
      if (err) return err;
    }
  }
  return null;
}
