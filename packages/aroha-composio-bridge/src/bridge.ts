// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Composio action ↔ Aroha capability adapter.
 *
 * Composio action shape:
 *
 *   interface Action {
 *     name: string;
 *     description: string;
 *     parameters: {
 *       type: "object";
 *       properties: Record<string, { type: string; description: string }>;
 *       required?: string[];
 *     };
 *     execute(params: Record<string, unknown>): Promise<{ data: unknown; error?: string }>;
 *   }
 *
 * This matches both the Composio SDK's CustomAction interface and the
 * OpenAI function-calling format, so the same adapter works with TrustClaw,
 * Claude + Composio, GPT-4 + Composio, and Gemini + Composio.
 */

import {
  ArohaClient,
  buildEnvelope,
  newCorrelationId,
  type ArohaRequestBody,
  type ArohaResponseBody,
} from "@aroha-sdk/core";

// ─── Composio types (duck-typed — peer dep keeps this optional) ───────────────

export interface ComposioActionParameter {
  type: "string" | "number" | "boolean" | "object" | "array";
  description: string;
  enum?: string[];
}

export interface ComposioAction {
  name: string;
  description: string;
  parameters: {
    type: "object";
    properties: Record<string, ComposioActionParameter>;
    required?: string[];
  };
  execute(params: Record<string, unknown>): Promise<ComposioActionResult>;
}

export interface ComposioActionResult {
  data: unknown;
  error?: string;
  successful: boolean;
}

// ─── Options ──────────────────────────────────────────────────────────────────

export interface ArohaComposioOptions {
  /** HTTP endpoint of the remote Aroha agent. */
  endpoint: string;
  /** DID of the remote Aroha agent. */
  agentDID: string;
  /** Capability ID on the remote agent. */
  capabilityId: string;
  /** Human-readable description for the LLM. */
  description: string;
  /** JSON Schema properties for the capability's parameters. */
  parameters?: Record<string, ComposioActionParameter>;
  /** Required parameter names. */
  required?: string[];
  /** DID of the caller (this bridge). */
  callerDID: string;
  /** Ed25519 private key for signing envelopes. */
  callerPrivateKey: Uint8Array;
  client?: ArohaClient;
}

// ─── Aroha capability → Composio action ──────────────────────────────────────

/**
 * Convert a single Aroha capability into a Composio-compatible custom action.
 *
 * The action name is derived from the agent DID + capability ID to avoid
 * collisions when registering multiple agents:
 *   "did:aroha:travel-agent" + "search-flights" → "aroha_travel_agent_search_flights"
 */
export function arohaCapabilityToComposioAction(
  opts: ArohaComposioOptions
): ComposioAction {
  const client = opts.client ?? new ArohaClient();
  const actionName = buildActionName(opts.agentDID, opts.capabilityId);

  return {
    name: actionName,
    description: opts.description,
    parameters: {
      type: "object",
      properties: opts.parameters ?? {},
      required: opts.required,
    },

    async execute(params: Record<string, unknown>): Promise<ComposioActionResult> {
      const correlationId = newCorrelationId();
      const body: ArohaRequestBody = {
        capability: opts.capabilityId,
        params,
      };

      try {
        const envelope = await buildEnvelope(
          "ArohaRequest",
          opts.callerDID,
          opts.agentDID,
          body,
          correlationId,
          opts.callerPrivateKey
        );

        const response = await client.send(opts.endpoint, envelope);

        if (!response) {
          return {
            data: { correlationId, status: "async" },
            successful: true,
          };
        }

        if (response.type === "ArohaError") {
          const err = response.body as { message: string };
          return { data: null, error: err.message, successful: false };
        }

        const result = (response.body as ArohaResponseBody).result;
        return { data: result, successful: true };
      } catch (err) {
        return { data: null, error: String(err), successful: false };
      }
    },
  };
}

// ─── Register multiple capabilities with a Composio instance ─────────────────

/**
 * Register a batch of Aroha capabilities as Composio custom actions.
 *
 * Composio duck-types the registration interface — pass any Composio client
 * that has addCustomAction() or createAction(). Both the official composio-core
 * SDK and the TrustClaw fork accept this shape.
 *
 * @param composio  A Composio client instance with addCustomAction()
 * @param options   Array of capability registrations
 * @returns         The registered Composio action objects
 */
export async function registerArohaCapabilities(
  composio: { addCustomAction?(action: ComposioAction): Promise<void>; createAction?(opts: ComposioAction): Promise<void> },
  options: ArohaComposioOptions[]
): Promise<ComposioAction[]> {
  const actions = options.map(arohaCapabilityToComposioAction);
  const register = composio.addCustomAction?.bind(composio) ?? composio.createAction?.bind(composio);

  if (!register) {
    throw new Error(
      "Composio client must have addCustomAction() or createAction(). " +
      "Check your composio-core version."
    );
  }

  await Promise.all(actions.map(register));
  return actions;
}

/**
 * Build a standalone action handler for frameworks that don't use Composio
 * directly but accept the same action format (e.g. custom tool routers).
 *
 * Returns a map of action name → execute function for quick lookup.
 */
export function buildComposioActionHandler(
  options: ArohaComposioOptions[]
): Map<string, ComposioAction["execute"]> {
  const actions = options.map(arohaCapabilityToComposioAction);
  return new Map(actions.map((a) => [a.name, a.execute.bind(a)]));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildActionName(agentDID: string, capabilityId: string): string {
  // "did:aroha:travel-agent" → "aroha_travel_agent"
  const didSlug = agentDID
    .replace(/^did:[^:]+:/, "")
    .replace(/[^a-zA-Z0-9]/g, "_");
  const capSlug = capabilityId.replace(/[^a-zA-Z0-9]/g, "_");
  return `aroha_${didSlug}_${capSlug}`;
}
