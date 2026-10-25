// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * OpenClaw skill ↔ Aroha capability adapter.
 *
 * OpenClaw skill shape (duck-typed from openclaw source):
 *
 *   interface Skill {
 *     name: string;           // slash-command or natural language intent
 *     description: string;    // shown to the LLM to decide when to call this
 *     parameters?: Record<string, { type: string; description: string; required?: boolean }>;
 *     execute(params: Record<string, unknown>, context: SkillContext): Promise<string>;
 *   }
 *
 *   interface SkillContext {
 *     userId: string;
 *     channel: string;        // "telegram" | "discord" | "slack" | "whatsapp"
 *     reply(text: string): Promise<void>;
 *   }
 *
 * OpenClaw plugin shape:
 *
 *   interface Plugin {
 *     name: string;
 *     version?: string;
 *     skills: Skill[];
 *     onLoad?(): Promise<void>;
 *     onUnload?(): Promise<void>;
 *   }
 */

import {
  ArohaClient,
  buildEnvelope,
  newCorrelationId,
  type ArohaRequestBody,
  type ArohaResponseBody,
  type MessageHandler,
  ArohaServer,
  type ArohaServerOptions,
} from "@aroha-sdk/core";

// ─── OpenClaw types (duck-typed) ──────────────────────────────────────────────

export interface OpenClawSkillContext {
  userId: string;
  channel: "telegram" | "discord" | "slack" | "whatsapp" | "signal" | string;
  reply(text: string): Promise<void>;
}

export interface OpenClawSkill {
  name: string;
  description: string;
  parameters?: Record<string, {
    type: "string" | "number" | "boolean" | "object";
    description: string;
    required?: boolean;
  }>;
  execute(params: Record<string, unknown>, context: OpenClawSkillContext): Promise<string>;
}

export interface OpenClawPlugin {
  name: string;
  version?: string;
  skills: OpenClawSkill[];
  onLoad?(): Promise<void>;
  onUnload?(): Promise<void>;
}

// ─── Options ──────────────────────────────────────────────────────────────────

export interface ArohaSkillOptions {
  /** HTTP endpoint of the remote Aroha agent. */
  endpoint: string;
  /** DID of the remote Aroha agent. */
  agentDID: string;
  /** DID of this OpenClaw plugin acting as a caller. */
  callerDID: string;
  /** Ed25519 private key for signing envelopes. */
  callerPrivateKey: Uint8Array;
  /** Human-readable description used by the LLM to decide when to call this skill. */
  description: string;
  /** JSON Schema properties for the skill's parameters. */
  parameters?: OpenClawSkill["parameters"];
  client?: ArohaClient;
}

// ─── Aroha capability → OpenClaw skill ───────────────────────────────────────

/**
 * Wrap a remote Aroha capability as an OpenClaw skill.
 *
 * When OpenClaw's LLM decides to call this skill, it sends a signed
 * ArohaRequest to the remote agent and returns the result as a string
 * that OpenClaw can relay back to the user via their chat channel.
 */
export function arohaCapabilityToOpenClawSkill(
  capabilityId: string,
  opts: ArohaSkillOptions
): OpenClawSkill {
  const client = opts.client ?? new ArohaClient();

  return {
    name: capabilityId,
    description: opts.description,
    parameters: opts.parameters,

    async execute(
      params: Record<string, unknown>,
      context: OpenClawSkillContext
    ): Promise<string> {
      const correlationId = newCorrelationId();
      const body: ArohaRequestBody = { capability: capabilityId, params };

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
        return `The Aroha agent is processing your request asynchronously (correlation: ${correlationId}).`;
      }

      if (response.type === "ArohaError") {
        const err = response.body as { message: string };
        throw new Error(`Aroha agent error: ${err.message}`);
      }

      const result = (response.body as ArohaResponseBody).result;
      return typeof result === "string"
        ? result
        : JSON.stringify(result, null, 2);
    },
  };
}

// ─── OpenClaw skill → Aroha handler ──────────────────────────────────────────

export interface OpenClawHandlerOptions {
  /** DID of the Aroha agent serving this skill. Replies are sent `from` this DID. */
  agentDID: string;
  /** Ed25519 private key (32 bytes) of `agentDID`. Every reply is signed with it. */
  agentPrivateKey: Uint8Array;
  /** Verification method id for the reply proof. Defaults to `${agentDID}#key-1`. */
  keyId?: string;
}

/**
 * Wrap an OpenClaw skill as an Aroha MessageHandler.
 *
 * This lets other Aroha agents call your OpenClaw-registered logic via signed
 * envelopes. The skill's execute() is called with a synthetic context that
 * maps the Aroha caller DID to a userId and "aroha" as the channel.
 *
 * Every reply (ArohaResponse or ArohaError) is a signed envelope built with
 * `buildEnvelope` from `@aroha-sdk/core`, so callers can verify it against
 * the serving agent's key. The serving identity is required: the function
 * throws if `agentDID` or `agentPrivateKey` is missing or malformed.
 */
export function openClawSkillToArohaHandler(
  skill: OpenClawSkill,
  opts: OpenClawHandlerOptions
): MessageHandler {
  if (!opts || typeof opts.agentDID !== "string" || !opts.agentDID.startsWith("did:")) {
    throw new Error(
      "openClawSkillToArohaHandler: opts.agentDID (the serving agent's DID) is required — replies are signed envelopes sent from this DID"
    );
  }
  if (!(opts.agentPrivateKey instanceof Uint8Array) || opts.agentPrivateKey.length !== 32) {
    throw new Error(
      "openClawSkillToArohaHandler: opts.agentPrivateKey (32-byte Ed25519 private key for opts.agentDID) is required — replies are signed with it"
    );
  }
  const envelopeOptions = { keyId: opts.keyId ?? `${opts.agentDID}#key-1` };

  return async (envelope, respond) => {
    if (envelope.type !== "ArohaRequest") return;

    const body = envelope.body as ArohaRequestBody;
    if (body.capability !== skill.name) return;

    const synthContext: OpenClawSkillContext = {
      userId: envelope.from,
      channel: "aroha",
      reply: async () => { /* no-op in Aroha mode */ },
    };

    let rawResult: string;
    try {
      rawResult = await skill.execute(body.params as Record<string, unknown>, synthContext);
    } catch (err) {
      const errEnvelope = await buildEnvelope(
        "ArohaError",
        opts.agentDID,
        envelope.from,
        {
          code: "SKILL_ERROR" as never,
          message: String(err),
          retryable: false,
        },
        envelope.correlationId,
        opts.agentPrivateKey,
        envelopeOptions
      );
      respond(errEnvelope);
      return;
    }

    let result: Record<string, unknown>;
    try { result = JSON.parse(rawResult); } catch { result = { output: rawResult }; }

    const replyBody: ArohaResponseBody = { capability: body.capability, result };
    const reply = await buildEnvelope(
      "ArohaResponse",
      opts.agentDID,
      envelope.from,
      replyBody,
      envelope.correlationId,
      opts.agentPrivateKey,
      envelopeOptions
    );
    respond(reply);
  };
}

// ─── Convenience: bundle many capabilities into a plugin ──────────────────────

/**
 * Create a complete OpenClaw plugin that exposes multiple Aroha capabilities
 * as skills under a single plugin name.
 *
 * @example
 * export default createArohaOpenClawPlugin("aroha-travel", [
 *   { capabilityId: "search-flights", description: "...", ...opts },
 *   { capabilityId: "book-hotel",     description: "...", ...opts },
 * ]);
 */
export function createArohaOpenClawPlugin(
  pluginName: string,
  capabilities: Array<{ capabilityId: string } & ArohaSkillOptions>
): OpenClawPlugin {
  return {
    name: pluginName,
    version: "1.0.0",
    skills: capabilities.map(({ capabilityId, ...opts }) =>
      arohaCapabilityToOpenClawSkill(capabilityId, opts)
    ),
  };
}
