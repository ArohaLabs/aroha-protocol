// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ OpenClaw Bridge
 *
 * OpenClaw is a local personal AI assistant (Node.js/npm) that communicates
 * via Telegram, Discord, WhatsApp, and Slack. It extends via "skills" —
 * modules that register named commands with descriptions.
 *
 * This bridge has two directions:
 *
 *   arohaCapabilityToOpenClawSkill()
 *     — Wraps a remote Aroha capability as an OpenClaw skill.
 *       The personal assistant can then call it by name (e.g. "book-flight")
 *       and Aroha handles identity, signing, and settlement underneath.
 *
 *   openClawSkillToArohaHandler()
 *     — Wraps an existing OpenClaw skill as an Aroha MessageHandler,
 *       so other Aroha agents can call your OpenClaw-registered logic
 *       via signed envelopes.
 *
 * Example (openclaw-plugin.mjs):
 *
 *   import { arohaCapabilityToOpenClawSkill } from "@aroha-sdk/openclaw-bridge";
 *   import { ArohaClient, generateDid, generateKeyPair } from "@aroha-sdk/core";
 *
 *   const { privateKey, publicKey } = await generateKeyPair();
 *   const myDID = generateDid(publicKey);
 *
 *   export default {
 *     name: "aroha-travel",
 *     skills: [
 *       arohaCapabilityToOpenClawSkill("search-flights", {
 *         endpoint: "http://travel-agent.aroha-labs.com",
 *         agentDID: "did:aroha:travel-agent-prod",
 *         callerDID: myDID,
 *         callerPrivateKey: privateKey,
 *         description: "Search and book flights via the Aroha travel agent",
 *       }),
 *     ],
 *   };
 */

export {
  arohaCapabilityToOpenClawSkill,
  openClawSkillToArohaHandler,
  createArohaOpenClawPlugin,
  type OpenClawSkill,
  type OpenClawPlugin,
  type ArohaSkillOptions,
  type OpenClawHandlerOptions,
} from "./bridge.js";
