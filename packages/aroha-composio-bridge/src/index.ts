// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Aroha ↔ Composio Bridge
 *
 * Composio is the integration platform behind TrustClaw and many other
 * AI agent frameworks. It exposes "actions" — named, typed functions that
 * LLMs can call. This bridge registers Aroha capabilities as Composio
 * custom actions.
 *
 * TrustClaw, Claude + Composio, GPT-4 + Composio, and any other Composio-
 * connected agent can then call your Aroha agents without knowing the
 * underlying Aroha protocol.
 *
 * Example (trustclaw-setup.ts):
 *
 *   import { Composio } from "composio-core";
 *   import { registerArohaCapabilities } from "@aroha-sdk/composio-bridge";
 *
 *   const composio = new Composio({ apiKey: process.env.COMPOSIO_API_KEY });
 *   await registerArohaCapabilities(composio, [
 *     {
 *       endpoint: "http://travel-agent.aroha-labs.com",
 *       agentDID: "did:aroha:travel-agent",
 *       capabilityId: "search-flights",
 *       description: "Search for available flights between two airports",
 *       callerDID: myDID,
 *       callerPrivateKey: privateKey,
 *     },
 *   ]);
 */

export {
  arohaCapabilityToComposioAction,
  registerArohaCapabilities,
  buildComposioActionHandler,
  type ComposioAction,
  type ComposioActionResult,
  type ArohaComposioOptions,
} from "./bridge.js";
