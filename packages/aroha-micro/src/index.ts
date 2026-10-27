// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export { createAgent, createAgent as createMicroAgent, MicroAgent } from "./agent.js";
export type { MicroAgentOptions, CapabilityHandler } from "./agent.js";
// The type of MicroAgentOptions.resolvePublicKey, re-exported so callers need not import core.
export type { PublicKeyResolver } from "@aroha-sdk/core";
