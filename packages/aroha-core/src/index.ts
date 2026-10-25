// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/core — Aroha Protocol Layers 0–3
 *
 * Layer 0: Transport  → ArohaServer, ArohaClient
 * Layer 1: Identity   → generateDID, DIDDocument, issueCredential, verifyCredential
 *          Auth       → issueCredential, verifyCredential, ArohaRole, RbacPolicy, checkPermission
 * Layer 3: Messaging  → buildEnvelope, validateEnvelope, ArohaEnvelope, all message types
 * Crypto:             → signMessage, verifyMessageSignature, encryptBody, decryptBody
 *                     → signCanonical, verifyCanonicalSignature (bare signature, no proof wrapper)
 * Manifest:           → buildAgentManifest, buildMcpManifest, buildSkillManifest, validateManifest
 * Skills:             → defineSkill, SkillRegistry
 * Scheduling:         → LocalScheduler, TriggerConfig
 * Consult:            → ConsultParams, checkConsultLoop, nextConsultHop
 * Action:             → ActionRequestParams, ActionRequestResult, ActionEvidence
 * Receipts:           → signActionReceipt, verifyActionReceipt, requireApprovalIfTainted
 */

export * from "./identity/index.js";
export * from "./crypto/index.js";
export * from "./messages/index.js";
// Node-only (fs) — kept out of the ./messages subpath on purpose.
export * from "./messages/file-nonce-store.js";
export * from "./transport/index.js";
export * from "./capabilities/taxonomy.js";
export * from "./manifest/index.js";
export * from "./skills/index.js";
export * from "./scheduling/index.js";
export * from "./consult/index.js";
export * from "./action/index.js";
export * from "./endpoints/index.js";
export * from "./receipts/index.js";
export * from "./conversation/index.js";
