// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export {
  verifyTaskMandateChain, parseTaskMandateToken, extractEnvelope,
  staticResolver, registryResolver,
  TaskMandateTokenError, assertRootTrustConfigured, checkRootTrust,
  DELEGATION_CONTEXT_KEY, DEFAULT_TASK_CHAIN_MAX_DEPTH,
  type DelegationEnvelope, type ChainVerificationResult, type ChainVerifyOptions,
  type RegistryResolverOptions, type RootTrustOptions,
} from "./chain.js";

export {
  issueDelegation, callDelegated,
  type RootIdentity, type IssueDelegationOptions,
  type CallDelegatedOptions, type DelegatedResponse,
} from "./client.js";

export {
  serveDelegated, publicKeyB64, DelegationError,
  type DelegationOptions, type DelegationIdentity,
  type DelegatedContext, type DelegatedHandler,
  type DelegateTarget, type DelegateOptions, type AssertCapabilityOptions,
} from "./serve-delegated.js";

export { RECEIPT_ARTIFACT_KIND, type TaskReceiptArtifact } from "./receipts.js";

export { ActionCounter, enforceScope, type TaskRequestScope } from "./enforce.js";

export {
  createDelegationMiddleware, getVerifiedMandate,
  type DelegationMiddlewareOptions,
} from "./server-middleware.js";
