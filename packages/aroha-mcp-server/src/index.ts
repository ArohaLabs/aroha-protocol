// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @aroha-sdk/mcp-server
 *
 * MCP server that lets Claude, Meta Muse custom connectors, ChatGPT plugins
 * and any other MCP client discover and call agents registered on the Aroha
 * Hub with signed, per-user mandates.
 *
 * Run it with the `aroha-mcp-server` binary (src/cli.ts): stdio by default,
 * `--http` for the Streamable HTTP transport (MCP 2026-07-28) acting as an
 * OAuth 2.1 protected resource, with Enterprise-Managed Authorization (ID-JAG)
 * on the resource-server side and the MCP Tasks extension for aroha_call. This
 * module exports the building blocks for embedding.
 *
 * Tools: aroha_discover, aroha_call, aroha_issue_task_mandate,
 * aroha_issue_spending_mandate, aroha_get_receipt, verify_mandate,
 * revoke_mandate, check_revocation_status, verify_receipt, lookup_kel.
 */

export { loadConfig, decodeSecret, isLoopbackHost, GATEABLE_TOOLS, type ArohaMcpConfigFile, type ResolvedConfig, type TransportMode } from "./config.js";
export { FilePrincipalKeyStore, LOCAL_PRINCIPAL, principalFromToken, type PrincipalKeyStore } from "./keystore.js";
export { loadOrCreateIdentity, defaultIdentityDir, type McpIdentity } from "./identity.js";
export { jwtAccessTokenVerifier, protectedResourceMetadata, isClientIdMetadataDocumentUrl, authorizationServerMetadataUrls, type JwtVerifierOptions } from "./auth.js";
export {
  createArohaMcpServer,
  createRuntime,
  principalFromAuthInfo,
  principalContextFromAuthInfo,
  ReceiptStore,
  APPROVAL_INPUT_KEY,
  SERVER_NAME,
  SERVER_VERSION,
  type ApprovalState,
  type ArohaMcpRuntime,
  type PrincipalContext,
} from "./server.js";
export {
  ENTERPRISE_MANAGED_AUTHORIZATION_EXTENSION,
  DEFAULT_ENTERPRISE_CLAIM,
  ID_JAG_TYP,
  ID_JAG_GRANT_PROFILE,
  ID_JAG_TOKEN_TYPE,
  JWT_BEARER_GRANT,
  readEnterpriseIdentity,
  enterprisePrincipal,
  enterpriseRoot,
  type EnterpriseAuthOptions,
  type EnterpriseIdentity,
  type TrustedIdp,
} from "./enterprise.js";
export { TASKS_EXTENSION, TaskStore, TaskLimitError, taskOwner, type TaskStatus, type TaskStoreOptions, type TaskView } from "./tasks.js";
export { startHttpServer, type HttpServerOptions, type RunningHttpServer } from "./http.js";
