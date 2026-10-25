// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { type ArohaMessageType } from "@aroha-sdk/core";
import { ArohaRole, type HumanCredential } from "./types.js";

export { ArohaRole } from "./types.js";

// ─── Actions ──────────────────────────────────────────────────────────────────

export type ArohaAction =
  | "query"
  | "reserve"
  | "commit"
  | "cancel"
  | "delegate"
  | "negotiate"
  | "mandate"
  | "admin";

export function actionForMessageType(type: ArohaMessageType): ArohaAction | null {
  switch (type) {
    case "ArohaRequest":
    case "ArohaStream":
      return "query";
    case "ArohaReserve":
      return "reserve";
    case "ArohaCommit":
      return "commit";
    case "ArohaCancel":
      return "cancel";
    case "ArohaDelegate":
      return "delegate";
    case "ArohaNegotiate":
    case "ArohaCounterOffer":
    case "ArohaAccept":
      return "negotiate";
    case "ArohaSpendingMandate":
      return "mandate";
    default:
      return null;
  }
}

// ─── Policy ───────────────────────────────────────────────────────────────────

export type RolePermissions = Partial<Record<ArohaRole, ArohaAction[]>>;

export interface RbacPolicy {
  permissions?: RolePermissions;
  resolveAgentRoles: (agentDID: string) => Promise<ArohaRole[]> | ArohaRole[];
  resolveIssuerPublicKey?: (issuerDID: string) => Promise<Uint8Array | null> | Uint8Array | null;
  credentialRegistry?: {
    resolve(credentialId: string): HumanCredential | null | Promise<HumanCredential | null>;
  };
  /**
   * TESTS AND LOCAL DEVELOPMENT ONLY. Honour the roles on a registry
   * credential (credentialId) without re-verifying its issuer signature when
   * no resolveIssuerPublicKey is configured. Without this flag such a request
   * is refused (401): a registry entry is only as trustworthy as whoever
   * wrote it, and the registry routes accept writes from the network.
   */
  allowUnverifiedCredentials?: boolean;
}

export const DEFAULT_RBAC_PERMISSIONS: RolePermissions = {
  [ArohaRole.HumanAdmin]:        ["query", "reserve", "commit", "cancel", "delegate", "negotiate", "mandate", "admin"],
  [ArohaRole.HumanUser]:         ["query", "reserve", "commit", "cancel", "negotiate", "mandate"],
  [ArohaRole.HumanReadonly]:     ["query"],
  [ArohaRole.AgentOrchestrator]: ["query", "reserve", "commit", "cancel", "delegate", "negotiate", "mandate"],
  [ArohaRole.AgentProvider]:     [],
  [ArohaRole.AgentObserver]:     ["query"],
};

// ─── Permission check ─────────────────────────────────────────────────────────

export interface RbacCheckResult {
  allowed: boolean;
  roles: ArohaRole[];
  reason?: string;
}

export function checkPermission(
  roles: ArohaRole[],
  action: ArohaAction,
  permissions: RolePermissions = DEFAULT_RBAC_PERMISSIONS
): RbacCheckResult {
  if (roles.length === 0) {
    return { allowed: false, roles, reason: "No roles assigned" };
  }
  for (const role of roles) {
    const allowed = permissions[role] ?? [];
    if (allowed.includes("admin") || allowed.includes(action)) {
      return { allowed: true, roles };
    }
  }
  return {
    allowed: false,
    roles,
    reason: `Roles [${roles.join(", ")}] do not permit action "${action}"`,
  };
}
