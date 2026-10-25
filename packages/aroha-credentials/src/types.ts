// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

export enum ArohaRole {
  HumanAdmin        = "human:admin",
  HumanUser         = "human:user",
  HumanReadonly     = "human:readonly",
  AgentOrchestrator = "agent:orchestrator",
  AgentProvider     = "agent:provider",
  AgentObserver     = "agent:observer",
}

export interface HumanCredential {
  credentialId: string;
  userId: string;
  email?: string;
  roles: ArohaRole[];
  issuedAt: string;
  expiresAt: string;
  issuerDID: string;
  signature: string;
}
