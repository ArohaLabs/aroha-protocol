// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { checkPermission, actionForMessageType, DEFAULT_RBAC_PERMISSIONS } from "./rbac.js";
import { ArohaRole } from "./types.js";

describe("actionForMessageType", () => {
  it("maps ArohaRequest to query", () => {
    expect(actionForMessageType("ArohaRequest")).toBe("query");
  });
  it("maps ArohaReserve to reserve", () => {
    expect(actionForMessageType("ArohaReserve")).toBe("reserve");
  });
  it("maps ArohaCommit to commit", () => {
    expect(actionForMessageType("ArohaCommit")).toBe("commit");
  });
  it("maps ArohaCancel to cancel", () => {
    expect(actionForMessageType("ArohaCancel")).toBe("cancel");
  });
  it("maps ArohaDelegate to delegate", () => {
    expect(actionForMessageType("ArohaDelegate")).toBe("delegate");
  });
  it("maps ArohaNegotiate to negotiate", () => {
    expect(actionForMessageType("ArohaNegotiate")).toBe("negotiate");
  });
  it("returns null for response/ack types", () => {
    expect(actionForMessageType("ArohaResponse")).toBeNull();
    expect(actionForMessageType("ArohaReserveAck")).toBeNull();
    expect(actionForMessageType("ArohaCommitAck")).toBeNull();
    expect(actionForMessageType("ArohaError")).toBeNull();
  });
});

describe("checkPermission", () => {
  it("allows HumanAdmin all actions", () => {
    const actions = ["query", "reserve", "commit", "cancel", "delegate", "negotiate", "admin"] as const;
    for (const action of actions) {
      const result = checkPermission([ArohaRole.HumanAdmin], action);
      expect(result.allowed).toBe(true);
    }
  });

  it("allows HumanUser to query/reserve/commit/cancel/negotiate but not delegate or admin", () => {
    expect(checkPermission([ArohaRole.HumanUser], "query").allowed).toBe(true);
    expect(checkPermission([ArohaRole.HumanUser], "reserve").allowed).toBe(true);
    expect(checkPermission([ArohaRole.HumanUser], "delegate").allowed).toBe(false);
    expect(checkPermission([ArohaRole.HumanUser], "admin").allowed).toBe(false);
  });

  it("allows HumanReadonly only query", () => {
    expect(checkPermission([ArohaRole.HumanReadonly], "query").allowed).toBe(true);
    expect(checkPermission([ArohaRole.HumanReadonly], "reserve").allowed).toBe(false);
  });

  it("denies AgentProvider all actions", () => {
    expect(checkPermission([ArohaRole.AgentProvider], "query").allowed).toBe(false);
  });

  it("allows AgentOrchestrator to delegate", () => {
    expect(checkPermission([ArohaRole.AgentOrchestrator], "delegate").allowed).toBe(true);
  });

  it("returns false with no roles", () => {
    const result = checkPermission([], "query");
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/No roles/);
  });

  it("unions permissions across multiple roles", () => {
    // HumanReadonly (query only) + AgentOrchestrator (query+reserve+..+delegate) → delegate allowed
    const result = checkPermission([ArohaRole.HumanReadonly, ArohaRole.AgentOrchestrator], "delegate");
    expect(result.allowed).toBe(true);
  });

  it("includes role list in result", () => {
    const result = checkPermission([ArohaRole.HumanUser], "query");
    expect(result.roles).toContain(ArohaRole.HumanUser);
  });
});

describe("ArohaSpendingMandate action mapping", () => {
  it("maps ArohaSpendingMandate to mandate", () => {
    expect(actionForMessageType("ArohaSpendingMandate")).toBe("mandate");
  });

  it("ArohaSatisfactionSignal returns null (private signal, no RBAC)", () => {
    expect(actionForMessageType("ArohaSatisfactionSignal")).toBeNull();
  });
});

describe("mandate action permissions", () => {
  it("allows HumanAdmin to issue mandates", () => {
    expect(checkPermission([ArohaRole.HumanAdmin], "mandate").allowed).toBe(true);
  });

  it("allows HumanUser to issue mandates", () => {
    expect(checkPermission([ArohaRole.HumanUser], "mandate").allowed).toBe(true);
  });

  it("allows AgentOrchestrator to issue mandates", () => {
    expect(checkPermission([ArohaRole.AgentOrchestrator], "mandate").allowed).toBe(true);
  });

  it("denies HumanReadonly from issuing mandates", () => {
    expect(checkPermission([ArohaRole.HumanReadonly], "mandate").allowed).toBe(false);
  });

  it("denies AgentObserver from issuing mandates", () => {
    expect(checkPermission([ArohaRole.AgentObserver], "mandate").allowed).toBe(false);
  });

  it("denies AgentProvider from issuing mandates", () => {
    expect(checkPermission([ArohaRole.AgentProvider], "mandate").allowed).toBe(false);
  });
});
