// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// serveDelegated() — the turnkey node of a multi-hop agent web.
//
// Wraps @aroha-sdk/run's serve() so that:
//   • every incoming /v1/run request must carry a VERIFIED mandate chain
//     (rejected with 400 before the handler runs — fail closed),
//   • with `requestScope`, the leaf mandate's constraints (allowed/blocked,
//     actionLimits, dataAccess, reversibleOnly, humanGates) are enforced
//     against what the request does, also before the handler runs; and
//     ctx.assertCapability / ctx.assertDataAccess enforce them per action,
//   • the handler receives ctx.mandate (its verified authority) and
//     ctx.delegate(), which attenuates that authority and calls the next
//     agent with the extended chain — depth enforced, correlationId
//     propagated, blocked list carried forward,
//   • a TaskReceipt is built automatically and returned as a response
//     artifact, with downstream receipts stitched in as children.
//
// A → B → (C, D) becomes a few lines per node instead of a custom
// verify/attenuate/call pipeline in every one.

import * as ed from "@noble/ed25519";
import type { ArohaTaskMandateBody, TaskConstraints } from "@aroha-sdk/core";
import type { KelSource, KelStore } from "@aroha-sdk/core/identity";
import {
  attenuateTaskMandate, TaskReceiptBuilder, checkTaskDataAccess,
  type MandateRevocationCheck, type TaskConstraintViolation,
} from "@aroha-sdk/credentials";
import {
  serve, resolveAgent,
  type ArohaAgent, type ServeOptions, type HandlerContext,
  type RunEvent, type ApprovalDecision, type RunRequest,
} from "@aroha-sdk/run";
import {
  verifyTaskMandateChain, parseTaskMandateToken, extractEnvelope,
  assertRootTrustConfigured, checkRootTrust,
  DELEGATION_CONTEXT_KEY, DEFAULT_TASK_CHAIN_MAX_DEPTH,
  type DelegationEnvelope, type ChainVerificationResult,
} from "./chain.js";
import { ActionCounter, enforceScope, type TaskRequestScope } from "./enforce.js";
import { callDelegated, type DelegatedResponse } from "./client.js";
import { RECEIPT_ARTIFACT_KIND, type TaskReceiptArtifact } from "./receipts.js";

// ── Errors ────────────────────────────────────────────────────────────────────

export class DelegationError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "NO_MANDATE"
      | "CHAIN_INVALID"
      | "CAPABILITY_NOT_PERMITTED"
      | "DELEGATION_DEPTH_EXCEEDED"
      | "TARGET_UNRESOLVED"
      | "ACTION_LIMIT_EXCEEDED"
      | "DATA_ACCESS_VIOLATION"
      | "REVERSIBILITY_VIOLATION"
      | "HUMAN_GATE_REQUIRED"
      | "CONSTRAINT_VIOLATION"
  ) {
    super(message);
    this.name = "DelegationError";
  }
}

// ── Options & context types ───────────────────────────────────────────────────

export interface DelegationIdentity {
  /** This agent's DID — incoming leaf mandates must be granted to it. */
  did: string;
  /** This agent's Ed25519 private key — signs the child mandates it issues. */
  privateKey: Uint8Array;
}

export interface DelegationOptions {
  identity: DelegationIdentity;
  /**
   * Root issuers this agent trusts, DID → raw/base64 Ed25519 public key.
   * The envelope's rootKeyB64 must match the entry for the root grantor's DID.
   * One of trustAnchors / resolveRootKey is REQUIRED (serveDelegated throws
   * otherwise) unless allowUnpinnedRoot is set. WHY: without a pinned root
   * the check reduces to "consistent", not "trusted" — any caller can sign
   * its own root mandate.
   */
  trustAnchors?: Record<string, Uint8Array | string>;
  /** Resolves a root grantor DID to its public key, for grantors not in trustAnchors. */
  resolveRootKey?: (grantorDid: string) => Promise<Uint8Array | null>;
  /** DEVELOPMENT ONLY: trust whatever root key the envelope carries. */
  allowUnpinnedRoot?: boolean;
  /** Resolves intermediate signer DIDs → public keys (chains longer than 1 hop). */
  resolvePublicKey?: (did: string) => Promise<Uint8Array | null>;
  /** Reject requests without a valid chain. Default: true. */
  require?: boolean;
  registryUrl?: string;
  /** DEVELOPMENT ONLY: let ctx.delegate() call http:// endpoints on non-loopback hosts. */
  allowInsecureHttp?: boolean;
  /**
   * Task-mandate revocation hook, consulted for every link of every incoming
   * chain with (mandateId, grantor). A hook that throws rejects the request.
   */
  isRevoked?: MandateRevocationCheck;
  /** Key Event Log source: E-DID grantors are checked against their current key, revoked identities refused. */
  kelSource?: KelSource;
  /** Highest-seen KEL memory, used with kelSource. */
  kelStore?: KelStore;
  /** Maximum chain length accepted (and produced by ctx.delegate). Default 8. */
  maxDepth?: number;
  /**
   * Describe what a request does — the capability it invokes and the data it
   * touches — so the leaf mandate's constraints are enforced BEFORE the
   * handler runs (rejected with 400 otherwise). Derived by YOUR code from
   * the request, never taken from a caller's claim about itself. Returning
   * null or undefined rejects the request (an undescribable request is not
   * admitted). A static scope serves single-capability agents.
   *
   * Without it, only ctx.assertCapability / ctx.assertDataAccess inside the
   * handler enforce the constraints — which depends on the handler calling
   * them. Set it on any agent whose mandates carry dataAccess, actionLimits,
   * reversibleOnly or humanGates.
   */
  requestScope?: TaskRequestScope | ((req: RunRequest) => TaskRequestScope | null | undefined | Promise<TaskRequestScope | null | undefined>);
}

/** Options for ctx.assertCapability: what this ONE action does. */
export interface AssertCapabilityOptions {
  /** Data the action touches, resource → access. Checked against the leaf's dataAccess. */
  dataAccess?: Record<string, "read" | "write" | "read-write">;
  /** Reversibility of the action. Omitted = "irreversible" (refused under reversibleOnly). */
  reversibility?: "full" | "semi" | "irreversible";
  /**
   * The decision returned by ctx.requestApproval for this action. Only a
   * decision of "approve" opens a humanGate; "edit", "respond" and "reject"
   * do not.
   */
  approval?: ApprovalDecision;
}

export interface DelegateTarget {
  /** Direct endpoint (http/https). Requires `did` for the child grant. */
  endpoint?: string;
  /** Registry didHash — endpoint and DID are resolved from the Hub. */
  didHash?: string;
  /** Grantee DID. Required with `endpoint`; inferred from the registry with `didHash`. */
  did?: string;
}

export interface DelegateOptions {
  /** Capabilities granted downstream — must be a subset of this agent's own. */
  allowed: string[];
  constraints?: TaskConstraints;
  ttlMs?: number;
  sessionId?: string;
  bearerToken?: string;
}

export interface DelegatedContext extends HandlerContext {
  /** The verified leaf mandate granted to this agent. Undefined only when require:false and no chain arrived. */
  mandate?: ArohaTaskMandateBody;
  /** Hops from the root issuer (1 = called directly by the root). */
  chainDepth: number;
  /** End-to-end trace ID, propagated unchanged across every hop. */
  correlationId?: string;
  /**
   * Throws a DelegationError unless `cap` is within the leaf mandate:
   * allowed and not blocked (CAPABILITY_NOT_PERMITTED), within actionLimits
   * (ACTION_LIMIT_EXCEEDED — each call counts one use, except the first call
   * for the capability the request was admitted for under requestScope),
   * reversible when reversibleOnly is set (REVERSIBILITY_VIOLATION), approved
   * when gated (HUMAN_GATE_REQUIRED), and within dataAccess for the data
   * declared in `opts` (DATA_ACCESS_VIOLATION).
   */
  assertCapability(cap: string, opts?: AssertCapabilityOptions): void;
  /**
   * Throws DATA_ACCESS_VIOLATION unless the leaf mandate's dataAccess grants
   * `access` on `resource`. Does not consume an action.
   */
  assertDataAccess(resource: string, access: "read" | "write" | "read-write"): void;
  /** Attenuate this agent's mandate and call the next agent with the extended chain. */
  delegate(target: DelegateTarget | string, message: string, opts: DelegateOptions): Promise<DelegatedResponse>;
  /** Record an action on this hop's receipt (delegations are recorded automatically). */
  recordAction(capability: string, status?: "success" | "failed" | "skipped"): void;
}

export type DelegatedHandler =
  | ((ctx: DelegatedContext) => string | Promise<string>)
  | ((ctx: DelegatedContext) => AsyncGenerator<string | RunEvent, void, ApprovalDecision | undefined>);

// ── Implementation ────────────────────────────────────────────────────────────

function isAsyncGen(fn: DelegatedHandler): fn is (
  ctx: DelegatedContext
) => AsyncGenerator<string | RunEvent, void, ApprovalDecision | undefined> {
  return fn.constructor.name === "AsyncGeneratorFunction";
}

interface Verified {
  envelope: DelegationEnvelope;
  result: ChainVerificationResult;
}

export function serveDelegated(
  name: string,
  delegation: DelegationOptions,
  handler: DelegatedHandler,
  serveOptions: ServeOptions = {}
): ArohaAgent {
  const { identity, resolvePublicKey, require = true } = delegation;
  assertRootTrustConfigured(delegation, `serveDelegated("${name}")`);
  const maxDepth = delegation.maxDepth ?? DEFAULT_TASK_CHAIN_MAX_DEPTH;
  const counter = new ActionCounter();

  async function scopeOf(req: RunRequest): Promise<TaskRequestScope | null> {
    const s = delegation.requestScope;
    if (s === undefined) return null;
    const scope = typeof s === "function" ? await s(req) : s;
    return scope ?? null;
  }

  // Verification results shared between the contentGuard (which rejects) and
  // the handler wrapper (which builds the context) — keyed by leaf token.
  const verified = new Map<string, Verified>();
  const remember = (key: string, value: Verified) => {
    if (verified.size > 200) {
      const first = verified.keys().next().value;
      if (first !== undefined) verified.delete(first);
    }
    verified.set(key, value);
  };

  async function verifyRequest(req: RunRequest): Promise<{ ok: boolean; reason?: string; v?: Verified }> {
    const envelope = extractEnvelope(req.context);
    if (!envelope) {
      return require
        ? { ok: false, reason: "Missing delegation envelope (context.aroha) — this agent requires a mandate chain" }
        : { ok: true };
    }

    // Pin the root key to the configured root of trust.
    let rootGrantor: string;
    try {
      rootGrantor = parseTaskMandateToken(envelope.chain[0]).mandate.grantor;
    } catch {
      return { ok: false, reason: "Malformed root mandate token" };
    }
    const untrusted = await checkRootTrust(rootGrantor, envelope.rootKeyB64, delegation);
    if (untrusted) return { ok: false, reason: untrusted };

    const result = await verifyTaskMandateChain(
      envelope.chain,
      new Uint8Array(Buffer.from(envelope.rootKeyB64, "base64")),
      {
        expectedGrantee: identity.did, resolvePublicKey,
        isRevoked: delegation.isRevoked, kelSource: delegation.kelSource, kelStore: delegation.kelStore, maxDepth,
      }
    );
    if (!result.valid) return { ok: false, reason: `Mandate chain rejected: ${result.reason}` };

    const v: Verified = { envelope, result };
    remember(envelope.chain[envelope.chain.length - 1], v);
    return { ok: true, v };
  }

  // ── Guard: reject bad chains with 400 before the handler ever runs ─────────
  const userGuard = serveOptions.contentGuard;
  const contentGuard: ServeOptions["contentGuard"] = async (req) => {
    const check = await verifyRequest(req);
    if (!check.ok) return { blocked: true, reason: check.reason };

    // Enforce the leaf's constraints against what this request does, before
    // the handler runs. A request whose scope cannot be determined is not
    // admitted: "we could not tell what it does" is not "it is in scope".
    if (delegation.requestScope !== undefined && check.v) {
      let scope: TaskRequestScope | null;
      try {
        scope = await scopeOf(req);
      } catch (err) {
        return { blocked: true, reason: `Could not determine the request scope: ${(err as Error).message}` };
      }
      if (!scope) return { blocked: true, reason: "Request scope could not be determined; refusing to run outside the mandate" };
      const violation = enforceScope(check.v.result.mandates!, scope, counter);
      if (violation) return { blocked: true, reason: `Mandate constraint violated: ${violation.message}` };
    }

    if (userGuard) return userGuard(req);
    return { blocked: false };
  };

  // ── Handler wrapper: build DelegatedContext, drive the user handler, stitch receipts ──
  async function* wrapped(ctx: HandlerContext): AsyncGenerator<string | RunEvent, void, ApprovalDecision | undefined> {
    const envelope = extractEnvelope(ctx.context);
    let v: Verified | undefined;
    if (envelope) {
      const leafToken = envelope.chain[envelope.chain.length - 1];
      v = verified.get(leafToken);
      if (!v) {
        // Guard populated the cache in the same request; this path only fires
        // if the entry was evicted under load — verify again, fail closed.
        const check = await verifyRequest(ctx);
        if (!check.ok || !check.v) {
          yield { type: "error", requestId: "delegation", message: check.reason ?? "Mandate chain rejected" };
          return;
        }
        v = check.v;
      }
    }

    const mandate = v?.result.mandate;
    const childArtifacts: TaskReceiptArtifact[] = [];
    const receipt = mandate
      ? new TaskReceiptBuilder(
          mandate.mandateId,
          v!.envelope.correlationId,
          identity.did,
          mandate.grantor
        )
      : null;
    let violated = false;

    // The capability the request-level check already counted, if any: its
    // first assertion inside the handler must not be counted a second time.
    let prepaid: string | null = null;
    if (mandate && delegation.requestScope !== undefined) {
      try {
        prepaid = (await scopeOf(ctx))?.capability ?? null;
      } catch {
        prepaid = null;
      }
    }

    const chainMandates = v?.result.mandates ?? (mandate ? [mandate] : []);
    const fail = (violation: TaskConstraintViolation): never => {
      receipt?.recordViolation(violation.message);
      violated = true;
      throw new DelegationError(violation.message, toDelegationCode(violation.code));
    };

    const assertCapability = (cap: string, opts: AssertCapabilityOptions = {}): void => {
      if (!mandate) throw new DelegationError("No mandate on this request", "NO_MANDATE");
      const isPrepaid = prepaid === cap;
      const violation = enforceScope(chainMandates, {
        capability: cap,
        dataAccess: opts.dataAccess,
        reversibility: opts.reversibility,
        humanApproved: opts.approval?.decision === "approve",
      }, counter, isPrepaid);
      if (violation) fail(violation);
      if (isPrepaid) prepaid = null;
    };

    const assertDataAccess = (resource: string, access: "read" | "write" | "read-write"): void => {
      if (!mandate) throw new DelegationError("No mandate on this request", "NO_MANDATE");
      // The same dataAccess rule as checkTaskConstraints, without the
      // capability rules: reading data is not itself a capability invocation.
      const violation = checkTaskDataAccess(mandate.taskConstraints, { [resource]: access });
      if (violation) fail(violation);
    };

    const delegate = async (
      target: DelegateTarget | string,
      message: string,
      opts: DelegateOptions
    ): Promise<DelegatedResponse> => {
      if (!mandate || !v) throw new DelegationError("Cannot delegate: no incoming mandate on this request", "NO_MANDATE");

      // ── Chain length: the default bound applies even without maxDelegationDepth ──
      if (v.envelope.chain.length >= maxDepth) {
        throw new DelegationError(
          `Delegation depth exceeded: the chain already has ${v.envelope.chain.length} links (maximum ${maxDepth})`,
          "DELEGATION_DEPTH_EXCEEDED"
        );
      }

      // ── Depth: this is where the web stops growing ────────────────────────
      const myDepth = mandate.taskConstraints?.maxDelegationDepth;
      if (myDepth !== undefined && myDepth <= 0) {
        throw new DelegationError(
          `Delegation depth exceeded: this mandate forbids sub-delegation (maxDelegationDepth=0)`,
          "DELEGATION_DEPTH_EXCEEDED"
        );
      }
      const childDepth =
        myDepth === undefined
          ? opts.constraints?.maxDelegationDepth
          : Math.min(opts.constraints?.maxDelegationDepth ?? myDepth - 1, myDepth - 1);

      // ── Resolve the target ────────────────────────────────────────────────
      const t: DelegateTarget = typeof target === "string"
        ? target.startsWith("http") ? { endpoint: target } : { didHash: target }
        : target;

      let endpoint = t.endpoint;
      let granteeDID = t.did;
      if (t.didHash) {
        const record = await resolveAgent(t.didHash, delegation.registryUrl);
        endpoint = endpoint ?? record.endpointUrl ?? undefined;
        granteeDID = granteeDID ?? record.did;
      }
      if (!endpoint) throw new DelegationError("Delegate target has no endpoint", "TARGET_UNRESOLVED");
      if (!granteeDID) throw new DelegationError("Delegate target DID unknown — pass target.did with endpoint targets", "TARGET_UNRESOLVED");

      // ── Attenuate: monotonic narrowing enforced by credentials, depth + blocked here ──
      const leafSigned = parseTaskMandateToken(v.envelope.chain[v.envelope.chain.length - 1])!;
      // Start from this hop's own constraints and let the caller narrow them.
      // A field the caller leaves out is inherited, not dropped: the chain
      // verifier treats a dropped constraint as widening and would refuse
      // the child on the next agent.
      const constraints: TaskConstraints = { ...mandate.taskConstraints, ...opts.constraints };
      if (childDepth !== undefined) constraints.maxDelegationDepth = childDepth;

      const started = Date.now();
      const child = await attenuateTaskMandate(
        leafSigned,
        granteeDID,
        opts.allowed,
        constraints,
        identity.privateKey,
        opts.ttlMs,
        { blocked: [...new Set([...(mandate.blocked ?? [])])] }
      );

      const childEnvelope: DelegationEnvelope = {
        v: 1,
        chain: [...v.envelope.chain, child.token],
        rootKeyB64: v.envelope.rootKeyB64,
        correlationId: v.envelope.correlationId,
      };

      try {
        const response = await callDelegated(endpoint, message, childEnvelope, {
          sessionId: opts.sessionId,
          bearerToken: opts.bearerToken,
          allowInsecureHttp: delegation.allowInsecureHttp,
        });
        childArtifacts.push(...response.receipts);
        receipt?.addAction({
          capability: `delegate:${granteeDID}`,
          reversibility: "full",
          startedAt: new Date(started).toISOString(),
          durationMs: Date.now() - started,
          status: "success",
          humanGateTriggered: false,
        });
        return response;
      } catch (err) {
        receipt?.addAction({
          capability: `delegate:${granteeDID}`,
          reversibility: "full",
          startedAt: new Date(started).toISOString(),
          durationMs: Date.now() - started,
          status: "failed",
          humanGateTriggered: false,
        });
        throw err;
      }
    };

    const dctx: DelegatedContext = {
      ...ctx,
      requestApproval: ctx.requestApproval,
      mandate,
      chainDepth: v?.result.depth ?? 0,
      correlationId: v?.envelope.correlationId,
      assertCapability,
      assertDataAccess,
      delegate,
      recordAction: (capability, status = "success") => {
        receipt?.addAction({
          capability,
          reversibility: "full",
          startedAt: new Date().toISOString(),
          durationMs: 0,
          status,
          humanGateTriggered: false,
        });
      },
    };

    // ── Drive the user handler, preserving the bidirectional approval protocol ──
    let accumulated = "";
    let userFinal: Extract<RunEvent, { type: "final" }> | null = null;

    try {
      if (isAsyncGen(handler)) {
        const gen = handler(dctx);
        let input: ApprovalDecision | undefined = undefined;
        while (true) {
          const { value, done } = await gen.next(input);
          if (done) break;
          if (typeof value === "string") {
            accumulated += value;
            input = yield value;
          } else if (value.type === "final") {
            userFinal = value;
            accumulated = value.message ?? accumulated;
            input = undefined;
          } else {
            if (value.type === "token") accumulated += value.delta;
            input = yield value;
          }
        }
      } else {
        accumulated = String(
          await (handler as (c: DelegatedContext) => string | Promise<string>)(dctx)
        );
      }
    } catch (err) {
      if (receipt) receipt.recordViolation(err instanceof Error ? err.message : String(err));
      violated = true;
      accumulated = accumulated || `⛔ ${err instanceof Error ? err.message : String(err)}`;
    }

    // ── Emit the final event with the stitched receipt artifact ───────────────
    const artifacts: unknown[] = [...(userFinal?.artifacts ?? [])];
    if (receipt) {
      const artifact: TaskReceiptArtifact = {
        kind: RECEIPT_ARTIFACT_KIND,
        receipt: receipt.complete(violated ? "failed" : "complete"),
        children: childArtifacts,
      };
      artifacts.push(artifact);
    }

    yield {
      type: "final",
      message: accumulated,
      sessionId: ctx.sessionId ?? "",
      artifacts: artifacts.length ? artifacts : undefined,
      usage: userFinal?.usage,
    };
  }

  // The verified mandate chain IS this agent's authentication: contentGuard
  // refuses every request without one (unless require: false, itself an
  // explicit opt-in to un-mandated callers). So the transport-level default
  // here is auth: "none", not serve()'s "aroha-sig" default — callDelegated
  // does not sign requests. Pass serveOptions.auth to layer signing on top.
  return serve(name, wrapped, { auth: "none", ...serveOptions, contentGuard });
}

function toDelegationCode(code: TaskConstraintViolation["code"]): DelegationError["code"] {
  switch (code) {
    case "CAPABILITY_NOT_PERMITTED":
    case "ACTION_LIMIT_EXCEEDED":
    case "DATA_ACCESS_VIOLATION":
    case "REVERSIBILITY_VIOLATION":
    case "HUMAN_GATE_REQUIRED":
    case "DELEGATION_DEPTH_EXCEEDED":
      return code;
    default:
      return "CONSTRAINT_VIOLATION";
  }
}

/** Derive the base64 public key for an identity — convenience for wiring trustAnchors. */
export async function publicKeyB64(privateKey: Uint8Array): Promise<string> {
  return Buffer.from(await ed.getPublicKeyAsync(privateKey)).toString("base64");
}
