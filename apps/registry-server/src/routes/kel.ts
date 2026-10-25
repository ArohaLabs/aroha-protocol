// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * /v1/kel and /v1/linkage — Key Event Logs for rotatable `did:aroha:E…`
 * identities, and linkages from legacy DIDs to them (design:
 * docs/superpowers/specs/2026-10-07-rotatable-identity-and-person-principal-design.md §8).
 *
 *   POST /v1/kel/:did             submit a log      — no API key, rate limited
 *   GET  /v1/kel/:did             the stored log    — refuses to serve a log its controller's seals prove stale
 *   GET  /v1/kel/:did/duplicity   recorded fork evidence, if any
 *   POST /v1/linkage              submit a legacy-DID → E-DID linkage — no API key, rate limited
 *   GET  /v1/linkage/:fromDid     the first linkage for a DID, and whether a conflicting one was seen
 *
 * WHY NO API KEY. A KEL authenticates itself: the DID is the hash of the
 * inception, and every later event is signed by a key the previous state
 * committed to. The registry can therefore accept a log from anyone — a
 * peer relaying it is as good as the owner posting it — and the access
 * control is acceptKel's verification, the same way the SAR index's access
 * control is the record's own signature. What the endpoint does need is abuse
 * control, because every submission replays a whole log: kelSubmitLimiter,
 * a body-size cap, and an event-count cap.
 *
 * SHARED SIGNALS. A POST that newly establishes a revocation (the DID's own
 * log, or the controller log it carries) is announced as signed SETs — CAEP
 * credential-change + Aroha did-revoked — for the DID and for every
 * registered agent that person controls (ssf.ts). Revocations reaching the
 * store through registration, SAR or linkage bodies are not announced; the
 * KEL route is the documented way to publish one.
 *
 * WHAT THE REGISTRY IS FOR, HERE. It cannot forge a log, only withhold one.
 * Its value is memory: the longest verified log per DID (so nobody can roll a
 * verifier back) and a durable duplicity alarm (so a fork, once seen, is
 * never forgotten). GET is written so the registry cannot be the thing that
 * hides a revocation either — see the freshness check below.
 */

import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { didRevokedEvents, emitSecurityEvents, settleInBackground } from "../ssf.js";
import {
  eventDigest,
  isInceptionDid,
  KelError,
  verifyLinkage,
  type IdentityLinkage,
  type KelEvent,
} from "@aroha-sdk/core/identity";
import type { HonoEnv } from "../index.js";
import { kelSubmitLimiter } from "../middleware/rate-limit.js";
import {
  acceptSubmittedKel,
  checkEventArray,
  kelErrorResponse,
  MAX_KEL_BODY_BYTES,
  RepositoryKelStore,
  sealsFor,
} from "../kel-store.js";
import { hashDID } from "./agents.js";
import { decodeEd25519PublicKey } from "../b64.js";

const submitBodyLimit = bodyLimit({
  maxSize: MAX_KEL_BODY_BYTES,
  onError: (c) => c.json({ error: `request body exceeds ${MAX_KEL_BODY_BYTES} bytes` }, 413),
});

function didParam(raw: string | undefined): string {
  return decodeURIComponent(raw ?? "");
}

/** Cap on cascaded per-agent announcements for one person's revocation. */
const MAX_CASCADE_ANNOUNCEMENTS = 200;

async function storedRevoked(store: RepositoryKelStore, did: string): Promise<boolean> {
  const events = await store.get(did);
  return events?.some((e) => e.type === "revoke") ?? false;
}

/**
 * Announce a newly accepted KEL revocation to Shared Signals receivers
 * (ssf.ts): the DID itself, then every registered agent whose verified
 * inception named it as controller (kel-store.ts has just deactivated those
 * rows). Queued durably, pushed within this request's lifetime; never fails
 * the KEL submission.
 */
async function announceRevocations(
  c: Context<HonoEnv>,
  did: string,
  reason: "kel-revoked",
  sequence?: number,
): Promise<void> {
  const events = didRevokedEvents({ did, reason, sequence });
  try {
    const { results } = await c.env.DB
      .prepare(`SELECT did FROM agent_records WHERE controller_did = ? ORDER BY did LIMIT ?`)
      .bind(did, MAX_CASCADE_ANNOUNCEMENTS)
      .all<{ did: string }>();
    for (const r of results ?? []) {
      events.push(...didRevokedEvents({ did: r.did, reason: "controller-revoked", controller: did }));
    }
  } catch (err) {
    console.error("[kel] controlled-agent lookup for revocation signals failed:", err);
  }
  const { pushes } = await emitSecurityEvents(c.env, events);
  await settleInBackground(c, pushes);
}

// ─── /v1/kel ──────────────────────────────────────────────────────────────────

export const kelRoutes = new Hono<HonoEnv>();

/**
 * POST /v1/kel/:did — body { events: KelEvent[], controllerKel?: KelEvent[] }
 *
 *   200 { did, sequence, revoked }   accepted (or identical to what is stored)
 *   400 { error, code: "invalid" }   malformed, mis-signed, mis-chained
 *   409 { error, code: "stale" }     shorter than the stored log, or than the controller's seals
 *   409 { error, code: "duplicity" } forked — the evidence is recorded and the DID refused from now on
 *   422 { error, code: "controller-unavailable" } the log names a controller whose KEL the
 *                                    registry does not have; post it first or include controllerKel
 *
 * The log is accepted ONLY through acceptSubmittedKel (kel-store.ts), which
 * wraps @aroha-sdk/core's acceptKel with the registry's rules: a controlled
 * agent needs its controller's KEL, the controller's KEL (when included) is
 * accepted first under the same rules, and a registered agent's row follows
 * the accepted log — rotated key, and deactivation on revoke.
 */
kelRoutes.post("/:did", kelSubmitLimiter, submitBodyLimit, async (c) => {
  const did = didParam(c.req.param("did"));
  if (!isInceptionDid(did)) {
    return c.json({ error: "did must be a rotatable did:aroha:E… identifier", code: "invalid" }, 400);
  }

  const body = await c.req.json<{ events?: unknown; controllerKel?: unknown }>().catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON", code: "invalid" }, 400);
  const problem =
    checkEventArray(body.events, "events") ??
    (body.controllerKel === undefined ? null : checkEventArray(body.controllerKel, "controllerKel"));
  if (problem) return c.json({ error: problem, code: "invalid" }, 400);

  const repo = c.get("repo");
  const store = new RepositoryKelStore(repo);
  // Revocation state BEFORE this submission, for this DID and the controller
  // its log claims — only a revocation this request newly establishes is
  // announced to Shared Signals receivers (see announceRevocations).
  const events = body.events as KelEvent[];
  const claimedController = events[0]?.type === "inception" ? events[0].controller : undefined;
  const wasRevoked = await storedRevoked(store, did);
  const controllerWasRevoked = claimedController ? await storedRevoked(store, claimedController) : false;
  try {
    const state = await acceptSubmittedKel(repo, did, events, {
      controllerKel: body.controllerKel as KelEvent[] | undefined,
      onStale: "reject",
    });
    if (state.revoked && !wasRevoked) {
      await announceRevocations(c, did, "kel-revoked", state.sequence);
    }
    if (state.controller && state.controllerRevoked && !controllerWasRevoked) {
      await announceRevocations(c, state.controller, "kel-revoked");
    }
    return c.json({ did, sequence: state.sequence, revoked: state.revoked });
  } catch (e) {
    if (e instanceof KelError) {
      const { status, body: errBody } = kelErrorResponse(e);
      return c.json(errBody, status);
    }
    throw e;
  }
});

/**
 * GET /v1/kel/:did — { did, events, sequence } (+ { controller, controllerRevoked } for a controlled agent)
 *
 *   404  nothing stored
 *   409  { code: "duplicity" } the DID has a recorded fork — the registry will
 *        not vouch for either branch (evidence: GET /v1/kel/:did/duplicity)
 *   409  { code: "stale" } the controller's stored KEL has sealed an event
 *        for this DID beyond the end of the stored log
 *
 * The stale case is the design's "withheld revocation must be detectable"
 * (§6) applied to the registry itself. A person revokes or recovers an agent
 * by anchoring a seal in the PERSON's log; if someone has since given us the
 * person's log but not the agent's matching event, serving the agent's
 * shorter log would hand verifiers exactly the pre-revocation state the
 * seal exists to rule out. Answering 409 — with the sequence the seal
 * implies — tells the caller the registry is behind, instead of being a
 * confident source of a stale key.
 */
kelRoutes.get("/:did", async (c) => {
  const did = didParam(c.req.param("did"));
  if (!isInceptionDid(did)) return c.json({ error: "Not found" }, 404);
  const store = new RepositoryKelStore(c.get("repo"));

  const alarm = await store.getDuplicity(did);
  if (alarm) {
    return c.json({
      error: `${did} has a recorded duplicity alarm at seq ${alarm.seq}; the registry will not serve a forked log`,
      code: "duplicity",
      duplicity: alarm,
    }, 409);
  }

  const events = await store.get(did);
  if (!events) return c.json({ error: "Not found" }, 404);

  const inception = events[0];
  const controller = inception.type === "inception" ? inception.controller : undefined;
  let controllerRevoked = false;
  if (controller) {
    const controllerEvents = await store.get(controller);
    // A person's log can only end in its revoke (nothing follows one).
    controllerRevoked = controllerEvents?.some((e) => e.type === "revoke") ?? false;
    if (controllerEvents) {
      for (const seal of sealsFor(controllerEvents, did)) {
        if (seal.seq >= events.length) {
          return c.json({
            error:
              `the controller ${controller} has anchored event ${seal.seq} of ${did}, but the stored log ends at ` +
              `${events.length - 1} — serving it could hide a revocation or recovery. POST the agent's current ` +
              `log to /v1/kel/${did}.`,
            code: "stale",
            controller,
            storedSequence: events.length - 1,
            sealedSequence: seal.seq,
          }, 409);
        }
        // A digest mismatch would already have been recorded as duplicity
        // when the second of the two logs was accepted (kel-store.ts); this
        // is the belt to that brace, and it never writes on a GET.
        if (eventDigest(events[seal.seq]) !== seal.digest) {
          return c.json({
            error: `the controller ${controller} anchored a different event at ${did} seq ${seal.seq} than the stored log`,
            code: "duplicity",
          }, 409);
        }
      }
    }
  }

  // controllerRevoked (controlled agents only): the agent's own log may be
  // perfectly current and unrevoked while the PERSON behind it has revoked
  // itself — core's KelState.controllerRevoked, which mandate checks treat
  // like revoked. A verifier fetching just this log would not see that, so
  // the registry says it outright, from the controller's stored (verified)
  // log. The registry row is already deactivated by then (kel-store.ts).
  return c.json(
    controller
      ? { did, events, sequence: events.length - 1, controller, controllerRevoked }
      : { did, events, sequence: events.length - 1 },
  );
});

/** GET /v1/kel/:did/duplicity — { did, duplicity: DuplicityEvidence | null } */
kelRoutes.get("/:did/duplicity", async (c) => {
  const did = didParam(c.req.param("did"));
  if (!isInceptionDid(did)) return c.json({ error: "Not found" }, 404);
  const evidence = await new RepositoryKelStore(c.get("repo")).getDuplicity(did);
  return c.json({ did, duplicity: evidence });
});

// ─── /v1/linkage ──────────────────────────────────────────────────────────────

export const linkageRoutes = new Hono<HonoEnv>();

/**
 * POST /v1/linkage — body { linkage: IdentityLinkage, toKel: KelEvent[], controllerKel?: KelEvent[] }
 *
 *   201 { from, to, linkage }               first linkage for `from` — stored
 *   200 { from, to, linkage, existing }     a linkage to the SAME successor was already stored (kept as-is)
 *   400 { error }                           malformed, or verifyLinkage rejected it
 *   409 { error, stored }                   a linkage from `from` to a DIFFERENT successor exists;
 *                                           this one is filed as a conflict, never followed
 *   (plus the KEL statuses of POST /v1/kel for `toKel`)
 *
 * First wins, never overwritten. A z-DID IS its key, so a thief holding the
 * old key can sign a linkage to an E-DID of their own (design §6). Nothing
 * the registry can check tells the owner's linkage from the thief's; what it
 * can do is refuse to let a later one silently redirect everyone who trusted
 * the old DID, and surface the conflict (GET reports it) for a human.
 *
 * The `from` key: a z-DID's key is derived from the DID inside
 * verifyLinkage. A named (registry-trusted) DID uses the key this registry
 * holds for that ACTIVE agent — the only key the registry can vouch for.
 * An E-DID has nothing to migrate from: it rotates instead.
 */
linkageRoutes.post("/", kelSubmitLimiter, submitBodyLimit, async (c) => {
  const body = await c.req
    .json<{ linkage?: unknown; toKel?: unknown; controllerKel?: unknown }>()
    .catch(() => null);
  if (!body || typeof body !== "object") return c.json({ error: "Invalid JSON" }, 400);
  const linkage = body.linkage as IdentityLinkage | undefined;
  if (!linkage || typeof linkage !== "object" || typeof linkage.from !== "string" || typeof linkage.to !== "string") {
    return c.json({ error: "linkage must be a signed IdentityLinkage object" }, 400);
  }
  if (!isInceptionDid(linkage.to)) return c.json({ error: "linkage.to must be a did:aroha:E… identifier" }, 400);
  const problem =
    checkEventArray(body.toKel, "toKel") ??
    (body.controllerKel === undefined ? null : checkEventArray(body.controllerKel, "controllerKel"));
  if (problem) return c.json({ error: problem }, 400);

  const repo = c.get("repo");
  const store = new RepositoryKelStore(repo);

  // The successor's log enters the store through the same door as POST
  // /v1/kel. "use-stored": the linkage was signed at toSeq, which any longer
  // stored log still contains, so a lagging toKel should not fail it.
  let toEvents: KelEvent[];
  try {
    const state = await acceptSubmittedKel(repo, linkage.to, body.toKel as KelEvent[], {
      controllerKel: body.controllerKel as KelEvent[] | undefined,
      onStale: "use-stored",
    });
    toEvents = state.events;
  } catch (e) {
    if (e instanceof KelError) {
      const { status, body: errBody } = kelErrorResponse(e);
      return c.json(errBody, status);
    }
    throw e;
  }

  const result = await verifyLinkage(linkage, toEvents, {
    resolveControllerKel: (cdid) => store.get(cdid),
    resolveFromKey: async (fromDid) => {
      if (isInceptionDid(fromDid)) return null;
      const agent = await repo.getAgent(hashDID(fromDid));
      if (!agent) return null;
      // Shared decoder: the row may hold base64url (SDK) or base64 (see b64.ts).
      return decodeEd25519PublicKey(agent.publicKeyB64);
    },
  });
  if (!result.valid) return c.json({ error: `linkage rejected: ${result.reason}` }, 400);

  const now = Date.now();
  const { inserted, stored } = await repo.insertIdentityLinkage({
    fromDid: linkage.from,
    toDid: linkage.to,
    linkage,
    createdAt: now,
  });
  if (inserted) {
    void repo.recordEvent("identity.linkage_stored", hashDID(linkage.from)).catch(() => {});
    return c.json({ from: linkage.from, to: linkage.to, linkage }, 201);
  }
  if (stored.toDid === linkage.to) {
    // Same successor, perhaps re-signed at a later toSeq: nothing to resolve,
    // and the first record stays the record.
    return c.json({ from: stored.fromDid, to: stored.toDid, linkage: stored.linkage, existing: true });
  }
  await repo.recordIdentityLinkageConflict(linkage.from, linkage, now);
  return c.json({
    error:
      `${linkage.from} is already linked to ${stored.toDid}; a different, validly signed linkage to ${linkage.to} ` +
      `has been recorded as a conflict and will not be followed`,
    stored: { from: stored.fromDid, to: stored.toDid, linkage: stored.linkage },
  }, 409);
});

/** GET /v1/linkage/:fromDid — { from, to, linkage, createdAt, conflict, conflictCount } */
linkageRoutes.get("/:fromDid", async (c) => {
  const fromDid = didParam(c.req.param("fromDid"));
  const row = await c.get("repo").getIdentityLinkage(fromDid);
  if (!row) return c.json({ error: "Not found" }, 404);
  return c.json({
    from: row.fromDid,
    to: row.toDid,
    linkage: row.linkage,
    createdAt: row.createdAt,
    // A conflict means two validly signed linkages exist for one old DID —
    // i.e. the old key is (or was) in two hands. Clients should show this to
    // a person rather than follow `to` automatically.
    conflict: row.conflictCount > 0,
    conflictCount: row.conflictCount,
  });
});
