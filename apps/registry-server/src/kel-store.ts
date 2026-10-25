// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The registry's side of rotatable `did:aroha:E…` identities: a durable
// KelStore over D1, and the ONE acceptance path every route uses to take a
// Key Event Log into it (POST /v1/kel, POST /v1/linkage, E-DID agent
// registration, E-DID SAR publish).
//
// WHY ONE PATH. A KEL authenticates itself, so the registry adds nothing by
// "approving" one — what it adds is memory. It keeps the longest verified log
// per DID so a lagging peer cannot roll a verifier back, and it records the
// first proof of a fork so the DID is refused from then on. Both only work if
// every way a log can enter the store applies the same rules; a second,
// slightly different acceptance path (say, SARs storing whatever log they
// carried) would be a way around the controller requirement and the duplicity
// alarm. So routes do not call acceptKel directly — they call
// acceptSubmittedKel here.
//
// WHY @aroha-sdk/core/identity AND NOT THE BARREL. The Worker cannot bundle
// `@aroha-sdk/core` (its barrel re-exports the transport module, which pulls
// in `ws` and `undici`, and through them `fs`, `http`, `path`). The `./identity` subpath depends
// only on @noble/* and bundles cleanly under wrangler, so the protocol logic
// here is the package's own verifyKel/acceptKel, not a copy.

import {
  acceptKel,
  eventDigest,
  isInceptionDid,
  KelError,
  type DuplicityEvidence,
  type KelEvent,
  type KelSource,
  type KelState,
  type KelStore,
} from "@aroha-sdk/core/identity";
import type { RegistryRepository } from "./repository.js";
import { hashDID } from "./routes/agents.js";

/**
 * Longest-wins cap on a submitted log. A KEL grows by one event per rotation,
 * recovery or (for persons) anchor, so even a busy person identity stays far
 * below this; the cap exists because every submission is replayed in full
 * (one Ed25519 verification per event) and the endpoint needs no API key.
 */
export const MAX_KEL_EVENTS = 256;

/** Request-body cap for the unauthenticated KEL / linkage endpoints. */
export const MAX_KEL_BODY_BYTES = 256 * 1024;

/** D1-backed KelStore (core interface) over the repository's opaque-JSON storage. */
export class RepositoryKelStore implements KelStore {
  constructor(private readonly repo: RegistryRepository) {}

  async get(did: string): Promise<KelEvent[] | null> {
    const row = await this.repo.getKelLog(did);
    return row ? (row.events as KelEvent[]) : null;
  }

  async put(did: string, events: KelEvent[]): Promise<void> {
    const written = await this.repo.putKelLogIfLonger({
      did,
      events,
      sequence: events.length - 1,
      lastDigest: eventDigest(events[events.length - 1]),
      updatedAt: Date.now(),
    });
    if (written) return;

    // acceptKel only calls put() for a log longer than the one it read, so
    // losing the conditional upsert means another request stored a log of
    // equal or greater length in between. If that log agrees with ours on
    // every common position we simply lost a benign race (theirs is at least
    // as new). If it DISAGREES, two different, individually valid logs for
    // one DID arrived at once — that is a fork, and it must be recorded
    // exactly as acceptKel records the sequential case, not lost to
    // last-writer-wins.
    const stored = await this.get(did);
    if (!stored) throw new Error(`kel_logs row for ${did} vanished during a conditional write`);
    const common = Math.min(stored.length, events.length);
    for (let i = 0; i < common; i++) {
      const seen = eventDigest(stored[i]);
      const offered = eventDigest(events[i]);
      if (seen !== offered) {
        await this.recordDuplicity({ did, seq: i, digests: [seen, offered], detectedAt: new Date().toISOString() });
        throw new KelError("duplicity", `${did}: two different events at seq ${i} — the log was forked`);
      }
    }
  }

  async recordDuplicity(evidence: DuplicityEvidence): Promise<void> {
    await this.repo.recordKelDuplicity(evidence.did, evidence, Date.now());
  }

  async getDuplicity(did: string): Promise<DuplicityEvidence | null> {
    return (await this.repo.getKelDuplicity(did)) as DuplicityEvidence | null;
  }
}

export interface AcceptSubmittedKelOptions {
  /**
   * The controller person's KEL, when the submitter has it. Accepted into the
   * store FIRST (same rules), so the agent's log is checked against the
   * longest controller log anyone has shown the registry — not just this one.
   */
  controllerKel?: KelEvent[];
  /**
   * "reject" (POST /v1/kel): a log shorter than the stored one is an error
   * the submitter should hear about. "use-stored" (registration, SARs,
   * linkages): the caller wants the newest verified state, and a lagging
   * attachment should not fail the request when the registry knows better.
   */
  onStale?: "reject" | "use-stored";
}

/**
 * Take a submitted log into the store, enforcing the registry's rules on top
 * of acceptKel:
 *
 *   - requireController: an agent that names a controller is only accepted
 *     once the controller's KEL is known. The controller's seals are what
 *     make a withheld revocation detectable (design §6); accepting the agent
 *     without them would let a submitter freeze its log before a revocation
 *     the registry could otherwise have seen.
 *   - duplicity proven by the controller's seals (an anchored event differs
 *     from a self-signed event in the submitted log) is RECORDED here, which
 *     acceptKel does not do for that case — see recordSealDuplicity.
 *   - side effects that keep the rest of the registry consistent with the
 *     log: a registered E-DID agent's row follows the KEL's current key and
 *     is deactivated once revoked; a person's newly accepted seals are
 *     checked against the agent logs already stored; a person's revocation
 *     deactivates every agent row it controls, and a seal past the end of a
 *     controlled agent's stored log takes that agent's row down until its
 *     log catches up (see afterAccept).
 *
 * Throws KelError (codes as in core) on rejection.
 */
export async function acceptSubmittedKel(
  repo: RegistryRepository,
  did: string,
  events: KelEvent[],
  options: AcceptSubmittedKelOptions = {},
): Promise<KelState> {
  // Capped here rather than only in the routes so every entry point (a SAR
  // with an attached log, a registration body) gets the same bound on how
  // much unauthenticated signature-verification work one request can buy.
  for (const [log, field] of [[events, "events"], [options.controllerKel, "controllerKel"]] as const) {
    if (log === undefined) continue;
    const problem = checkEventArray(log, field);
    if (problem) throw new KelError("invalid", problem);
  }

  const store = new RepositoryKelStore(repo);

  // The inception's `controller` is read here only to decide which log to
  // fetch; verifyKel re-derives it from the hash-checked inception, so a
  // lying value just fails verification.
  const claimedController = controllerOf(events);
  if (claimedController && options.controllerKel) {
    const ctl = await acceptKel(claimedController, options.controllerKel, store, { onStale: "use-stored" });
    await afterAccept(repo, store, ctl);
  }

  // A controller with a recorded fork is not a principal anyone can rely on:
  // which branch's seals are "the" seals is exactly what is in dispute. So
  // its agents are refused too, rather than judged against one branch.
  const resolveControllerKel: KelSource = async (cdid) => {
    const alarm = await store.getDuplicity(cdid);
    if (alarm) throw new KelError("duplicity", `controller ${cdid} has a recorded duplicity alarm at seq ${alarm.seq}`);
    return store.get(cdid);
  };
  let state: KelState;
  try {
    state = await acceptKel(did, events, store, {
      resolveControllerKel,
      requireController: true,
      onStale: options.onStale ?? "reject",
    });
  } catch (e) {
    if (e instanceof KelError && e.code === "duplicity" && claimedController) {
      await recordSealDuplicity(store, did, events, claimedController);
    }
    throw e;
  }
  await afterAccept(repo, store, state);
  return state;
}

/**
 * The stored log for `did`, re-verified against the store (controller seals
 * included). Null when nothing is stored. Used where a request names an
 * E-DID but carries no log of its own.
 */
export async function storedKelState(repo: RegistryRepository, did: string): Promise<KelState | null> {
  const stored = await new RepositoryKelStore(repo).get(did);
  if (!stored) return null;
  return acceptSubmittedKel(repo, did, stored, { onStale: "use-stored" });
}

function controllerOf(events: unknown): string | null {
  if (!Array.isArray(events) || events.length === 0) return null;
  const inc = events[0] as { type?: unknown; controller?: unknown } | null;
  if (!inc || typeof inc !== "object" || inc.type !== "inception") return null;
  return typeof inc.controller === "string" && isInceptionDid(inc.controller) ? inc.controller : null;
}

/**
 * Record a fork that the CONTROLLER's seals prove: the person anchored event
 * X at seq N of this agent's log, and the submitted log has a different,
 * self-signed event at seq N.
 *
 * Why only self-signed events count. verifyKel compares seal digests before
 * it checks that every controller-authorised event is sealed, so a submitted
 * log can reach that comparison carrying an UNSIGNED `recover` or controller
 * `revoke` at seq N — which anyone can write. Recording on the error code
 * alone would let a stranger raise a permanent duplicity alarm on somebody
 * else's agent with junk. A `rotate` or next-key `revoke` at seq N, on the
 * other hand, only verified because the agent's pre-committed next key
 * signed it — a genuine second branch, i.e. real evidence.
 */
async function recordSealDuplicity(
  store: RepositoryKelStore,
  did: string,
  events: KelEvent[],
  controller: string,
): Promise<void> {
  if (await store.getDuplicity(did)) return; // acceptKel already recorded it
  const controllerEvents = await store.get(controller);
  if (!controllerEvents) return;
  for (const seal of sealsFor(controllerEvents, did)) {
    const offered = events[seal.seq];
    if (!offered || !isSelfSigned(offered)) continue;
    const offeredDigest = eventDigest(offered);
    if (offeredDigest !== seal.digest) {
      await store.recordDuplicity({
        did,
        seq: seal.seq,
        digests: [seal.digest, offeredDigest],
        detectedAt: new Date().toISOString(),
      });
      return;
    }
  }
}

function isSelfSigned(event: KelEvent): boolean {
  return event.type === "rotate" || (event.type === "revoke" && event.auth === "next-key");
}

/**
 * Seals a STORED (therefore already verified) person log has placed for
 * `agentDid`. Callers MUST pass the log of the person the agent's own
 * inception names as controller — a seal from any other person is
 * meaningless for that agent (anyone can anchor a seal naming any DID). Reading anchors straight out of a stored log, without
 * re-verifying it, is sound only because nothing enters kel_logs except
 * through acceptKel.
 */
export function sealsFor(personEvents: KelEvent[], agentDid: string): Array<{ seq: number; digest: string }> {
  const out: Array<{ seq: number; digest: string }> = [];
  for (const e of personEvents) {
    if (e.type !== "anchor") continue;
    for (const s of e.seals) if (s.did === agentDid) out.push({ seq: s.seq, digest: s.digest });
  }
  return out;
}

async function afterAccept(repo: RegistryRepository, store: RepositoryKelStore, state: KelState): Promise<void> {
  if (state.kind === "agent") {
    await syncAgentRow(repo, state);
    return;
  }

  // A person who has revoked ITSELF has abandoned every agent it controls:
  // their authority came from this person, and there is no longer anyone
  // behind them (core marks such agents `controllerRevoked`, and mandate
  // checks treat that like `revoked`). Waiting for each agent's own log to
  // be re-posted would leave their rows discoverable with live keys
  // indefinitely, so the cascade runs here, on the person's log. Scoped by
  // the agents' OWN inceptions (agent_records.controller_did, copied from
  // the verified log): a person can only ever reach agents that named it as
  // controller when they were created. Idempotent — only active rows move.
  if (state.revoked) {
    await repo.deactivateAgentsControlledBy(state.did);
  }
  // A person: every seal is a claim about one of their agents' logs. If we
  // already hold that agent's log and it has a DIFFERENT event at the sealed
  // position, the agent's log is forked (its stored event was validly
  // signed when accepted, and the person's key has now anchored another).
  // A seal past the end of the stored log is not an error here — it means
  // the stored agent log is behind, which GET /v1/kel refuses to serve.
  //
  // ONLY the agent's own controller's seals count. Anyone can incept a
  // person identity and anchor seals naming any DID they like; a seal is
  // authority (and evidence) solely for agents whose hash-committed
  // inception names THIS person as controller. Honouring a stranger's seal
  // would let anyone permanently alarm — and so disable — somebody else's
  // agent for the price of one self-made person log.
  //
  // A seal PAST the end of the stored agent log is the other signal: the
  // controller has authorised an agent event the registry has not seen. The
  // seal carries only a digest, so the registry cannot tell a revoke from a
  // recovery — but it does not need to. Every agent event after inception
  // (rotate, recover, revoke) replaces or kills the key, so the key on the
  // agent's registry row is no longer its current key either way. The row is
  // taken down as 'controller-sealed-ahead' right away, instead of serving
  // a dead (possibly stolen) key until somebody posts the agent's log; when
  // that log arrives, syncAgentRow makes it permanent (a revoke) or brings
  // the row back with the installed key (a recovery or rotation). Same
  // scoping as above: only the agent's own controller can do this.
  const suspended = new Set<string>();
  for (const seal of state.seals) {
    const agentLog = await store.get(seal.did);
    if (!agentLog) continue;
    const inc = agentLog[0];
    if (inc.type !== "inception" || inc.controller !== state.did) continue;
    if (seal.seq >= agentLog.length) {
      if (!state.revoked && !suspended.has(seal.did)) {
        suspended.add(seal.did);
        await repo.suspendAgentPendingControllerEvent(hashDID(seal.did));
      }
      continue;
    }
    const storedDigest = eventDigest(agentLog[seal.seq]);
    if (storedDigest !== seal.digest) {
      await store.recordDuplicity({
        did: seal.did,
        seq: seal.seq,
        digests: [storedDigest, seal.digest],
        detectedAt: new Date().toISOString(),
      });
    }
  }
}

/**
 * Make a registered E-DID agent's registry row follow its KEL. The KEL is
 * the authority for an E-DID's key — the row is a cache of it, kept so the
 * existing consumers of publicKeyB64 (discovery clients, the relay's
 * connect challenge, mandate checks that resolve keys from the registry)
 * see the rotated key without learning about KELs.
 *
 * It also carries the agent's controller (state.controller is read from the
 * verified, hash-committed inception), which is how a row the migration-015
 * backfill missed gets the column lazily, and it settles a row that was
 * taken down as 'controller-sealed-ahead': acceptKel only returns a state
 * for a controlled agent once the log covers every seal its controller has
 * placed, so this IS the sealed event arriving.
 */
async function syncAgentRow(repo: RegistryRepository, state: KelState): Promise<void> {
  await repo.applyKelKeyState(hashDID(state.did), {
    publicKeyB64: state.currentKey ? bytesToB64(state.currentKey) : null,
    keyVersion: state.keyHistory.length,
    revoked: state.revoked,
    controllerRevoked: state.controllerRevoked,
    controllerDid: state.controller ?? null,
  });
}

export function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** HTTP status and body for a KelError — shared so every route answers the same way. */
export function kelErrorResponse(e: KelError): { status: 400 | 409 | 422; body: { error: string; code: string } } {
  switch (e.code) {
    case "stale":
    case "duplicity":
      return { status: 409, body: { error: e.message, code: e.code } };
    case "controller-unavailable":
      return {
        status: 422,
        body: {
          error: `${e.message} — POST the controller's KEL to /v1/kel/<controller DID> first, or include it as controllerKel`,
          code: e.code,
        },
      };
    default:
      return { status: 400, body: { error: e.message, code: e.code } };
  }
}

/** Shape check for a submitted log before any cryptography runs. */
export function checkEventArray(value: unknown, field: string): string | null {
  if (!Array.isArray(value) || value.length === 0) return `${field} must be a non-empty array of KEL events`;
  if (value.length > MAX_KEL_EVENTS) return `${field} has ${value.length} events; the limit is ${MAX_KEL_EVENTS}`;
  if (!value.every((e) => typeof e === "object" && e !== null && !Array.isArray(e))) {
    return `${field} must contain only event objects`;
  }
  return null;
}
