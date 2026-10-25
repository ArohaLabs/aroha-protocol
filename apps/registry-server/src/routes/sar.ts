// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// Signed Agent Record index (design spec §7.3, §7.4) — "the registry as one
// index among many, not the index." Deliberately open: publishing needs no
// API key, only a valid self-signature, because requiring an account here
// would recreate exactly the centralized gatekeeping federated discovery is
// meant to avoid. The cryptographic check (@aroha-sdk/registry/sar) IS the access
// control; globalIpLimiter (applied to all of /v1/* in index.ts) is the
// abuse control.
//
//   POST /v1/sar              publish (or replace) a SAR — no auth
//   GET  /v1/sar               query, optional ?capability= / ?did= /
//                              ?limit= (1–100, default 50) / ?offset= — no auth
//
// WHY THE PACKAGE'S verifySar AND NOT A LOCAL COPY. This Worker used to
// carry its own sar-verify.ts, kept byte-for-byte in step with
// @aroha-sdk/registry by pinning tests, because importing the package pulled
// in Node built-ins wrangler cannot bundle. The package now publishes a
// Worker-safe `./sar` subpath (it imports only the @aroha-sdk/core
// `./identity` and `./crypto` subpaths, guarded by the package's
// worker-safety.test.ts), so the index verifies records with the reference
// implementation itself — the same code every client uses to check what
// this index serves. The one thing injected is E-DID resolution
// (`resolveKel`): a log attached to a record must enter the registry only
// through kel-store.ts's acceptance path, never a looser one.

import { Hono } from "hono";
import type { HonoEnv } from "../index.js";
import { isInceptionDid } from "@aroha-sdk/core/identity";
import { verifySar, hasSarShape } from "@aroha-sdk/registry/sar";
import { acceptSubmittedKel, storedKelState } from "../kel-store.js";
import { sarPublishLimiter } from "../middleware/rate-limit.js";
import { parsePagination } from "../pagination.js";

export const sarRoutes = new Hono<HonoEnv>();

// sarPublishLimiter: per-isolate burst bound (globalIpLimiter is the floor;
// Cloudflare WAF rate rules are the shared control — see rate-limit.ts).
sarRoutes.post("/", sarPublishLimiter, async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  // E-DID records verify against the CURRENT key of the agent's KEL. The log
  // attached to the record (if any) goes through the registry's single
  // acceptance path, so publishing a SAR is also a way to relay a newer KEL —
  // under exactly the rules POST /v1/kel applies, never looser ones. With no
  // attachment, the registry's stored log is used ("use-stored" either way:
  // a lagging attachment should not fail a record the registry can verify).
  const repo = c.get("repo");
  const result = await verifySar(body, Date.now(), {
    resolveKel: async (did, attached) =>
      attached
        ? acceptSubmittedKel(repo, did, attached, { onStale: "use-stored" })
        : storedKelState(repo, did),
  });
  if (!result.valid) {
    return c.json({ error: `SAR rejected: ${result.reason}` }, 422);
  }
  // hasSarShape narrowed `body` inside verifySar's own scope, not
  // this one — re-check here so this function has its own type evidence
  // rather than trusting a cast.
  if (!hasSarShape(body)) return c.json({ error: "SAR rejected: bad_shape" }, 422);

  // The attached KEL is not stored with the record: kel_logs already holds
  // the longest verified log for the DID, and GET attaches THAT, so a reader
  // always gets the newest log rather than whatever the publisher had.
  await repo.upsertSar({
    did: body.did,
    capabilities: body.capabilities,
    transports: body.transports,
    settlementRails: body.settlementRails,
    // SarTerms is an interface (no index signature); the column is opaque JSON.
    terms: body.terms as Record<string, unknown>,
    issuedAt: body.issuedAt,
    ttl: body.ttl,
    signature: body.signature,
    storedAt: Date.now(),
  });

  return c.json({ ok: true, did: body.did }, 201);
});

sarRoutes.get("/", async (c) => {
  const capability = c.req.query("capability") ?? undefined;
  const did = c.req.query("did") ?? undefined;
  const repo = c.get("repo");
  // Paged like every other list route: an unfiltered GET used to return the
  // whole live index in one response (and attach a KEL to each E-DID row).
  const { limit, offset } = parsePagination(c);
  const records = await repo.querySar({ capability, did, now: Date.now(), limit, offset });
  // E-DID records go out with the registry's stored KEL attached, so a
  // client can verify them with no second lookup. The attachment is unsigned
  // by design (see @aroha-sdk/registry's sar.ts): attaching the NEWEST log is the point — if
  // the agent rotated since signing, the record correctly stops verifying.
  const out = await Promise.all(
    records.map(async (r) => {
      const base = {
        did: r.did,
        capabilities: r.capabilities,
        transports: r.transports,
        settlementRails: r.settlementRails,
        terms: r.terms,
        issuedAt: r.issuedAt,
        ttl: r.ttl,
        signature: r.signature,
      };
      if (!isInceptionDid(r.did)) return base;
      const kel = await repo.getKelLog(r.did);
      if (!kel) return base;
      // A record whose identity has since been revoked — by itself or because
      // the person controlling it revoked ITSELF — is withheld from discovery,
      // like a deactivated agent row. A client verifying the attached log
      // would reject it anyway; the index should not be the thing advertising
      // it. Stored logs are verified, so reading event types is enough.
      const events = kel.events as Array<{ type?: string; controller?: string }>;
      if (events.some((e) => e.type === "revoke")) return null;
      const controller = events[0]?.controller;
      if (controller) {
        const ctl = await repo.getKelLog(controller);
        if ((ctl?.events as Array<{ type?: string }> | undefined)?.some((e) => e.type === "revoke")) return null;
      }
      return { ...base, kel: kel.events };
    }),
  );
  return c.json({ records: out.filter((r) => r !== null) });
});
