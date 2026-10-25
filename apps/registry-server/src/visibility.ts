// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Who may see an agent — the one rule every per-agent read route applies.
 *
 * GET /v1/agents/:did has always hidden a private agent from anyone but its
 * owner and live grantees, answering 404 (never 403) so the route cannot be
 * used to prove a private agent exists. Several sibling routes keyed by the
 * same didHash (credential, revoked keys, analytics, relay status) did not
 * apply that rule, so each one leaked the record — or at least its
 * existence — that the resolve route withheld. They all call this now.
 */

import type { Context } from "hono";
import type { HonoEnv } from "./index.js";
import type { AgentRow, RegistryRepository } from "./repository.js";

/**
 * public / unlisted → anyone who knows the identifier;
 * private → the owner's API key, or a key holding a live grant.
 */
export async function canViewAgent(
  repo: RegistryRepository,
  agent: Pick<AgentRow, "didHash" | "visibility" | "ownerKeyHash">,
  viewerKeyHash: string | null,
): Promise<boolean> {
  if (agent.visibility !== "private") return true;
  if (!viewerKeyHash) return false;
  if (agent.ownerKeyHash === viewerKeyHash) return true;
  return repo.hasGrant(agent.didHash, { keyHash: viewerKeyHash });
}

/**
 * Mark a response as depending on who asked. Without this a shared cache
 * (or the browser's) could serve one caller's view of a private resource —
 * or one caller's grants, spend, or credential — to the next caller of the
 * same URL. `Vary: Authorization` is the honest description; `no-store`
 * is the control, because not every intermediary honours Vary.
 */
export function viewerDependent(c: Context<HonoEnv>): void {
  c.header("Cache-Control", "no-store");
  c.header("Vary", "Authorization");
}

/**
 * Router-level form of viewerDependent for route groups where every
 * response is per-caller (spaces, spending): applied after the handler so
 * it covers every route and status in the group without per-handler calls.
 */
export async function viewerDependentMiddleware(c: Context<HonoEnv>, next: () => Promise<void>): Promise<void> {
  await next();
  c.res.headers.set("Cache-Control", "no-store");
  c.res.headers.set("Vary", "Authorization");
}
