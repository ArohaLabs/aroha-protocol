// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Spaces, and the grants they produce.
 *
 * The assertions that matter are not "a space can be created" but the ones
 * about access_grants: a space is only worth having if joining one actually
 * grants access, and only safe if leaving one revokes exactly what it gave.
 */

import { describe, it, expect } from "vitest";
import { makeApp, type TestApp } from "../test-utils/make-app.js";

/** Register a private agent owned by this app's key, and return its didHash. */
async function seedPrivateAgent(app: TestApp, didHash: string): Promise<void> {
  await app.env.DB.prepare(
    `INSERT INTO agent_records (did_hash, did, owner_key_hash, org_name, manifest_cid,
                                public_key_b64, registered_at, last_updated_at, active, visibility)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'private')`,
  ).bind(
    didHash, `did:aroha:test-${didHash}`, app.keyHash, "Test Org",
    "QmTest", "key", Date.now(), Date.now(),
  ).run();
}

function auth(key: string): Record<string, string> {
  return { Authorization: `Bearer ${key}`, "Content-Type": "application/json" };
}

/** Live grants on a resource, whatever created them. */
async function liveGrants(app: TestApp, didHash: string): Promise<Array<Record<string, unknown>>> {
  const { results } = await app.env.DB
    .prepare(`SELECT * FROM access_grants WHERE resource_did_hash = ? AND revoked_at IS NULL`)
    .bind(didHash).all();
  return (results ?? []) as Array<Record<string, unknown>>;
}

describe("spaces", () => {
  it("creates one owned by the calling org", async () => {
    const a = await makeApp("Firm A");
    const res = await a.app.request("/v1/spaces", {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ name: "Meridian deal" }),
    }, a.env);
    expect(res.status).toBe(201);
    const { space } = await res.json() as { space: { id: string; name: string; ownerOrg: string } };
    expect(space.name).toBe("Meridian deal");
    expect(space.ownerOrg).toBe("Firm A");
  });

  it("refuses an unauthenticated caller", async () => {
    const a = await makeApp("Firm A");
    const res = await a.app.request("/v1/spaces", { method: "POST", body: "{}" }, a.env);
    expect(res.status).toBe(401);
  });

  it("hides a space from a firm that is not in it, as absent rather than forbidden", async () => {
    // 403 would confirm the id exists. A space somebody is not in should not
    // be discoverable by asking about it.
    const a = await makeApp("Firm A");
    const b = await makeApp("Firm B");
    const made = await (await a.app.request("/v1/spaces", {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ name: "Private" }),
    }, a.env)).json() as { space: { id: string } };

    // Firm B's key, added to firm A's database so it can authenticate there.
    // makeApp already seeded B's own database with it, hence no second insert
    // on b.env — that would collide on the unique key hash.
    await a.env.DB.prepare(
      `INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`,
    ).bind(b.keyHash, "Firm B", Date.now()).run();

    const mine = await a.app.request(`/v1/spaces/${made.space.id}`, { headers: auth(a.apiKey) }, a.env);
    expect(mine.status).toBe(200);
    const theirs = await a.app.request(`/v1/spaces/${made.space.id}`, { headers: auth(b.apiKey) }, a.env);
    expect(theirs.status).toBe(404);
  });
});

describe("spaces — invitations", () => {
  it("returns the code exactly once and never stores it", async () => {
    // A registry that can read back its own invitation codes is one whose
    // database leak grants space access.
    const a = await makeApp("Firm A");
    const { space } = await (await a.app.request("/v1/spaces", {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ name: "Deal" }),
    }, a.env)).json() as { space: { id: string } };

    const res = await a.app.request(`/v1/spaces/${space.id}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ note: "for Meridian" }),
    }, a.env);
    expect(res.status).toBe(201);
    const { invite } = await res.json() as { invite: { code: string; id: string } };
    expect(invite.code).toBeTruthy();

    const row = await a.env.DB.prepare(`SELECT * FROM space_invites WHERE id = ?`)
      .bind(invite.id).first() as Record<string, unknown>;
    // The raw code appears nowhere in the row.
    expect(JSON.stringify(row)).not.toContain(invite.code);
    expect(row.code_hash).toBeTruthy();
  });

  it("refuses to invite into a space you do not own", async () => {
    const a = await makeApp("Firm A");
    const { space } = await (await a.app.request("/v1/spaces", {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ name: "Deal" }),
    }, a.env)).json() as { space: { id: string } };

    const otherKey = "another-key-" + Math.random().toString(36).slice(2);
    const { sha256hex } = await import("../auth.js");
    await a.env.DB.prepare(
      `INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`,
    ).bind(await sha256hex(otherKey), "Firm B", Date.now()).run();

    const res = await a.app.request(`/v1/spaces/${space.id}/invites`, {
      method: "POST", headers: auth(otherKey), body: "{}",
    }, a.env);
    expect(res.status).toBe(403);
  });

  it("gives the same answer for every unusable code", async () => {
    // Expired, revoked, already used, never existed — one message. Telling
    // them apart turns this into an oracle for guessing codes.
    const a = await makeApp("Firm A");
    const res = await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ code: "nonsense" }),
    }, a.env);
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("cannot be used");
  });
});

describe("spaces — what joining actually grants", () => {
  /** Firm A owns a space holding one private agent; firm B holds a key. */
  async function twoFirms(): Promise<{
    a: TestApp; spaceId: string; didHash: string; bKey: string; bHash: string;
  }> {
    const a = await makeApp("Firm A");
    const didHash = "0x" + "ab".repeat(16);
    await seedPrivateAgent(a, didHash);

    const { space } = await (await a.app.request("/v1/spaces", {
      method: "POST", headers: auth(a.apiKey), body: JSON.stringify({ name: "Deal" }),
    }, a.env)).json() as { space: { id: string } };

    const bKey = "firm-b-key-" + Math.random().toString(36).slice(2);
    const { sha256hex } = await import("../auth.js");
    const bHash = await sha256hex(bKey);
    await a.env.DB.prepare(
      `INSERT INTO api_keys (key_hash, org_name, created_at, active) VALUES (?, ?, ?, 1)`,
    ).bind(bHash, "Firm B", Date.now()).run();

    return { a, spaceId: space.id, didHash, bKey, bHash };
  }

  it("grants everything already in the space when a firm joins", async () => {
    const { a, spaceId, didHash, bKey, bHash } = await twoFirms();

    await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent" }),
    }, a.env);
    expect(await liveGrants(a, didHash)).toHaveLength(0);

    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };

    const joined = await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);
    expect(joined.status).toBe(200);
    expect(await joined.json()).toMatchObject({ grantsCreated: 1 });

    const grants = await liveGrants(a, didHash);
    expect(grants).toHaveLength(1);
    expect(grants[0].grantee_key_hash).toBe(bHash);
    expect(grants[0].via_space_id).toBe(spaceId);
  });

  it("grants a resource added after somebody joined", async () => {
    const { a, spaceId, didHash, bKey } = await twoFirms();
    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };
    await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);

    const res = await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent" }),
    }, a.env);
    expect(res.status).toBe(201);
    expect(await liveGrants(a, didHash)).toHaveLength(1);
  });

  it("refuses to share a resource the caller does not own", async () => {
    // Otherwise anybody could grant access to somebody else's private agent
    // by adding it to a space they happen to run.
    const { a, spaceId } = await twoFirms();
    const someoneElses = "0x" + "cd".repeat(16);
    const res = await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: someoneElses, resourceType: "agent" }),
    }, a.env);
    expect(res.status).toBe(403);
  });

  it("revokes what the space gave when a member is removed", async () => {
    const { a, spaceId, didHash, bKey, bHash } = await twoFirms();
    await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent" }),
    }, a.env);
    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };
    await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);
    expect(await liveGrants(a, didHash)).toHaveLength(1);

    const removed = await a.app.request(`/v1/spaces/${spaceId}/members/${bHash}`, {
      method: "DELETE", headers: auth(a.apiKey),
    }, a.env);
    expect(removed.status).toBe(200);
    expect(await removed.json()).toMatchObject({ removed: true, grantsRevoked: 1 });
    expect(await liveGrants(a, didHash)).toHaveLength(0);
  });

  it("leaves a hand-written grant alone when the member is removed", async () => {
    // THE PROPERTY via_space_id EXISTS FOR. Somebody given direct access to
    // one agent before being invited keeps it afterwards, which is what they
    // were told when it was granted.
    const { a, spaceId, didHash, bKey, bHash } = await twoFirms();

    // A direct grant, written by hand, with no space behind it.
    await a.env.DB.prepare(
      `INSERT INTO access_grants
         (resource_did_hash, resource_type, grantee_key_hash, granted_by_key_hash, created_at)
       VALUES (?, 'agent', ?, ?, ?)`,
    ).bind(didHash, bHash, a.keyHash, Date.now()).run();

    await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent" }),
    }, a.env);
    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };
    await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);

    // The space added nothing: a live grant already covered the pair.
    const before = await liveGrants(a, didHash);
    expect(before).toHaveLength(1);
    expect(before[0].via_space_id).toBeNull();

    await a.app.request(`/v1/spaces/${spaceId}/members/${bHash}`, {
      method: "DELETE", headers: auth(a.apiKey),
    }, a.env);

    // Still there. Removing them from the space did not take away what a
    // person granted directly.
    const after = await liveGrants(a, didHash);
    expect(after).toHaveLength(1);
    expect(after[0].via_space_id).toBeNull();
  });

  it("revokes everything when the space is archived", async () => {
    const { a, spaceId, didHash, bKey } = await twoFirms();
    await a.app.request(`/v1/spaces/${spaceId}/resources`, {
      method: "POST", headers: auth(a.apiKey),
      body: JSON.stringify({ resourceDidHash: didHash, resourceType: "agent" }),
    }, a.env);
    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };
    await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);

    const res = await a.app.request(`/v1/spaces/${spaceId}`, {
      method: "DELETE", headers: auth(a.apiKey),
    }, a.env);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ archived: true, grantsRevoked: 1 });
    expect(await liveGrants(a, didHash)).toHaveLength(0);
  });

  it("cannot redeem the same code twice", async () => {
    const { a, spaceId, bKey } = await twoFirms();
    const { invite } = await (await a.app.request(`/v1/spaces/${spaceId}/invites`, {
      method: "POST", headers: auth(a.apiKey), body: "{}",
    }, a.env)).json() as { invite: { code: string } };

    const first = await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);
    expect(first.status).toBe(200);

    const second = await a.app.request("/v1/spaces/join", {
      method: "POST", headers: auth(bKey), body: JSON.stringify({ code: invite.code }),
    }, a.env);
    expect(second.status).toBe(404);
  });
});
