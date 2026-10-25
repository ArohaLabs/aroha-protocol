// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Device labels on API keys.
 *
 * Somebody who connects Aroha on a laptop, a desktop and a work machine ends
 * up with three live keys. Without a label the list shows three rows that
 * differ by a hash and a timestamp, so revoking the right one is guesswork —
 * and guessing wrong cuts off the machine they are sitting at.
 *
 * The label exists only to be read. These tests hold that line in both
 * directions: it must survive the round trip, and it must never influence who
 * a key belongs to.
 */

import { describe, it, expect } from "vitest";
import { D1Repository } from "./d1-repository.js";
import { openDb, API_KEYS_SCHEMA } from "./test-utils/sqlite-d1.js";

function makeRepo() {
  const { db, adapter } = openDb(API_KEYS_SCHEMA);
  return { db, repo: new D1Repository(adapter as unknown as D1Database) };
}

describe("api key device labels", () => {
  it("gives back the label the key was minted with", async () => {
    const { repo } = makeRepo();
    await repo.insertKey("hash-a", "Someone", "github:1", "Rangas-MacBook");

    const keys = await repo.listKeysByOwner("github:1");
    expect(keys).toHaveLength(1);
    expect(keys[0]!.label).toBe("Rangas-MacBook");
  });

  it("lists an older unlabelled key as null rather than failing", async () => {
    // Every key minted before migration 013 has a NULL label, and a caller
    // that asked for none is legitimate too. The list has to render those
    // rows, not omit them — an invisible key cannot be revoked.
    const { repo } = makeRepo();
    await repo.insertKey("hash-b", "Someone", "github:1");

    const keys = await repo.listKeysByOwner("github:1");
    expect(keys[0]!.label).toBeNull();
  });

  it("tells three machines apart in one list", async () => {
    // The situation the feature is for.
    const { repo } = makeRepo();
    await repo.insertKey("hash-1", "Someone", "github:1", "work-laptop");
    await repo.insertKey("hash-2", "Someone", "github:1", "home-desktop");
    await repo.insertKey("hash-3", "Someone", "github:1", "travel-mac");

    const labels = (await repo.listKeysByOwner("github:1")).map((k) => k.label).sort();
    expect(labels).toEqual(["home-desktop", "travel-mac", "work-laptop"]);
  });

  it("does not let a label reach across owners", async () => {
    // The label is app-supplied text, so it must carry no authority at all.
    // Naming your machine after somebody else's account changes nothing:
    // owner_id alone decides whose key this is.
    const { repo } = makeRepo();
    await repo.insertKey("hash-mine", "Me", "github:1", "github:2");

    expect(await repo.listKeysByOwner("github:2")).toHaveLength(0);
    expect(await repo.listKeysByOwner("github:1")).toHaveLength(1);
  });

  it("still scopes revocation by owner, label or not", async () => {
    const { repo } = makeRepo();
    await repo.insertKey("hash-theirs", "Them", "github:2", "their-laptop");

    expect(await repo.revokeKey("hash-theirs", "github:1")).toBe(false);
    expect(await repo.revokeKey("hash-theirs", "github:2")).toBe(true);
    expect(await repo.listKeysByOwner("github:2")).toHaveLength(0);
  });
});
