// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0
//
// The D1-backed KelStore against the core KelStore contract, plus the one
// behaviour the in-memory store never needs: a conditional write that cannot
// let a shorter log replace a longer one, and that turns two concurrent,
// different same-length logs into a recorded fork rather than a silent
// last-writer-wins.

import { describe, it, expect } from "vitest";
import { incept, rotateKel, acceptKel, eventDigest } from "@aroha-sdk/core";
import { D1Repository } from "./d1-repository.js";
import { RepositoryKelStore } from "./kel-store.js";
import { openDb } from "./test-utils/sqlite-d1.js";
import { FULL_SCHEMA } from "./test-utils/make-app.js";

function makeStore() {
  const { adapter } = openDb(FULL_SCHEMA);
  const repo = new D1Repository(adapter as unknown as D1Database);
  return { repo, store: new RepositoryKelStore(repo) };
}

describe("RepositoryKelStore", () => {
  it("round-trips a log and its denormalised sequence/digest", async () => {
    const { repo, store } = makeStore();
    const id = await rotateKel(await incept({ kind: "agent" }));
    await store.put(id.did, id.kel);
    expect(await store.get(id.did)).toEqual(id.kel);
    const row = await repo.getKelLog(id.did);
    expect(row).toMatchObject({ sequence: 1, lastDigest: eventDigest(id.kel[1]) });
  });

  it("never lets a shorter log overwrite a longer one", async () => {
    const { store } = makeStore();
    const id = await incept({ kind: "agent" });
    const rotated = await rotateKel(id);
    await store.put(id.did, rotated.kel);
    await store.put(id.did, id.kel); // a lagging writer that lost the race
    expect(await store.get(id.did)).toEqual(rotated.kel);
  });

  it("turns a concurrent, different same-length write into recorded duplicity", async () => {
    const { store } = makeStore();
    const id = await incept({ kind: "agent" });
    const a = await rotateKel(id);
    const b = await rotateKel(id);
    // Both requests read "inception only" and both decide they are longer —
    // simulated by calling put() directly, as acceptKel would after its read.
    await store.put(id.did, a.kel);
    await expect(store.put(id.did, b.kel)).rejects.toMatchObject({ code: "duplicity" });
    expect(await store.getDuplicity(id.did)).toMatchObject({ did: id.did, seq: 1 });
    expect(await store.get(id.did)).toEqual(a.kel);
  });

  it("keeps the FIRST duplicity evidence per DID", async () => {
    const { store } = makeStore();
    const first = { did: "did:aroha:Ex", seq: 1, digests: ["Ea", "Eb"] as [string, string], detectedAt: "t1" };
    await store.recordDuplicity(first);
    await store.recordDuplicity({ ...first, seq: 2, detectedAt: "t2" });
    expect(await store.getDuplicity("did:aroha:Ex")).toEqual(first);
  });

  it("satisfies acceptKel's contract: stale rejected, fork alarmed and then refused", async () => {
    const { store } = makeStore();
    const id = await incept({ kind: "person" });
    const a = await rotateKel(id);
    await acceptKel(id.did, a.kel, store);
    await expect(acceptKel(id.did, id.kel, store)).rejects.toMatchObject({ code: "stale" });
    await expect(acceptKel(id.did, (await rotateKel(id)).kel, store)).rejects.toMatchObject({ code: "duplicity" });
    await expect(acceptKel(id.did, a.kel, store)).rejects.toMatchObject({ code: "duplicity" });
  });
});
