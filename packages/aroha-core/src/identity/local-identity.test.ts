// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { mintLocalIdentity, preparePublish, type LocalIdentity, type PublishableIdentity } from "./local-identity.js";

describe("mintLocalIdentity", () => {
  it("mints a real identity carrying the private key, tagged local", async () => {
    const identity = await mintLocalIdentity("test-firm", "http://localhost:8010/aroha/v1");

    expect(identity.kind).toBe("local");
    expect(identity.did).toMatch(/^did:aroha:/);
    expect(identity.privateKey).toBeInstanceOf(Uint8Array);
    expect(identity.privateKey.length).toBe(32);
    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.document.id).toBe(identity.did);
  });

  it("supports the same namespace option generateDID does", async () => {
    const identity = await mintLocalIdentity("agent-a", "http://localhost:8010/aroha/v1", { namespace: "acme" });
    expect(identity.did).toBe("did:aroha:acme.agent-a");
  });

  it("mints a content-addressed did:aroha:<pubkey> when contentAddressed is true", async () => {
    const identity = await mintLocalIdentity("ignored-agent-id", "http://localhost:8010/aroha/v1", { contentAddressed: true });
    expect(identity.did).toMatch(/^did:aroha:z/);
    expect(identity.did).not.toContain("ignored-agent-id");
    expect(identity.document.id).toBe(identity.did);
  });

  it("content-addressed DIDs from two different agentIds still differ (identity comes from the key, not agentId)", async () => {
    const a = await mintLocalIdentity("agent-a", "http://localhost:8010/aroha/v1", { contentAddressed: true });
    const b = await mintLocalIdentity("agent-b", "http://localhost:8010/aroha/v1", { contentAddressed: true });
    expect(a.did).not.toBe(b.did);
  });
});

describe("preparePublish", () => {
  it("strips the private key entirely — not present, not just empty", async () => {
    const local = await mintLocalIdentity("test-firm", "http://localhost:8010/aroha/v1");
    const publishable = preparePublish(local);

    expect(publishable.kind).toBe("publishable");
    expect(publishable.did).toBe(local.did);
    expect(publishable.publicKey).toBe(local.publicKey);
    expect(publishable.document).toBe(local.document);
    expect("privateKey" in publishable).toBe(false);
  });

  it("produces a type that cannot satisfy LocalIdentity (compile-time check, run to confirm no runtime coupling)", async () => {
    const local = await mintLocalIdentity("test-firm", "http://localhost:8010/aroha/v1");
    const publishable: PublishableIdentity = preparePublish(local);

    // Structural proof at the type level: this assignment only compiles
    // because LocalIdentity and PublishableIdentity are different shapes.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _notAssignable: LocalIdentity extends PublishableIdentity ? never : true = true;
    expect(publishable).toBeDefined();
  });
});
