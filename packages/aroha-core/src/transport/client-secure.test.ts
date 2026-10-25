// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/** N4: ArohaClient refuses cleartext to non-loopback hosts unless allowInsecureHttp. */

import { describe, it, expect, vi, afterEach } from "vitest";
import { ArohaClient } from "./client.js";
import { InsecureEndpointError } from "../endpoints/index.js";
import type { ArohaEnvelope } from "../messages/envelope.js";

afterEach(() => { vi.unstubAllGlobals(); });
const env = {} as ArohaEnvelope;

describe("ArohaClient endpoint policy", () => {
  it("refuses http:// to a remote host before any request is made", async () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    await expect(new ArohaClient().send("http://agent.example.com/aroha/v1", env)).rejects.toThrow(InsecureEndpointError);
    expect(f).not.toHaveBeenCalled();
    expect(() => new ArohaClient().stream("ws://agent.example.com/aroha/stream", "cid")).toThrow(InsecureEndpointError);
    await expect(new ArohaClient().fetchDIDDocument("http://agent.example.com")).rejects.toThrow(InsecureEndpointError);
  });

  it("allows loopback http, https, and remote http with allowInsecureHttp", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 202 })));
    await expect(new ArohaClient().send("http://127.0.0.1:9/aroha/v1", env)).resolves.toBeNull();
    await expect(new ArohaClient().send("https://agent.example.com/aroha/v1", env)).resolves.toBeNull();
    await expect(new ArohaClient({ allowInsecureHttp: true }).send("http://10.0.0.5/aroha/v1", env)).resolves.toBeNull();
  });
});
