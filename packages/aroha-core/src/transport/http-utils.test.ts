// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * readBody — the server's only defence against an oversized request body is
 * this byte counter, so it must reject (once) past the cap and stop reading.
 */

import { describe, it, expect } from "vitest";
import { PassThrough } from "node:stream";
import type { IncomingMessage } from "node:http";
import { readBody } from "./http-utils.js";

function fakeReq(): PassThrough & { destroyedCalled: boolean } {
  const s = new PassThrough() as PassThrough & { destroyedCalled: boolean };
  s.destroyedCalled = false;
  const orig = s.destroy.bind(s);
  s.destroy = ((err?: Error) => { s.destroyedCalled = true; return orig(err); }) as typeof s.destroy;
  return s;
}

describe("readBody", () => {
  it("concatenates chunks and decodes UTF-8 (including multi-byte characters split across chunks)", async () => {
    const req = fakeReq();
    const p = readBody(req as unknown as IncomingMessage);
    const bytes = Buffer.from("héllo wörld", "utf8");
    req.write(bytes.subarray(0, 2)); // splits the 2-byte "é"
    req.write(bytes.subarray(2));
    req.end();
    expect(await p).toBe("héllo wörld");
  });

  it("resolves an empty string for an empty body", async () => {
    const req = fakeReq();
    const p = readBody(req as unknown as IncomingMessage);
    req.end();
    expect(await p).toBe("");
  });

  it("accepts a body of exactly maxBytes", async () => {
    const req = fakeReq();
    const p = readBody(req as unknown as IncomingMessage, 4);
    req.end(Buffer.from("abcd"));
    expect(await p).toBe("abcd");
  });

  it("rejects with PAYLOAD_TOO_LARGE past maxBytes and destroys the request", async () => {
    const req = fakeReq();
    const p = readBody(req as unknown as IncomingMessage, 4);
    req.write(Buffer.from("abc"));
    req.write(Buffer.from("de"));
    await expect(p).rejects.toMatchObject({ code: "PAYLOAD_TOO_LARGE" });
    expect(req.destroyedCalled).toBe(true);
  });

  it("propagates a stream error", async () => {
    const req = fakeReq();
    const p = readBody(req as unknown as IncomingMessage);
    req.emit("error", new Error("socket reset"));
    await expect(p).rejects.toThrow("socket reset");
  });
});
