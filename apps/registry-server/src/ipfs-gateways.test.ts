// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, vi } from "vitest";
import { AROHA_DEFAULT_IPFS_GATEWAY } from "@aroha-sdk/core/endpoints";
import { manifestGatewayAttempts, PINATA_API_GATEWAY } from "./ipfs-gateways.js";

describe("manifestGatewayAttempts", () => {
  it("uses only the Aroha gateway when nothing else is configured", () => {
    expect(manifestGatewayAttempts("bafyX", {}).map((a) => a.url)).toEqual([`${AROHA_DEFAULT_IPFS_GATEWAY}/bafyX`]);
    expect(manifestGatewayAttempts("bafyX", { IPFS_GATEWAY: "https://gw.example/ipfs/" }).map((a) => a.url))
      .toEqual(["https://gw.example/ipfs/bafyX"]);
  });

  it("puts authenticated Pinata first only when PINATA_JWT is set", () => {
    const [first] = manifestGatewayAttempts("bafyX", { PINATA_JWT: "jwt", IPFS_GATEWAY: "https://gw.example/ipfs" });
    expect(first.url).toBe(`${PINATA_API_GATEWAY}/bafyX`);
    expect(first.headers).toEqual({ Authorization: "Bearer jwt" });
  });

  it("appends explicit https fallbacks, skipping duplicates and non-https entries", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const urls = manifestGatewayAttempts("bafyX", {
      IPFS_GATEWAY: "https://gw.example/ipfs",
      IPFS_FALLBACK_GATEWAYS: " https://dweb.link/ipfs , https://gw.example/ipfs, http://plain.example/ipfs, ",
    }).map((a) => a.url);
    expect(urls).toEqual(["https://gw.example/ipfs/bafyX", "https://dweb.link/ipfs/bafyX"]);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });
});
