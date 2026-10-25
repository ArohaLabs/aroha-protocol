// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, afterEach } from "vitest";
import {
  assertSecureEndpoint, isLoopbackHost, InsecureEndpointError,
  resolveRegistryUrl, resolveIpfsGateway, AROHA_MANAGED_REGISTRY_URL, AROHA_DEFAULT_IPFS_GATEWAY,
} from "./index.js";

describe("assertSecureEndpoint", () => {
  it("accepts https and wss anywhere", () => {
    expect(assertSecureEndpoint("https://agent.example.com/v1").hostname).toBe("agent.example.com");
    expect(() => assertSecureEndpoint("wss://agent.example.com")).not.toThrow();
  });

  it("accepts http to loopback only", () => {
    for (const u of ["http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:1", "http://b.localhost", "ws://127.9.9.9"]) {
      expect(() => assertSecureEndpoint(u)).not.toThrow();
    }
    for (const u of ["http://agent.example.com", "http://10.0.0.5", "http://127.0.0.1.example.com", "ws://192.168.1.2"]) {
      expect(() => assertSecureEndpoint(u)).toThrow(InsecureEndpointError);
    }
  });

  it("allowInsecureHttp opts in to remote http", () => {
    expect(() => assertSecureEndpoint("http://10.0.0.5", { allowInsecureHttp: true })).not.toThrow();
  });

  it("refuses other schemes and garbage", () => {
    expect(() => assertSecureEndpoint("file:///etc/passwd")).toThrow(/unsupported scheme/);
    expect(() => assertSecureEndpoint("not a url", { label: "registryUrl" })).toThrow(/registryUrl/);
  });

  it("isLoopbackHost rejects out-of-range octets", () => {
    expect(isLoopbackHost("127.0.0.256")).toBe(false);
    expect(isLoopbackHost("LOCALHOST")).toBe(true);
  });
});

describe("registry / IPFS defaults", () => {
  const saved = { r: process.env.AROHA_REGISTRY_URL, i: process.env.AROHA_IPFS_GATEWAY };
  afterEach(() => {
    if (saved.r === undefined) delete process.env.AROHA_REGISTRY_URL; else process.env.AROHA_REGISTRY_URL = saved.r;
    if (saved.i === undefined) delete process.env.AROHA_IPFS_GATEWAY; else process.env.AROHA_IPFS_GATEWAY = saved.i;
  });

  it("defaults to the managed constants, env overrides, explicit wins", () => {
    delete process.env.AROHA_REGISTRY_URL;
    delete process.env.AROHA_IPFS_GATEWAY;
    expect(resolveRegistryUrl()).toBe(AROHA_MANAGED_REGISTRY_URL);
    expect(resolveIpfsGateway()).toBe(AROHA_DEFAULT_IPFS_GATEWAY);
    process.env.AROHA_REGISTRY_URL = "https://reg.example.com/";
    process.env.AROHA_IPFS_GATEWAY = "https://gw.example.com/ipfs";
    expect(resolveRegistryUrl()).toBe("https://reg.example.com");
    expect(resolveIpfsGateway()).toBe("https://gw.example.com/ipfs");
    expect(resolveRegistryUrl("https://mine.example.com")).toBe("https://mine.example.com");
  });
});
