// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { isCredentialExpired } from "./credentials.js";

type VC = Parameters<typeof isCredentialExpired>[0];

describe("isCredentialExpired (M4: fail closed on NaN)", () => {
  it("treats an unparseable expirationDate as expired", () => {
    expect(isCredentialExpired({ expirationDate: "not-a-date" } as unknown as VC)).toBe(true);
  });
  it("past is expired, future is not, absent means no expiry", () => {
    expect(isCredentialExpired({ expirationDate: new Date(Date.now() - 1000).toISOString() } as unknown as VC)).toBe(true);
    expect(isCredentialExpired({ expirationDate: new Date(Date.now() + 60_000).toISOString() } as unknown as VC)).toBe(false);
    expect(isCredentialExpired({} as unknown as VC)).toBe(false);
  });
});
