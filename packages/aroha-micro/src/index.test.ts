// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * The public entry must export every type its options use, so callers can
 * type a `resolvePublicKey` without importing from @aroha-sdk/core.
 * This is a type-level check: it fails under `tsc` (or `vitest --typecheck`),
 * not at runtime, if the export is missing.
 */

import { describe, it, expectTypeOf } from "vitest";
import type { PublicKeyResolver as CorePublicKeyResolver } from "@aroha-sdk/core";
import type { MicroAgentOptions, PublicKeyResolver } from "./index.js";

describe("@aroha-sdk/micro public types", () => {
  it("exports PublicKeyResolver, the type of MicroAgentOptions.resolvePublicKey", () => {
    expectTypeOf<PublicKeyResolver>().toEqualTypeOf<CorePublicKeyResolver>();
    expectTypeOf<MicroAgentOptions["resolvePublicKey"]>().toEqualTypeOf<PublicKeyResolver | undefined>();
  });
});
