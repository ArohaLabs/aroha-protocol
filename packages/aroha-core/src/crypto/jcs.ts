// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Where this lives, and why: it started in @aroha-sdk/credentials (mandate
 * tokens were its first user). Key Event Logs (identity/kel.ts) now sign
 * over JCS too, and core sits BELOW credentials in the dependency graph
 * (credentials depends on core, never the reverse), so the one
 * implementation moved here. credentials re-exports it from its old module
 * path, so `import { canonicalizeJcs } from "@aroha-sdk/credentials"` keeps
 * working. Two copies would be worse than one: a signature is only as
 * portable as the agreement between the bytes the signer and the verifier
 * produce, and two implementations can drift.
 *
 * Why this exists: a signature is only portable if every SDK produces the
 * same bytes for the same mandate. The v1 mandate format signed
 * `JSON.stringify(sortKeys(body))`, which is "whatever V8 does" — it happens
 * to agree with JCS for most inputs, but nothing pins it down, and a Python
 * or Go verifier that formats `0.1 + 0.2` or `1e21` its own way would reject
 * a perfectly valid mandate (or, worse, two SDKs would disagree on which
 * bytes a signature covers). RFC 8785 is the published rule set, so a
 * conformant implementation in any language reproduces these bytes exactly.
 *
 * The rules, and how each is met here:
 *   - Object keys sorted by UTF-16 code units. JavaScript's default
 *     Array.prototype.sort() compares strings by UTF-16 code unit, which is
 *     precisely the RFC's ordering (it is NOT locale or code-point order —
 *     an astral-plane key sorts by its surrogate pair).
 *   - Numbers serialised with the ECMAScript Number-to-String algorithm
 *     (ECMA-262 §7.1.12.1), which is what JSON.stringify(number) does. -0
 *     serialises as "0". NaN and ±Infinity are not representable in JSON and
 *     are rejected rather than silently written as "null".
 *   - Strings serialised as JSON.stringify does (the RFC adopts ECMAScript's
 *     escaping: \b \t \n \f \r \" \\ and \u00XX for other controls, no other
 *     escaping). Lone surrogates are rejected — RFC 8785 requires I-JSON
 *     (RFC 7493), which forbids them, and different runtimes repair them
 *     differently.
 *   - No insignificant whitespace.
 *
 * One deliberate convenience beyond the RFC: an object property whose value
 * is `undefined` is omitted, exactly as JSON.stringify omits it. TypeScript
 * objects routinely carry optional fields set to undefined; the token that
 * travels on the wire is JSON, where those fields simply do not exist, so
 * the signer and the verifier must both canonicalise them as absent.
 * `undefined` anywhere else (top level, inside an array) is an error.
 */
export function canonicalizeJcs(value: unknown): string {
  return serialize(value, "$");
}

function serialize(value: unknown, path: string): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError(`JCS: non-finite number at ${path} cannot be canonicalised`);
      }
      // JSON.stringify(n) IS the ECMAScript Number serialisation, and maps -0 to "0".
      return JSON.stringify(value);

    case "string":
      assertWellFormed(value, path);
      return JSON.stringify(value);

    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v, i) => {
          if (v === undefined) throw new TypeError(`JCS: undefined array element at ${path}[${i}]`);
          return serialize(v, `${path}[${i}]`);
        }).join(",") + "]";
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        // Dates, Maps, class instances: their JSON form depends on toJSON()
        // and is not something two SDKs would agree on. Convert explicitly.
        throw new TypeError(`JCS: only plain objects can be canonicalised (at ${path})`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return "{" + keys.map((k) => {
        assertWellFormed(k, `${path} (key)`);
        return JSON.stringify(k) + ":" + serialize(obj[k], `${path}.${k}`);
      }).join(",") + "}";
    }

    default:
      // undefined, bigint, symbol, function
      throw new TypeError(`JCS: value of type ${typeof value} at ${path} is not JSON`);
  }
}

/** Reject lone UTF-16 surrogates (I-JSON, RFC 7493 §2.1). */
function assertWellFormed(s: string, path: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) { i++; continue; }
      throw new TypeError(`JCS: lone high surrogate in string at ${path}`);
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
      throw new TypeError(`JCS: lone low surrogate in string at ${path}`);
    }
  }
}
