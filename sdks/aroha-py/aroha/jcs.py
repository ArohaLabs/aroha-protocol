# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
RFC 8785 JSON Canonicalization Scheme (JCS), byte-compatible with
``canonicalizeJcs`` in @aroha-sdk/core (packages/aroha-core/src/crypto/jcs.ts).

Also provides :func:`js_stringify_sorted`, an emulation of the TypeScript
SDK's *legacy* canonical form ``JSON.stringify(sortKeysDeep(value))``, which
is what message envelopes (and v1 mandate tokens) are still signed over.

Why both exist: a signature is only portable if every SDK produces the same
bytes. Python's ``json.dumps(sort_keys=True)`` disagrees with JavaScript on
numbers (``10.0`` vs ``10``, ``1e-07`` vs ``1e-7``, ``1e+21``), on non-ASCII
escaping (``ensure_ascii``), and on key order (code-point vs UTF-16 code
unit). Both functions below reproduce the JavaScript bytes exactly.

Rules implemented by :func:`canonicalize_jcs`:
  - object keys sorted by UTF-16 code units (not code points);
  - numbers formatted with the ECMAScript Number::toString algorithm
    (shortest round-trip digits, ``1e+21`` / ``1e-7`` exponent rules,
    ``-0`` -> ``0``); integers without ``.0``; NaN / Infinity rejected;
  - strings escaped as ``JSON.stringify`` does (``\\b \\t \\n \\f \\r \\" \\\\``
    and ``\\u00xx`` for other controls, nothing else); lone surrogates rejected;
  - no insignificant whitespace.
"""

from __future__ import annotations

import math
from typing import Any

__all__ = [
    "canonicalize_jcs",
    "js_stringify_sorted",
    "format_es_number",
    "JcsError",
]


class JcsError(TypeError):
    """Raised when a value cannot be canonicalised (non-finite number, lone surrogate, non-JSON type)."""


_MAX_SAFE = 2 ** 53


# ── Numbers ───────────────────────────────────────────────────────────────────

def format_es_number(x: Any, *, path: str = "$") -> str:
    """Format a number exactly as ECMAScript ``Number.prototype.toString`` / ``JSON.stringify`` does.

    Raises :class:`JcsError` for NaN and +/-Infinity.
    """
    if isinstance(x, bool):
        raise JcsError(f"JCS: boolean at {path} is not a number")
    if isinstance(x, int):
        if -_MAX_SAFE < x < _MAX_SAFE:
            return str(x)
        # A JavaScript peer holds this value as an IEEE-754 double; format
        # what it would have parsed.
        try:
            x = float(x)
        except OverflowError:
            raise JcsError(f"JCS: integer at {path} is too large to be a JSON number") from None
    if not isinstance(x, float):
        raise JcsError(f"JCS: value of type {type(x).__name__} at {path} is not a number")
    if math.isnan(x) or math.isinf(x):
        raise JcsError(f"JCS: non-finite number at {path} cannot be canonicalised")
    if x == 0:
        return "0"  # also -0

    sign = "-" if x < 0 else ""
    # repr() gives the shortest digit string that round-trips (same digits
    # ECMAScript picks); only the layout differs, which is rebuilt below.
    r = repr(abs(x))
    mantissa, _, exp_str = r.partition("e")
    exp = int(exp_str) if exp_str else 0
    int_part, _, frac = mantissa.partition(".")
    all_digits = int_part + frac
    point = len(int_part) + exp  # decimal point sits after this many digits
    stripped = all_digits.lstrip("0")
    point -= len(all_digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    k = len(digits)
    n = point

    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        e_str = ("+" if e >= 0 else "-") + str(abs(e))
        out = digits + "e" + e_str if k == 1 else digits[0] + "." + digits[1:] + "e" + e_str
    return sign + out


# ── Strings ───────────────────────────────────────────────────────────────────

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _join_surrogate_pairs(s: str) -> str:
    """Combine explicit surrogate pairs ("\\ud83d\\ude00" as two chars) into one code point."""
    if not any(0xD800 <= ord(c) <= 0xDFFF for c in s):
        return s
    return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _quote(s: str, path: str, *, reject_lone_surrogates: bool) -> str:
    s = _join_surrogate_pairs(s)
    out = ['"']
    for ch in s:
        o = ord(ch)
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        elif 0xD800 <= o <= 0xDFFF:
            if reject_lone_surrogates:
                kind = "high" if o <= 0xDBFF else "low"
                raise JcsError(f"JCS: lone {kind} surrogate in string at {path}")
            # JSON.stringify (ES2019 well-formed stringify) escapes lone surrogates.
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly like UTF-16 code-unit sequences.
    return _join_surrogate_pairs(s).encode("utf-16-be", "surrogatepass")


# ── JCS ───────────────────────────────────────────────────────────────────────

def canonicalize_jcs(value: Any) -> str:
    """RFC 8785 canonical JSON of ``value`` (dict/list/tuple/str/int/float/bool/None)."""
    return _jcs(value, "$")


def _jcs(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return format_es_number(value, path=path)
    if isinstance(value, str):
        return _quote(value, path, reject_lone_surrogates=True)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise JcsError(f"JCS: non-string key {k!r} at {path}")
        keys = sorted(value.keys(), key=_utf16_key)
        return "{" + ",".join(
            _quote(k, f"{path} (key)", reject_lone_surrogates=True) + ":" + _jcs(value[k], f"{path}.{k}")
            for k in keys
        ) + "}"
    raise JcsError(f"JCS: value of type {type(value).__name__} at {path} is not JSON")


# ── Legacy JS canonical form: JSON.stringify(sortKeysDeep(value)) ─────────────

_ARRAY_INDEX_MAX = 2 ** 32 - 2


def _is_array_index(k: str) -> bool:
    # ECMAScript "array index": canonical decimal string of an integer in
    # [0, 2^32 - 2]. JS objects enumerate these keys FIRST, in ascending
    # numeric order, whatever order they were inserted in.
    if not k or not k.isascii() or not k.isdigit():
        return False
    if len(k) > 1 and k[0] == "0":
        return False
    return int(k) <= _ARRAY_INDEX_MAX


def js_stringify_sorted(value: Any) -> str:
    """Byte-exact emulation of TypeScript ``JSON.stringify(sortKeysDeep(value))``.

    This is the canonical form envelope signatures (``signMessage``) and v1
    mandate tokens use. It is NOT JCS: integer-like keys come first in
    numeric order (JavaScript property enumeration), non-finite numbers
    become ``null``, and lone surrogates are escaped rather than rejected.
    """
    return _js(value, "$")


def _js(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return "null"
    if isinstance(value, (int, float)):
        try:
            return format_es_number(value, path=path)
        except JcsError:
            return "null"
    if isinstance(value, str):
        return _quote(value, path, reject_lone_surrogates=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_js(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise JcsError(f"non-string key {k!r} at {path}")
        sorted_keys = sorted(value.keys(), key=_utf16_key)
        index_keys = sorted((k for k in sorted_keys if _is_array_index(k)), key=int)
        other_keys = [k for k in sorted_keys if not _is_array_index(k)]
        return "{" + ",".join(
            _quote(k, path, reject_lone_surrogates=False) + ":" + _js(value[k], f"{path}.{k}")
            for k in index_keys + other_keys
        ) + "}"
    raise JcsError(f"value of type {type(value).__name__} at {path} is not JSON")
