# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
aroha.nonce_store — pluggable replay stores for :class:`aroha.messages.NonceRegistry`.

Port of the TypeScript ``NonceStore`` / ``MapNonceStore`` / ``FileNonceStore``
(aroha-core/src/messages/nonce.ts and file-nonce-store.ts).

Default: :class:`MapNonceStore` (in-process, forgotten on restart). Recommended:

* single instance → :class:`FileNonceStore`, so a restart does not reopen the
  replay window for envelopes that have not yet expired;
* multiple instances → a shared store (e.g. Redis ``SET key NX PXAT expiry``)
  implementing :class:`NonceStore`.

Keys passed by :func:`aroha.messages.validate_envelope` are sender-scoped
(``"<fromDID>:<nonce>"``) and are recorded only AFTER the envelope's signature
verified, so unauthenticated traffic cannot fill the store.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Protocol, runtime_checkable

from aroha.timeutil import now_ms

__all__ = ["NonceStore", "MapNonceStore", "FileNonceStore"]


@runtime_checkable
class NonceStore(Protocol):
    """Replay-store backend.

    ``set_if_absent`` records ``key`` until ``expiry_ms`` (absolute Unix ms) and
    returns True if it was fresh, False if it was already recorded (replay).
    It must be atomic with respect to concurrent callers. ``evict_expired``
    drops records whose expiry has passed.
    """

    def set_if_absent(self, key: str, expiry_ms: int) -> bool: ...

    def evict_expired(self) -> None: ...


class MapNonceStore:
    """In-process store. A restart forgets every nonce."""

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def set_if_absent(self, key: str, expiry_ms: int) -> bool:
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = int(expiry_ms)
            return True

    def evict_expired(self) -> None:
        now = now_ms()
        with self._lock:
            for k in [k for k, e in self._seen.items() if e < now]:
                del self._seen[k]

    def __len__(self) -> int:
        return len(self._seen)


class FileNonceStore:
    """File-backed store for a single-instance deployment.

    Format: append-only JSON Lines, one ``{"k": <key>, "e": <expiryMs>}`` per
    accepted nonce — the same format as the TypeScript ``FileNonceStore``. On
    construction the file is replayed into memory (expired and malformed
    lines, e.g. a torn final line after a crash, are skipped).
    :meth:`evict_expired` drops expired entries and, once
    ``compact_after_evictions`` have expired, rewrites the live set to a temp
    file and renames it over the original.

    Durability: each accepted nonce is appended BEFORE :meth:`set_if_absent`
    returns True; if the write fails the exception propagates and the
    envelope is rejected (fail closed). ``fsync=True`` also flushes to stable
    storage on every write.

    One process per file: the in-memory map is the source of truth for the
    duplicate check. Use a shared store for multi-instance setups.
    """

    def __init__(self, file_path: str, *, fsync: bool = False, compact_after_evictions: int = 1000) -> None:
        self._path = os.fspath(file_path)
        self._fsync = fsync
        self._compact_after = compact_after_evictions
        self._seen: dict[str, int] = {}
        self._evicted_since_compaction = 0
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        now = now_ms()
        stale = 0
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    k, e = rec.get("k"), rec.get("e")
                    if not isinstance(k, str) or isinstance(e, bool) or not isinstance(e, (int, float)):
                        stale += 1
                        continue
                    if e < now:
                        stale += 1
                        continue
                    prev = self._seen.get(k)
                    if prev is None or e > prev:
                        self._seen[k] = int(e)
                except Exception:
                    # Torn/garbled line (e.g. crash mid-append): skip it.
                    stale += 1
        self._evicted_since_compaction = stale
        if stale >= self._compact_after:
            self._compact()

    def _append(self, key: str, expiry_ms: int) -> None:
        line = json.dumps({"k": key, "e": expiry_ms}, separators=(",", ":"), ensure_ascii=False) + "\n"
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line)
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    def _compact(self) -> None:
        tmp = f"{self._path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for k, e in self._seen.items():
                f.write(json.dumps({"k": k, "e": e}, separators=(",", ":"), ensure_ascii=False) + "\n")
        os.replace(tmp, self._path)
        self._evicted_since_compaction = 0

    def set_if_absent(self, key: str, expiry_ms: int) -> bool:
        with self._lock:
            existing = self._seen.get(key)
            if existing is not None and existing >= now_ms():
                return False
            # Persist first: if the write raises, the nonce is NOT reported fresh.
            self._append(key, int(expiry_ms))
            self._seen[key] = int(expiry_ms)
            return True

    def evict_expired(self) -> None:
        now = now_ms()
        with self._lock:
            for k in [k for k, e in self._seen.items() if e < now]:
                del self._seen[k]
                self._evicted_since_compaction += 1
            if self._evicted_since_compaction >= self._compact_after:
                self._compact()

    def __len__(self) -> int:
        return len(self._seen)
