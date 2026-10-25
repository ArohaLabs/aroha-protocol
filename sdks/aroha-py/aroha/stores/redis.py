# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
Redis stores (redis-py 5+, synchronous) — ``pip install "aroha[redis]"``.

Durable, shared implementations of the three store interfaces:

- ``RedisHttpPresentationNonces`` — ``HttpPresentationNonceStore``
  (``aroha.http_mandate``): ``SET key 1 NX PX ttl``.
- ``RedisEnrollmentStore`` — ``EnrollmentStore`` (``aroha.enrollment``):
  challenge issue and consume are Lua scripts (consume = get-and-delete in
  one step); bindings are plain strings.
- ``RedisSpendingLedger`` — ``SpendingLedger`` (``aroha.spending_ledger``):
  init / allocate / release are Lua scripts, so the check-and-add is atomic.

Key layout (``P`` = ``key_prefix``, default ``"aroha:"``)::

    P nonce:<holder> <nonce>          "1", PX until the presentation expires
    P enroll:challenge:<challenge>    JSON {"accountId", "expiresAtMs"}, PX until expiry
    P enroll:challenges               ZSET challenge -> expiresAtMs (bounds outstanding challenges)
    P enroll:binding:<accountId>      the DID
    P ledger:budget:<key>             HASH {limit, allocated}  (integer micro-USD)
    P ledger:alloc:<key>              HASH allocationId -> micro-USD

The scripts touch two keys each (challenge + index, budget + allocations).
On Redis Cluster put a hash tag in the prefix (``"{aroha}:"``) so they share
a slot. Persistence is Redis's: run it with AOF (``appendonly yes``) or the
"durable" store is only as durable as the last RDB snapshot.

Errors are never swallowed: a Redis error propagates, and the verifiers turn
it into NONCE_STORE_UNAVAILABLE / STORE_UNAVAILABLE / LEDGER_UNAVAILABLE.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any, Optional

try:
    import redis as _redis  # noqa: F401  (import check: the extra is installed)
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('aroha.stores.redis needs redis-py 5+: pip install "aroha[redis]"') from e

from aroha.enrollment import EnrollmentChallengeRecord
from aroha.spending_ledger import BudgetExhaustedError, BudgetStatus, _micros

__all__ = [
    "DEFAULT_KEY_PREFIX",
    "RedisHttpPresentationNonces",
    "RedisEnrollmentStore",
    "RedisSpendingLedger",
]

DEFAULT_KEY_PREFIX = "aroha:"


def _check_prefix(key_prefix: Any) -> str:
    if not isinstance(key_prefix, str) or not 0 < len(key_prefix) <= 64 \
            or any(ch.isspace() or ord(ch) < 0x20 for ch in key_prefix):
        raise ValueError("key_prefix must be 1-64 characters without whitespace or control characters")
    return key_prefix


def _check_client(client: Any) -> Any:
    if client is None or not callable(getattr(client, "register_script", None)):
        raise ValueError("a redis-py client (redis.Redis or redis.cluster.RedisCluster) is required")
    return client


def _s(v: Any) -> Optional[str]:
    if v is None or v is False:
        return None
    return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)


# ── Nonces ────────────────────────────────────────────────────────────────────

class RedisHttpPresentationNonces:
    """``HttpPresentationNonceStore`` on Redis: ``SET P nonce:<key> 1 NX PX ttl``.

    The key lives until ``expires_at_ms`` inclusive, measured on the caller's
    clock (``now_ms``), as the in-memory store does; Redis drops it after.
    """

    def __init__(self, client: Any, *, key_prefix: str = DEFAULT_KEY_PREFIX) -> None:
        self._r = _check_client(client)
        self._p = _check_prefix(key_prefix) + "nonce:"

    def claim(self, key: str, expires_at_ms: int, now_ms: int) -> bool:
        if not isinstance(key, str) or not key:
            raise ValueError("claim: key must be a non-empty string")
        ttl = max(1, int(expires_at_ms) - int(now_ms) + 1)
        return self._r.set(self._p + key, "1", nx=True, px=ttl) is True

    def __bool__(self) -> bool:
        return True


# ── Enrollment ────────────────────────────────────────────────────────────────

# KEYS: challenge key, index zset. ARGV: value, px, now, max, member, expires.
_PUT_CHALLENGE = """
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[6], ARGV[5])
return 1
"""

# KEYS: challenge key, index zset. ARGV: member. Get and delete in one step.
_CONSUME_CHALLENGE = """
local v = redis.call('GET', KEYS[1])
if v then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
end
return v
"""


class RedisEnrollmentStore:
    """``EnrollmentStore`` on Redis.

    ``consume_challenge`` reads and deletes the challenge in one script: one
    caller gets the record. ``put_challenge`` drops expired index entries and
    refuses (RuntimeError) when ``max_challenges`` live ones are outstanding;
    the check and the write are one script, so the bound is exact.
    """

    def __init__(self, client: Any, *, key_prefix: str = DEFAULT_KEY_PREFIX, max_challenges: int = 100_000) -> None:
        if isinstance(max_challenges, bool) or not isinstance(max_challenges, int) or max_challenges < 1:
            raise ValueError("max_challenges must be a positive integer")
        self._r = _check_client(client)
        p = _check_prefix(key_prefix)
        self._challenge = p + "enroll:challenge:"
        self._index = p + "enroll:challenges"
        self._binding = p + "enroll:binding:"
        self._max = max_challenges
        self._put = self._r.register_script(_PUT_CHALLENGE)
        self._consume = self._r.register_script(_CONSUME_CHALLENGE)

    def put_challenge(self, challenge: str, record: EnrollmentChallengeRecord, now_ms: int) -> None:
        exp, now = int(record.expires_at_ms), int(now_ms)
        value = json.dumps({"accountId": record.account_id, "expiresAtMs": exp}, separators=(",", ":"))
        r = int(self._put(keys=[self._challenge + challenge, self._index],
                          args=[value, max(1, exp - now + 1), now, self._max, challenge, exp]))  # same rule as nonces and the TS store
        if r == -1:
            raise ValueError("RedisEnrollmentStore: challenge already issued")
        if r != 1:
            raise RuntimeError("RedisEnrollmentStore: too many outstanding challenges")

    def consume_challenge(self, challenge: str) -> Optional[EnrollmentChallengeRecord]:
        v = _s(self._consume(keys=[self._challenge + challenge, self._index], args=[challenge]))
        if v is None:
            return None
        d = json.loads(v)
        return EnrollmentChallengeRecord(str(d["accountId"]), int(d["expiresAtMs"]))

    def get_binding(self, account_id: str) -> Optional[str]:
        return _s(self._r.get(self._binding + account_id))

    def set_binding(self, account_id: str, did: str) -> None:
        self._r.set(self._binding + account_id, did)

    @property
    def pending_challenges(self) -> int:
        return int(self._r.zcard(self._index))

    def __bool__(self) -> bool:
        return True


# ── Spending ledger ───────────────────────────────────────────────────────────

# KEYS: budget. ARGV: limit (micros). Only the first call for a key writes.
_INIT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('HSET', KEYS[1], 'limit', ARGV[1], 'allocated', '0')
end
return 1
"""

# KEYS: budget, allocations. ARGV: amount (micros), allocation id.
# Returns {1} on success, {0, limit, allocated} when it would pass the limit,
# {-1} for an unknown key.
_ALLOCATE = """
local b = redis.call('HMGET', KEYS[1], 'limit', 'allocated', 'expires')
if not b[1] then return {-1} end
-- 'expires' (Unix ms) is written by @aroha-sdk/store-redis when init has an
-- expiry; absent means never. An expired budget has nothing left to charge.
if b[3] and tonumber(ARGV[3]) > tonumber(b[3]) then return {0, b[1], b[1]} end
if tonumber(b[2]) + tonumber(ARGV[1]) > tonumber(b[1]) then return {0, b[1], b[2]} end
redis.call('HINCRBY', KEYS[1], 'allocated', ARGV[1])
redis.call('HSET', KEYS[2], ARGV[2], ARGV[1])
return {1}
"""

# KEYS: budget, allocations. ARGV: allocation id. A second release finds nothing.
_RELEASE = """
local a = redis.call('HGET', KEYS[2], ARGV[1])
if not a then return 0 end
redis.call('HDEL', KEYS[2], ARGV[1])
if redis.call('EXISTS', KEYS[1]) == 1 then
  local n = tonumber(redis.call('HGET', KEYS[1], 'allocated')) - tonumber(a)
  if n < 0 then n = 0 end
  redis.call('HSET', KEYS[1], 'allocated', string.format('%d', n))
end
return 1
"""


class RedisSpendingLedger:
    """``SpendingLedger`` on Redis, in integer micro-USD.

    Each operation is one Lua script, so concurrent allocations against the
    same key never take the total past the limit.
    """

    def __init__(self, client: Any, *, key_prefix: str = DEFAULT_KEY_PREFIX) -> None:
        self._r = _check_client(client)
        p = _check_prefix(key_prefix)
        self._budget = p + "ledger:budget:"
        self._alloc = p + "ledger:alloc:"
        self._init = self._r.register_script(_INIT)
        self._allocate = self._r.register_script(_ALLOCATE)
        self._release = self._r.register_script(_RELEASE)

    def init(self, key: str, limit_usd: float) -> None:
        limit = _micros("limit_usd", limit_usd)
        self._init(keys=[self._budget + key], args=[limit])

    def allocate(self, key: str, amount_usd: float) -> str:
        amount = _micros("amount_usd", amount_usd)
        allocation_id = str(uuid.uuid4())
        r = self._allocate(keys=[self._budget + key, self._alloc + key], args=[amount, allocation_id, int(time.time() * 1000)])
        if int(r[0]) == 1:
            return allocation_id
        remaining = 0 if int(r[0]) == -1 else (int(_s(r[1])) - int(_s(r[2]))) / 1_000_000
        raise BudgetExhaustedError(key, amount_usd, remaining)

    def release(self, key: str, allocation_id: str) -> None:
        self._release(keys=[self._budget + key, self._alloc + key], args=[allocation_id])

    def status(self, key: str) -> Optional[BudgetStatus]:
        pipe = self._r.pipeline(transaction=True)
        pipe.hmget(self._budget + key, "limit", "allocated")
        pipe.hlen(self._alloc + key)
        (limit_s, allocated_s), count = pipe.execute()
        if limit_s is None:
            return None
        limit, allocated = int(_s(limit_s)), int(_s(allocated_s))
        return BudgetStatus(key, limit / 1_000_000, allocated / 1_000_000, (limit - allocated) / 1_000_000, int(count))
