# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""One contract suite for every store implementation: in-memory, PostgreSQL, Redis.

The durable backends run against real servers:

    AROHA_TEST_POSTGRES_URL=postgresql://postgres:pw@127.0.0.1:5432/aroha
    AROHA_TEST_REDIS_URL=redis://127.0.0.1:6379/0

Each is skipped (with the reason) when its URL is unset or its driver
(``aroha[postgres]`` / ``aroha[redis]``) is not installed. Every test uses its
own table / key prefix and removes what it created.

Concurrency tests give each thread its OWN client (its own connection), as
separate server processes would have, so they exercise the database's
atomicity rather than a lock in this process.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import threading
import time
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aroha.enrollment import (
    EnrollmentChallengeRecord,
    InMemoryEnrollmentStore,
    complete_enrollment,
    enrolled_did,
    issue_enrollment_challenge,
    sign_enrollment,
)
from aroha.http_mandate import (
    HTTP_MANDATE_HEADER,
    InMemoryHttpPresentationNonces,
    present_mandate_http,
    verify_http_spend_request,
)
from aroha.identity import to_multibase
from aroha.mandate import SpendingConstraints, issue_intent_mandate, mandate_redemption_key
from aroha.spending_ledger import BudgetExhaustedError, InMemorySpendingLedger
from aroha.timeutil import now_ms

PG_URL = os.environ.get("AROHA_TEST_POSTGRES_URL")
REDIS_URL = os.environ.get("AROHA_TEST_REDIS_URL")
HAVE_PSYCOPG = importlib.util.find_spec("psycopg") is not None
HAVE_REDIS = importlib.util.find_spec("redis") is not None

_PG_SKIP = ("AROHA_TEST_POSTGRES_URL is not set" if not PG_URL
            else 'psycopg is not installed (pip install "aroha[postgres]")' if not HAVE_PSYCOPG else None)
_REDIS_SKIP = ("AROHA_TEST_REDIS_URL is not set" if not REDIS_URL
               else 'redis-py is not installed (pip install "aroha[redis]")' if not HAVE_REDIS else None)

needs_pg = pytest.mark.skipif(_PG_SKIP is not None, reason=f"Postgres store tests: {_PG_SKIP}")
needs_redis = pytest.mark.skipif(_REDIS_SKIP is not None, reason=f"Redis store tests: {_REDIS_SKIP}")

BACKENDS = [
    pytest.param("memory", id="memory"),
    pytest.param("postgres", id="postgres", marks=needs_pg),
    pytest.param("redis", id="redis", marks=needs_redis),
]
DURABLE = [b for b in BACKENDS if b.values[0] != "memory"]


# ── Backend factories ─────────────────────────────────────────────────────────

class Backend:
    """Makes fresh store instances that share one namespace (tables / key prefix).

    For "memory" every call returns the same instance: there is nothing to
    share between instances. For the durable backends every call opens a new
    client, as another process (or the same one after a restart) would.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.durable = name != "memory"
        self._clients: list[Any] = []
        self._memory: dict[str, Any] = {}
        tag = secrets.token_hex(4)
        if name == "postgres":
            from aroha.stores import postgres as pg
            self.prefix = f"t{tag}_"
            conn = self._pg_conn()
            pg.migrate(conn, table_prefix=self.prefix)
        elif name == "redis":
            self.prefix = f"aroha-test:{tag}:"

    def _pg_conn(self) -> Any:
        import psycopg
        c = psycopg.connect(PG_URL, autocommit=True)
        self._clients.append(c)
        return c

    def _redis(self) -> Any:
        import redis
        c = redis.Redis.from_url(REDIS_URL)
        self._clients.append(c)
        return c

    def nonces(self) -> Any:
        if self.name == "memory":
            return self._memory.setdefault("nonces", InMemoryHttpPresentationNonces())
        if self.name == "postgres":
            from aroha.stores.postgres import PostgresHttpPresentationNonces
            return PostgresHttpPresentationNonces(self._pg_conn(), table_prefix=self.prefix)
        from aroha.stores.redis import RedisHttpPresentationNonces
        return RedisHttpPresentationNonces(self._redis(), key_prefix=self.prefix)

    def enrollment(self, max_challenges: int = 100_000) -> Any:
        if self.name == "memory":
            key = f"enrollment-{max_challenges}"
            return self._memory.setdefault(key, InMemoryEnrollmentStore(max_challenges))
        if self.name == "postgres":
            from aroha.stores.postgres import PostgresEnrollmentStore
            return PostgresEnrollmentStore(self._pg_conn(), table_prefix=self.prefix, max_challenges=max_challenges)
        from aroha.stores.redis import RedisEnrollmentStore
        return RedisEnrollmentStore(self._redis(), key_prefix=self.prefix, max_challenges=max_challenges)

    def ledger(self) -> Any:
        if self.name == "memory":
            return self._memory.setdefault("ledger", InMemorySpendingLedger())
        if self.name == "postgres":
            from aroha.stores.postgres import PostgresSpendingLedger
            return PostgresSpendingLedger(self._pg_conn(), table_prefix=self.prefix)
        from aroha.stores.redis import RedisSpendingLedger
        return RedisSpendingLedger(self._redis(), key_prefix=self.prefix)

    def close(self) -> None:
        try:
            if self.name == "postgres":
                from aroha.stores.postgres import _TABLE_NAMES
                c = self._pg_conn()
                # Dependents first; names come from the validated test prefix.
                for t in ("spending_allocations",) + tuple(n for n in _TABLE_NAMES if n != "spending_allocations"):
                    c.execute(f'DROP TABLE IF EXISTS "{self.prefix}{t}"')
            elif self.name == "redis":
                c = self._redis()
                keys = list(c.scan_iter(match=self.prefix + "*", count=1000))
                if keys:
                    c.delete(*keys)
        finally:
            for c in self._clients:
                try:
                    c.close()
                except Exception:  # noqa: BLE001
                    pass


@pytest.fixture(params=BACKENDS)
def backend(request):
    b = Backend(request.param)
    yield b
    b.close()


@pytest.fixture(params=DURABLE)
def durable(request):
    b = Backend(request.param)
    yield b
    b.close()


def race(n: int, make: Callable[[], Any], act: Callable[[Any], Any]) -> list[Any]:
    """Run ``act`` on ``n`` threads at once, each with its own store from ``make``."""
    stores = [make() for _ in range(n)]
    barrier = threading.Barrier(n)
    out: list[Any] = [None] * n

    def run(i: int) -> None:
        barrier.wait()
        try:
            out[i] = act(stores[i])
        except Exception as e:  # noqa: BLE001
            out[i] = e

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return out


# ── Nonces ────────────────────────────────────────────────────────────────────

def test_nonce_single_use(backend):
    s, t = backend.nonces(), now_ms()
    assert s.claim("did:a n1", t + 60_000, t) is True
    assert s.claim("did:a n1", t + 60_000, t + 1) is False
    assert s.claim("did:a n2", t + 60_000, t) is True
    assert s.claim("did:b n1", t + 60_000, t) is True
    assert bool(s) is True


def test_nonce_expiry_frees_the_key(backend):
    s, t = backend.nonces(), now_ms()
    assert s.claim("did:a short", t + 100, t) is True
    assert s.claim("did:a short", t + 100, t + 100) is False  # live up to and including expires
    time.sleep(0.3)
    t2 = now_ms()
    assert s.claim("did:a short", t2 + 60_000, t2) is True
    assert s.claim("did:a short", t2 + 60_000, t2) is False


def test_nonce_twenty_parallel_claims_one_wins(backend):
    t = now_ms()
    out = race(20, backend.nonces, lambda s: s.claim("did:a raced", t + 60_000, t))
    assert out.count(True) == 1 and out.count(False) == 19, out


def test_nonce_survives_new_client(durable):
    t = now_ms()
    assert durable.nonces().claim("did:a kept", t + 60_000, t) is True
    assert durable.nonces().claim("did:a kept", t + 60_000, t) is False


# ── Enrollment ────────────────────────────────────────────────────────────────

def test_challenge_consumed_once(backend):
    s, t = backend.enrollment(), now_ms()
    s.put_challenge("c" * 43, EnrollmentChallengeRecord("acct-1", t + 60_000), t)
    with pytest.raises(ValueError):
        s.put_challenge("c" * 43, EnrollmentChallengeRecord("acct-2", t + 60_000), t)
    r = s.consume_challenge("c" * 43)
    assert r == EnrollmentChallengeRecord("acct-1", t + 60_000)
    assert isinstance(r.expires_at_ms, int)
    assert s.consume_challenge("c" * 43) is None
    assert s.consume_challenge("never-issued-challenge") is None


def test_challenge_parallel_consume_one_wins(backend):
    t = now_ms()
    backend.enrollment().put_challenge("raced-challenge-xyz", EnrollmentChallengeRecord("acct", t + 60_000), t)
    out = race(20, backend.enrollment, lambda s: s.consume_challenge("raced-challenge-xyz"))
    assert sum(1 for r in out if isinstance(r, EnrollmentChallengeRecord)) == 1, out
    assert sum(1 for r in out if r is None) == 19, out


def test_challenges_are_bounded_and_expired_ones_free_space(backend):
    s, t = backend.enrollment(max_challenges=3), now_ms()
    s.put_challenge("short-lived-0001", EnrollmentChallengeRecord("a", t + 100), t)
    s.put_challenge("long-lived-00001", EnrollmentChallengeRecord("a", t + 60_000), t)
    s.put_challenge("long-lived-00002", EnrollmentChallengeRecord("a", t + 60_000), t)
    with pytest.raises(RuntimeError):
        s.put_challenge("long-lived-00003", EnrollmentChallengeRecord("a", t + 60_000), t)
    time.sleep(0.3)
    t2 = now_ms()
    s.put_challenge("long-lived-00003", EnrollmentChallengeRecord("a", t2 + 60_000), t2)
    assert s.pending_challenges == 3
    assert s.consume_challenge("long-lived-00001") is not None
    s.put_challenge("long-lived-00004", EnrollmentChallengeRecord("a", t2 + 60_000), t2)  # consuming frees a slot


def test_bindings_and_rotation(backend):
    s = backend.enrollment()
    assert s.get_binding("acct-1") is None
    s.set_binding("acct-1", "did:aroha:zOne")
    s.set_binding("acct-2", "did:aroha:zTwo")
    s.set_binding("acct-1", "did:aroha:zThree")
    assert s.get_binding("acct-1") == "did:aroha:zThree"
    assert s.get_binding("acct-2") == "did:aroha:zTwo"
    assert bool(s) is True


def test_enrollment_survives_new_client(durable):
    t = now_ms()
    durable.enrollment().put_challenge("persisted-challenge", EnrollmentChallengeRecord("acct", t + 60_000), t)
    durable.enrollment().set_binding("acct", "did:aroha:zKept")
    assert durable.enrollment().consume_challenge("persisted-challenge") == EnrollmentChallengeRecord("acct", t + 60_000)
    assert durable.enrollment().consume_challenge("persisted-challenge") is None
    assert durable.enrollment().get_binding("acct") == "did:aroha:zKept"


# ── Spending ledger ───────────────────────────────────────────────────────────

def test_ledger_contract(backend):
    led = backend.ledger()
    assert led.status("k") is None
    with pytest.raises(BudgetExhaustedError) as e:
        led.allocate("k", 1)  # unknown key
    assert e.value.remaining_usd == 0 and e.value.code == "BUDGET_EXHAUSTED"
    led.init("k", 500)
    led.init("k", 9_999)  # idempotent: the first limit stays
    a = led.allocate("k", 200)
    b = led.allocate("k", 250.5)
    with pytest.raises(BudgetExhaustedError) as e:
        led.allocate("k", 49.51)
    assert e.value.remaining_usd == pytest.approx(49.5) and e.value.key == "k"
    st = led.status("k")
    assert (st.limit_usd, st.allocated_usd, st.remaining_usd, st.allocation_count) == (500, 450.5, 49.5, 2)
    led.release("k", a)
    led.release("k", a)  # repeat: no-op
    led.release("k", "no-such-allocation")
    led.release("unknown-key", b)
    st = led.status("k")
    assert (st.allocated_usd, st.allocation_count) == (250.5, 1)
    assert led.allocate("k", 249.5)
    with pytest.raises(ValueError):
        led.allocate("k", -1)
    with pytest.raises(ValueError):
        led.init("k2", float("nan"))


def test_ledger_is_exact_in_micros(backend):
    led = backend.ledger()
    led.init("cents", 1)
    for _ in range(10):
        led.allocate("cents", 0.1)
    assert led.status("cents").allocated_usd == 1
    with pytest.raises(BudgetExhaustedError):
        led.allocate("cents", 0.000001)


def test_ledger_three_parallel_200_on_500_two_win(backend):
    backend.ledger().init("race", 500)
    out = race(3, backend.ledger, lambda led: led.allocate("race", 200))
    assert sum(1 for r in out if isinstance(r, str)) == 2, out
    assert sum(1 for r in out if isinstance(r, BudgetExhaustedError)) == 1, out
    assert backend.ledger().status("race").allocated_usd == 400


def test_ledger_twenty_parallel_50_on_500_ten_win(backend):
    backend.ledger().init("race20", 500)
    out = race(20, backend.ledger, lambda led: led.allocate("race20", 50))
    assert sum(1 for r in out if isinstance(r, str)) == 10, out
    assert backend.ledger().status("race20").allocated_usd == 500


def test_ledger_parallel_release_returns_once(backend):
    led = backend.ledger()
    led.init("rel", 100)
    aid = led.allocate("rel", 60)
    race(10, backend.ledger, lambda x: x.release("rel", aid))
    st = backend.ledger().status("rel")
    assert (st.allocated_usd, st.allocation_count) == (0, 0)


def test_ledger_survives_new_client(durable):
    durable.ledger().init("kept", 500)
    aid = durable.ledger().allocate("kept", 300)
    with pytest.raises(BudgetExhaustedError):
        durable.ledger().allocate("kept", 300)
    durable.ledger().release("kept", aid)
    assert durable.ledger().status("kept").allocated_usd == 0


# ── End to end: enrollment + verify_http_spend_request on durable stores ─────

class Key:
    def __init__(self) -> None:
        self.priv = Ed25519PrivateKey.generate()
        self.did = "did:aroha:" + to_multibase(self.priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


AUD = "https://invoices.example.com"


def test_enroll_then_spend_across_restarts(backend):
    human, agent = Key(), Key()

    # Enrollment: challenge issued by one server instance, completed by another.
    c = issue_enrollment_challenge(backend.enrollment(), authenticated_account_id="cust-1")
    proof = sign_enrollment(account_id="cust-1", did=human.did, challenge=c.challenge, audience=AUD, private_key=human.priv)
    r = complete_enrollment(backend.enrollment(), authenticated_account_id="cust-1", audience=AUD,
                            did=human.did, challenge=c.challenge, proof=proof)
    assert r.ok, r
    again = complete_enrollment(backend.enrollment(), authenticated_account_id="cust-1", audience=AUD,
                                did=human.did, challenge=c.challenge, proof=proof)
    assert again.code == "CHALLENGE_UNKNOWN"

    grant = issue_intent_mandate(human.did, agent.did, SpendingConstraints(spend_limit_usd=500), human.priv, 600)
    body = b'{"customerId":"cust-1"}'

    def request() -> str:
        return present_mandate_http(token=grant.token, holder_did=agent.did, holder_private_key=agent.priv,
                                    audience=AUD, method="POST", url=AUD + "/invoices", body=body)[HTTP_MANDATE_HEADER]

    def spend(h: str, amount: float):  # a fresh "server process" per request on the durable backends
        return verify_http_spend_request(h, audience=AUD, method="POST", url="/invoices", body=body,
                                         nonces=backend.nonces(), ledger=backend.ledger(), is_revoked=None,
                                         expected_root=enrolled_did(backend.enrollment(), "cust-1"), amount_usd=amount)

    h1 = request()
    first = spend(h1, 300)
    assert first.ok, first
    assert spend(h1, 1).code == "REPLAYED"
    over = spend(request(), 300)
    assert (over.code, over.status) == ("OVER_LIMIT", 403)
    assert spend(request(), 200).ok
    first.charge.release()
    key = mandate_redemption_key(grant.mandate)
    assert backend.ledger().status(key).allocated_usd == 200

    # Parallel spends on fresh headers: $500 cap, $200 already used, three $150 → exactly two.
    headers = [request() for _ in range(3)]
    out = race(3, lambda: None, lambda _s, it=iter(headers): spend(next(it), 150))
    assert sum(1 for x in out if getattr(x, "ok", False)) == 2, out
    assert backend.ledger().status(key).allocated_usd == 500


# ── Fail closed ───────────────────────────────────────────────────────────────

def _spend_with(nonces, ledger):
    human, agent = Key(), Key()
    grant = issue_intent_mandate(human.did, agent.did, SpendingConstraints(spend_limit_usd=50), human.priv, 600)
    h = present_mandate_http(token=grant.token, holder_did=agent.did, holder_private_key=agent.priv,
                             audience=AUD, method="POST", url=AUD + "/x", body=b"")[HTTP_MANDATE_HEADER]
    return verify_http_spend_request(h, audience=AUD, method="POST", url="/x", body=b"", nonces=nonces, ledger=ledger,
                                     is_revoked=None, expected_root=human.did, amount_usd=1)


@needs_pg
def test_postgres_errors_refuse():
    import psycopg
    from aroha.stores.postgres import PostgresEnrollmentStore, PostgresHttpPresentationNonces, PostgresSpendingLedger

    b = Backend("postgres")
    try:
        dead = psycopg.connect(PG_URL, autocommit=True)
        nonces = PostgresHttpPresentationNonces(dead, table_prefix=b.prefix)
        ledger = PostgresSpendingLedger(dead, table_prefix=b.prefix)
        store = PostgresEnrollmentStore(dead, table_prefix=b.prefix)
        dead.close()
        with pytest.raises(psycopg.Error):
            nonces.claim("k", now_ms() + 1000, now_ms())
        with pytest.raises(psycopg.Error):
            ledger.allocate("k", 1)
        assert _spend_with(nonces, b.ledger()).code == "NONCE_STORE_UNAVAILABLE"
        assert _spend_with(b.nonces(), ledger).code == "LEDGER_UNAVAILABLE"
        r = complete_enrollment(store, authenticated_account_id="a", audience=AUD, did="did:x",
                                challenge="A" * 43, proof="x")
        assert r.code == "STORE_UNAVAILABLE"
        missing = PostgresSpendingLedger(b._pg_conn(), table_prefix="no_such_tables_")
        with pytest.raises(psycopg.Error):
            missing.init("k", 1)
    finally:
        b.close()


@needs_redis
def test_redis_errors_refuse():
    import redis
    from aroha.stores.redis import RedisEnrollmentStore, RedisHttpPresentationNonces, RedisSpendingLedger

    from redis.backoff import NoBackoff
    from redis.retry import Retry

    dead = redis.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.5, retry=Retry(NoBackoff(), 0))
    nonces, ledger = RedisHttpPresentationNonces(dead), RedisSpendingLedger(dead)
    with pytest.raises(redis.RedisError):
        nonces.claim("k", now_ms() + 1000, now_ms())
    with pytest.raises(redis.RedisError):
        ledger.allocate("k", 1)
    assert _spend_with(nonces, InMemorySpendingLedger()).code == "NONCE_STORE_UNAVAILABLE"
    assert _spend_with(InMemoryHttpPresentationNonces(), ledger).code == "LEDGER_UNAVAILABLE"
    r = complete_enrollment(RedisEnrollmentStore(dead), authenticated_account_id="a", audience=AUD, did="did:x",
                            challenge="A" * 43, proof="x")
    assert r.code == "STORE_UNAVAILABLE"


# ── Configuration ─────────────────────────────────────────────────────────────

@needs_pg
def test_postgres_configuration():
    import psycopg
    from aroha.stores import postgres as pg

    for bad in ("", "A_", "1x", "x-y", "x;drop", 'x"', "a" * 42, None, 3):
        with pytest.raises(ValueError):
            pg.schema_sql(bad)
        with pytest.raises(ValueError):
            pg.PostgresSpendingLedger(object(), table_prefix=bad)
    assert '"aroha_spending_budgets"' in pg.schema_sql()
    assert '"svc_http_nonces"' in pg.schema_sql("svc_")
    with psycopg.connect(PG_URL) as not_autocommit:
        with pytest.raises(ValueError):
            pg.PostgresHttpPresentationNonces(not_autocommit)
    with pytest.raises(ValueError):
        pg.PostgresHttpPresentationNonces(None)
    with pytest.raises(ValueError):
        pg.PostgresEnrollmentStore(object(), max_challenges=0)


@needs_pg
def test_postgres_migrate_is_idempotent_and_pool_works():
    from aroha.stores import postgres as pg

    b = Backend("postgres")
    try:
        pg.migrate(b._pg_conn(), table_prefix=b.prefix)  # second run: no error
        if importlib.util.find_spec("psycopg_pool") is None:
            pytest.skip("psycopg_pool not installed: pool path not exercised")
        from psycopg_pool import ConnectionPool
        with ConnectionPool(PG_URL, min_size=2, max_size=8, open=True) as pool:
            led = pg.PostgresSpendingLedger(pool, table_prefix=b.prefix)
            nonces = pg.PostgresHttpPresentationNonces(pool, table_prefix=b.prefix)
            led.init("pooled", 500)
            out = race(3, lambda: led, lambda x: x.allocate("pooled", 200))
            assert sum(1 for r in out if isinstance(r, str)) == 2, out
            t = now_ms()
            assert race(20, lambda: nonces, lambda s: s.claim("p n", t + 60_000, t)).count(True) == 1
    finally:
        b.close()


@needs_redis
def test_redis_configuration_and_layout():
    import redis
    from aroha.stores import redis as rs

    for bad in ("", "a b", "x\n", "p" * 65, None):
        with pytest.raises(ValueError):
            rs.RedisSpendingLedger(redis.Redis.from_url(REDIS_URL), key_prefix=bad)
    with pytest.raises(ValueError):
        rs.RedisHttpPresentationNonces(None)

    b = Backend("redis")
    try:
        t = now_ms()
        b.nonces().claim("did:h n", t + 60_000, t)
        b.enrollment().put_challenge("layout-challenge", EnrollmentChallengeRecord("acct", t + 60_000), t)
        b.enrollment().set_binding("acct", "did:aroha:zL")
        b.ledger().init("did:g#m", 5)
        aid = b.ledger().allocate("did:g#m", 1)
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        p = b.prefix
        assert r.get(p + "nonce:did:h n") == "1" and 0 < r.pttl(p + "nonce:did:h n") <= 60_001
        assert r.get(p + "enroll:challenge:layout-challenge") == f'{{"accountId":"acct","expiresAtMs":{t + 60_000}}}'
        assert r.zscore(p + "enroll:challenges", "layout-challenge") == t + 60_000
        assert r.get(p + "enroll:binding:acct") == "did:aroha:zL"
        assert r.hgetall(p + "ledger:budget:did:g#m") == {"limit": "5000000", "allocated": "1000000"}
        assert r.hgetall(p + "ledger:alloc:did:g#m") == {aid: "1000000"}
        # A decode_responses client works the same.
        assert rs.RedisSpendingLedger(r, key_prefix=p).status("did:g#m").allocated_usd == 1
        r.close()
    finally:
        b.close()


# ── Shared layout with @aroha-sdk/store-postgres / store-redis ────────────────

def _expire_budget(b: Backend, key: str, at_ms: int) -> None:
    """Write a budget expiry the way the TypeScript stores do (init with expiresAt)."""
    if b.name == "postgres":
        b._pg_conn().execute(f'UPDATE "{b.prefix}spending_budgets" SET expires_at_ms = %s WHERE key = %s', (at_ms, key))
    else:
        b._redis().hset(b.prefix + "ledger:budget:" + key, "expires", at_ms)


def test_budget_expiry_written_by_typescript_is_honoured(durable):
    led = durable.ledger()
    led.init("live", 10)
    led.init("dead", 10)
    _expire_budget(durable, "live", now_ms() + 60_000)
    _expire_budget(durable, "dead", now_ms() - 1)
    assert isinstance(led.allocate("live", 4), str)
    with pytest.raises(BudgetExhaustedError) as e:
        led.allocate("dead", 1)
    assert e.value.remaining_usd == 0
    assert led.status("dead").allocated_usd == 0
