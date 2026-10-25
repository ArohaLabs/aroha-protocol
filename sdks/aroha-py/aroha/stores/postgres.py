# Copyright (c) 2026 Aroha Labs
# SPDX-License-Identifier: Apache-2.0

"""
PostgreSQL stores (psycopg 3, synchronous) — ``pip install "aroha[postgres]"``.

Durable, shared implementations of the three store interfaces:

- ``PostgresHttpPresentationNonces`` — ``HttpPresentationNonceStore``
  (``aroha.http_mandate``): single-use presentation nonces.
- ``PostgresEnrollmentStore`` — ``EnrollmentStore`` (``aroha.enrollment``):
  challenges and account → DID bindings.
- ``PostgresSpendingLedger`` — ``SpendingLedger`` (``aroha.spending_ledger``):
  running totals in integer micro-USD.

Every check-and-write is ONE statement or one transaction, so any number of
processes can share the tables::

    nonce claim        INSERT … ON CONFLICT (key) DO UPDATE … WHERE expired RETURNING
    challenge consume  DELETE … RETURNING
    ledger allocate    UPDATE … SET allocated = allocated + amt
                         WHERE key = … AND allocated + amt <= limit RETURNING
                       (+ the allocation row, same transaction)
    ledger release     DELETE allocation … RETURNING amount, then subtract it
                       (same transaction; a second release finds nothing)

Pass either a ``psycopg.Connection`` opened with ``autocommit=True`` (calls
are serialised on it by a lock) or a pool with a ``connection()`` context
manager (``psycopg_pool.ConnectionPool``) for parallel calls. Create the
tables once with ``migrate(conn)`` (or apply ``schema_sql()`` with your own
migration tool). Table names are ``<table_prefix><name>``; the prefix must
match ``^[a-z_][a-z0-9_]{0,40}$``. Inputs are always bound parameters.

Errors are never swallowed: a database error propagates, and the verifiers
turn it into NONCE_STORE_UNAVAILABLE / STORE_UNAVAILABLE / LEDGER_UNAVAILABLE.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

try:
    import psycopg
    from psycopg import sql
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError('aroha.stores.postgres needs psycopg 3: pip install "aroha[postgres]"') from e

from aroha.enrollment import EnrollmentChallengeRecord
from aroha.spending_ledger import BudgetExhaustedError, BudgetStatus, _micros

__all__ = [
    "DEFAULT_TABLE_PREFIX",
    "schema_sql",
    "migrate",
    "PostgresHttpPresentationNonces",
    "PostgresEnrollmentStore",
    "PostgresSpendingLedger",
]

DEFAULT_TABLE_PREFIX = "aroha_"
_PREFIX_RE = re.compile(r"[a-z_][a-z0-9_]{0,40}")
_CLEANUP_EVERY = 64


def _check_prefix(table_prefix: Any) -> str:
    if not isinstance(table_prefix, str) or not _PREFIX_RE.fullmatch(table_prefix):
        raise ValueError("table_prefix must match ^[a-z_][a-z0-9_]{0,40}$")
    return table_prefix


_TABLE_NAMES = ("http_nonces", "enrollment_challenges", "enrollment_bindings", "spending_budgets", "spending_allocations")


def _tables(prefix: str) -> dict[str, sql.Identifier]:
    p = _check_prefix(prefix)
    return {n: sql.Identifier(p + n) for n in _TABLE_NAMES}


_SCHEMA = """
CREATE TABLE IF NOT EXISTS {http_nonces} (
  key            TEXT   PRIMARY KEY,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS {http_nonces_exp} ON {http_nonces} (expires_at_ms);

CREATE TABLE IF NOT EXISTS {enrollment_challenges} (
  challenge      TEXT   PRIMARY KEY,
  account_id     TEXT   NOT NULL,
  expires_at_ms  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS {enrollment_challenges_exp} ON {enrollment_challenges} (expires_at_ms);

CREATE TABLE IF NOT EXISTS {enrollment_bindings} (
  account_id  TEXT        PRIMARY KEY,
  did         TEXT        NOT NULL,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS {spending_budgets} (
  key               TEXT   PRIMARY KEY,
  limit_micros      BIGINT NOT NULL CHECK (limit_micros >= 0),
  allocated_micros  BIGINT NOT NULL DEFAULT 0 CHECK (allocated_micros >= 0)
);
-- Optional budget expiry (Unix ms; NULL = never expires), shared with
-- @aroha-sdk/store-postgres, which writes it when init is given expiresAt.
-- ADD COLUMN IF NOT EXISTS so either language can migrate first.
ALTER TABLE {spending_budgets} ADD COLUMN IF NOT EXISTS expires_at_ms BIGINT;

CREATE TABLE IF NOT EXISTS {spending_allocations} (
  key            TEXT   NOT NULL REFERENCES {spending_budgets} (key) ON DELETE CASCADE,
  allocation_id  TEXT   NOT NULL,
  amount_micros  BIGINT NOT NULL CHECK (amount_micros >= 0),
  PRIMARY KEY (key, allocation_id)
);
"""


def schema_sql(table_prefix: str = DEFAULT_TABLE_PREFIX) -> str:
    """The DDL ``migrate`` runs, as a string, for your own migration tool."""
    p = _check_prefix(table_prefix)  # validated above, so quoting it as an identifier is safe
    names = {n: f'"{p}{n}"' for n in _TABLE_NAMES}
    return _SCHEMA.format(
        http_nonces_exp=f'"{p}http_nonces_expires_idx"',
        enrollment_challenges_exp=f'"{p}enrollment_challenges_expires_idx"',
        **names,
    )


class _Db:
    """A psycopg Connection (autocommit, serialised by a lock) or a pool with ``connection()``."""

    def __init__(self, conn: Any) -> None:
        if conn is None:
            raise ValueError("a psycopg Connection or ConnectionPool is required")
        self._pool = conn if callable(getattr(conn, "connection", None)) and not isinstance(conn, psycopg.Connection) else None
        if self._pool is None:
            if not isinstance(conn, psycopg.Connection):
                raise ValueError("conn must be a psycopg.Connection or a pool with a connection() context manager")
            if not conn.autocommit:
                raise ValueError("pass a psycopg.Connection opened with autocommit=True (or a ConnectionPool)")
        self._conn = conn
        self._lock = threading.Lock()

    @contextmanager
    def tx(self) -> Iterator[Any]:
        if self._pool is not None:
            with self._pool.connection() as c, c.transaction():
                yield c
        else:
            with self._lock, self._conn.transaction():
                yield self._conn


def migrate(conn: Any, *, table_prefix: str = DEFAULT_TABLE_PREFIX) -> None:
    """Create the tables and indexes if they do not exist. Idempotent; safe to run from several processes."""
    ddl = sql.SQL(schema_sql(table_prefix))  # type: ignore[arg-type]  # built only from the validated prefix
    with _Db(conn).tx() as c:
        # Same lock key as @aroha-sdk/store-postgres, so a Python and a TypeScript
        # migrate() on the same database wait for each other.
        c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"aroha-store:migrate:{table_prefix}",))
        c.execute(ddl)


# ── Nonces ────────────────────────────────────────────────────────────────────

class PostgresHttpPresentationNonces:
    """``HttpPresentationNonceStore`` on PostgreSQL.

    ``claim`` inserts the key, or takes over a row whose expiry has passed, in
    one statement; a live row makes it return False. Expired rows are deleted
    every 64 claims made through this instance.
    """

    def __init__(self, conn: Any, *, table_prefix: str = DEFAULT_TABLE_PREFIX) -> None:
        _check_prefix(table_prefix)
        self._db = _Db(conn)
        t = _tables(table_prefix)["http_nonces"]
        self._claim_sql = sql.SQL(
            "INSERT INTO {t} AS n (key, expires_at_ms) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET expires_at_ms = EXCLUDED.expires_at_ms "
            "WHERE n.expires_at_ms < %s RETURNING 1"
        ).format(t=t)
        self._cleanup_sql = sql.SQL("DELETE FROM {t} WHERE expires_at_ms < %s").format(t=t)
        self._claims = 0
        self._count_lock = threading.Lock()

    def claim(self, key: str, expires_at_ms: int, now_ms: int) -> bool:
        if not isinstance(key, str) or not key:
            raise ValueError("claim: key must be a non-empty string")
        exp, now = int(expires_at_ms), int(now_ms)
        with self._count_lock:
            self._claims += 1
            cleanup = self._claims % _CLEANUP_EVERY == 0
        with self._db.tx() as c:
            if cleanup:
                c.execute(self._cleanup_sql, (now,))
            return c.execute(self._claim_sql, (key, exp, now)).fetchone() is not None

    def __bool__(self) -> bool:
        return True


# ── Enrollment ────────────────────────────────────────────────────────────────

class PostgresEnrollmentStore:
    """``EnrollmentStore`` on PostgreSQL.

    ``consume_challenge`` is ``DELETE … RETURNING``: one caller gets the row.
    ``put_challenge`` deletes expired challenges and refuses (RuntimeError)
    when ``max_challenges`` live ones are outstanding. Under concurrent
    issuance the bound can be overshot by the number of parallel callers; it
    exists to cap storage, not to protect a secret.
    """

    def __init__(self, conn: Any, *, table_prefix: str = DEFAULT_TABLE_PREFIX, max_challenges: int = 100_000) -> None:
        if isinstance(max_challenges, bool) or not isinstance(max_challenges, int) or max_challenges < 1:
            raise ValueError("max_challenges must be a positive integer")
        _check_prefix(table_prefix)
        self._db = _Db(conn)
        self._max = max_challenges
        t = _tables(table_prefix)
        ch, b = t["enrollment_challenges"], t["enrollment_bindings"]
        self._expire_sql = sql.SQL("DELETE FROM {ch} WHERE expires_at_ms <= %s").format(ch=ch)
        self._put_sql = sql.SQL(
            "INSERT INTO {ch} (challenge, account_id, expires_at_ms) "
            "SELECT %s, %s, %s WHERE (SELECT count(*) FROM {ch}) < %s "
            "ON CONFLICT (challenge) DO NOTHING RETURNING 1"
        ).format(ch=ch)
        self._exists_sql = sql.SQL("SELECT 1 FROM {ch} WHERE challenge = %s").format(ch=ch)
        self._consume_sql = sql.SQL(
            "DELETE FROM {ch} WHERE challenge = %s RETURNING account_id, expires_at_ms"
        ).format(ch=ch)
        self._count_sql = sql.SQL("SELECT count(*) FROM {ch}").format(ch=ch)
        self._get_sql = sql.SQL("SELECT did FROM {b} WHERE account_id = %s").format(b=b)
        self._set_sql = sql.SQL(
            "INSERT INTO {b} (account_id, did) VALUES (%s, %s) "
            "ON CONFLICT (account_id) DO UPDATE SET did = EXCLUDED.did, updated_at = now()"
        ).format(b=b)

    def put_challenge(self, challenge: str, record: EnrollmentChallengeRecord, now_ms: int) -> None:
        with self._db.tx() as c:
            c.execute(self._expire_sql, (int(now_ms),))
            row = c.execute(self._put_sql, (challenge, record.account_id, int(record.expires_at_ms), self._max)).fetchone()
            if row is None:
                if c.execute(self._exists_sql, (challenge,)).fetchone() is not None:
                    raise ValueError("PostgresEnrollmentStore: challenge already issued")
                raise RuntimeError("PostgresEnrollmentStore: too many outstanding challenges")

    def consume_challenge(self, challenge: str) -> Optional[EnrollmentChallengeRecord]:
        with self._db.tx() as c:
            row = c.execute(self._consume_sql, (challenge,)).fetchone()
        return None if row is None else EnrollmentChallengeRecord(row[0], int(row[1]))

    def get_binding(self, account_id: str) -> Optional[str]:
        with self._db.tx() as c:
            row = c.execute(self._get_sql, (account_id,)).fetchone()
        return None if row is None else row[0]

    def set_binding(self, account_id: str, did: str) -> None:
        with self._db.tx() as c:
            c.execute(self._set_sql, (account_id, did))

    @property
    def pending_challenges(self) -> int:
        with self._db.tx() as c:
            return int(c.execute(self._count_sql).fetchone()[0])

    def __bool__(self) -> bool:
        return True


# ── Spending ledger ───────────────────────────────────────────────────────────

class PostgresSpendingLedger:
    """``SpendingLedger`` on PostgreSQL, in integer micro-USD.

    ``allocate`` is a conditional UPDATE (``allocated + amount <= limit``) plus
    the allocation row in the same transaction; ``release`` deletes the
    allocation row and subtracts what it held, so repeating it is a no-op.
    """

    def __init__(self, conn: Any, *, table_prefix: str = DEFAULT_TABLE_PREFIX) -> None:
        _check_prefix(table_prefix)
        self._db = _Db(conn)
        t = _tables(table_prefix)
        bud, al = t["spending_budgets"], t["spending_allocations"]
        self._init_sql = sql.SQL(
            "INSERT INTO {bud} (key, limit_micros) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING"
        ).format(bud=bud)
        self._alloc_sql = sql.SQL(
            "UPDATE {bud} SET allocated_micros = allocated_micros + %s "
            "WHERE key = %s AND allocated_micros + %s <= limit_micros "
            "AND (expires_at_ms IS NULL OR expires_at_ms >= %s) RETURNING allocated_micros"
        ).format(bud=bud)
        self._alloc_row_sql = sql.SQL(
            "INSERT INTO {al} (key, allocation_id, amount_micros) VALUES (%s, %s, %s)"
        ).format(al=al)
        self._budget_sql = sql.SQL("SELECT limit_micros, allocated_micros, expires_at_ms FROM {bud} WHERE key = %s").format(bud=bud)
        self._release_row_sql = sql.SQL(
            "DELETE FROM {al} WHERE key = %s AND allocation_id = %s RETURNING amount_micros"
        ).format(al=al)
        self._release_sql = sql.SQL(
            "UPDATE {bud} SET allocated_micros = GREATEST(0, allocated_micros - %s) WHERE key = %s"
        ).format(bud=bud)
        self._status_sql = sql.SQL(
            "SELECT b.limit_micros, b.allocated_micros, (SELECT count(*) FROM {al} a WHERE a.key = b.key) "
            "FROM {bud} b WHERE b.key = %s"
        ).format(bud=bud, al=al)

    def init(self, key: str, limit_usd: float) -> None:
        limit = _micros("limit_usd", limit_usd)
        with self._db.tx() as c:
            c.execute(self._init_sql, (key, limit))

    def allocate(self, key: str, amount_usd: float) -> str:
        amount = _micros("amount_usd", amount_usd)
        allocation_id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)
        with self._db.tx() as c:
            # A budget past its expiry (written by the TypeScript store) is not charged.
            if c.execute(self._alloc_sql, (amount, key, amount, now_ms)).fetchone() is not None:
                c.execute(self._alloc_row_sql, (key, allocation_id, amount))
                return allocation_id
            row = c.execute(self._budget_sql, (key,)).fetchone()
        expired = row is not None and row[2] is not None and int(row[2]) < now_ms
        remaining = 0 if row is None or expired else (int(row[0]) - int(row[1])) / 1_000_000
        raise BudgetExhaustedError(key, amount_usd, remaining)

    def release(self, key: str, allocation_id: str) -> None:
        with self._db.tx() as c:
            row = c.execute(self._release_row_sql, (key, allocation_id)).fetchone()
            if row is not None:
                c.execute(self._release_sql, (int(row[0]), key))

    def status(self, key: str) -> Optional[BudgetStatus]:
        with self._db.tx() as c:
            row = c.execute(self._status_sql, (key,)).fetchone()
        if row is None:
            return None
        limit, allocated, count = int(row[0]), int(row[1]), int(row[2])
        return BudgetStatus(key, limit / 1_000_000, allocated / 1_000_000, (limit - allocated) / 1_000_000, count)
