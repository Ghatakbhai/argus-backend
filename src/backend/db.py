"""ARGUS Phase 7.1 — database access, and the one place a tenant gets bound.

The rule this module exists to enforce: no query touches tenant data outside
`tenant_tx()`. Inside it, every statement runs in a transaction that has
`argus.tenant_id` set, which is what the row-level security policies read. If
the binding is ever missing, the policies see NULL and the query returns zero
rows — a bug here shows up as an empty screen, never as another team's data.
"""
from __future__ import annotations

import contextlib
import os
from typing import Iterator

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import config

_app_pool: ConnectionPool | None = None
_admin_pool: ConnectionPool | None = None


def bootstrap_schema_if_needed() -> bool:
    """Applies schema_pg.sql then roles.sql to a brand-new database exactly
    once, using a superuser-ish "owner" connection string (`ARGUS_OWNER_DSN`)
    that only this one-shot bootstrap ever touches — `argus_app`/`argus_admin`
    still can't create tables, extensions or roles, same as before.

    This exists so a fresh managed Postgres (Render's, at step 7.2) comes up
    ready with zero manual `psql -f ...` steps. Dirgh never opens a terminal
    on this host, or any other — the working agreement's rule holds even
    though this step is the first one to actually deploy anywhere.

    Whether or not the schema was already present, this ALSO syncs
    `argus_app`/`argus_admin`'s real passwords to `config.APP_DB_PASSWORD` /
    `config.ADMIN_DB_PASSWORD` on every call. roles.sql itself still creates
    both roles with fixed, published-in-this-repo development passwords —
    fine for a local sandbox nobody else can reach, a real problem the
    moment this runs against a database with a public IP. Setting
    ARGUS_APP_DB_PASSWORD / ARGUS_ADMIN_DB_PASSWORD to a host-generated
    random value (Render's "Generate Value" does this with no typing from
    Dirgh at all) means the passwords actually protecting production are
    never the ones checked into this repository, without needing a second
    manual step to rotate them after the fact.

    Returns True if it just ran the schema/roles migration, False if the
    schema was already present (every restart after the first) or no owner
    DSN was configured at all (e.g. local dev, where conftest.py already
    runs the migration files directly against a superuser connection).
    """
    if not config.OWNER_DSN:
        return False
    with psycopg.connect(config.OWNER_DSN, autocommit=True) as conn:
        already = conn.execute("SELECT to_regclass('public.tenant')").fetchone()[0]
        just_migrated = not already
        if just_migrated:
            here = os.path.dirname(os.path.abspath(__file__))
            for fname in ("schema_pg.sql", "roles.sql"):
                with open(os.path.join(here, fname)) as f:
                    # One `execute()` per file, not per statement: psycopg
                    # sends a parameter-less query as Postgres's "simple
                    # query" protocol message, which (like `psql -f`) allows
                    # multiple ;-separated statements in one call.
                    conn.execute(f.read())
        # ALTER ROLE's PASSWORD clause is a literal in the grammar, not a
        # bindable value — sql.Literal() is psycopg's safe way to quote one
        # in without hand-rolling escaping.
        for role, password in (("argus_app", config.APP_DB_PASSWORD),
                                ("argus_admin", config.ADMIN_DB_PASSWORD)):
            conn.execute(sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)))
    return just_migrated


def app_pool() -> ConnectionPool:
    global _app_pool
    if _app_pool is None:
        _app_pool = ConnectionPool(config.APP_DSN, min_size=1, max_size=8,
                                   kwargs={"row_factory": dict_row}, open=True)
    return _app_pool


def admin_pool() -> ConnectionPool:
    global _admin_pool
    if _admin_pool is None:
        _admin_pool = ConnectionPool(config.ADMIN_DSN, min_size=1, max_size=4,
                                     kwargs={"row_factory": dict_row}, open=True)
    return _admin_pool


def close_pools() -> None:
    global _app_pool, _admin_pool
    for p in (_app_pool, _admin_pool):
        if p is not None:
            p.close()
    _app_pool = _admin_pool = None


@contextlib.contextmanager
def tenant_tx(tenant_id: str) -> Iterator[psycopg.Connection]:
    """A transaction bound to exactly one tenant. The only door into tenant data."""
    with app_pool().connection() as conn:
        with conn.transaction():
            # set_config(..., is_local => true) scopes the binding to this
            # transaction, so a pooled connection can never carry one tenant's
            # binding into the next request.
            conn.execute("SELECT set_config('argus.tenant_id', %s, true)",
                         (str(tenant_id),))
            yield conn


@contextlib.contextmanager
def unbound_app_tx() -> Iterator[psycopg.Connection]:
    """An app-role transaction with NO tenant bound.

    Used only for things that are genuinely tenant-less: resolving a presented
    API key, and writing an audit row for a request that was refused. Any data
    query made through here returns nothing, by design.
    """
    with app_pool().connection() as conn:
        with conn.transaction():
            yield conn


@contextlib.contextmanager
def admin_tx() -> Iterator[psycopg.Connection]:
    """Control plane only: create tenants, issue and revoke keys, read metrics."""
    with admin_pool().connection() as conn:
        with conn.transaction():
            yield conn
