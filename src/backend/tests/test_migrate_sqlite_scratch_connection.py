"""7.4c-a: `migrate()` / `record_phase6_run()` now accept an already-open
`sqlite3.Connection`, not only a file path — the plumbing the live ingestion
consumer (D-156) needs to hand in a populated in-memory scratch database
without ever writing a temp file to disk. See D-160.

This is a small, hand-built world (same style as test_dashboard_payload.py's
`world` fixture), not a real snapshot — the point here is exercising the NEW
calling convention end to end, not re-proving the engine's verdicts (that is
test_real_phase6_data.py's job, and it already covers the file-path path).
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import db  # noqa: E402
from backend.migrate_sqlite import migrate, record_phase6_run  # noqa: E402

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOW = "2026-08-25T09:00:00Z"

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}


@pytest.fixture
def scratch_conn():
    """A fresh, in-memory SQLite database — exactly the shape a live
    ingestion run will build per D-156's design: one small project with one
    open PR-shaped work item, nothing pre-existing on disk anywhere."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(os.path.join(SRC, "schema.sql")) as f:
        conn.executescript(f.read())

    conn.execute("INSERT INTO source (id, name, base_url) VALUES (1,'github','https://github.com')")
    conn.execute("INSERT INTO project (id, source_id, source_key, display_name)"
                " VALUES (1,1,'acme/scratch','acme/scratch')")
    conn.execute("INSERT INTO snapshot (id, source_id, project_id, observed_at, started_at,"
                " is_complete) VALUES (1,1,1,?,?,1)", (NOW, NOW))
    conn.execute("INSERT INTO actor (id, source_id, source_key, kind, kind_reason)"
                " VALUES (1,1,'riya-p','human','assumed_human')")
    conn.execute(
        "INSERT INTO work_item (id, snapshot_id, project_id, source_number, kind, title,"
        " state, author_id, created_at, url) VALUES (1,1,1,701,'change_request',"
        "'Add retry budget','open',1,?,?)",
        (NOW, "https://github.com/acme/scratch/pull/701"))
    conn.execute(
        "INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,"
        " counts_as_human, human_reason) VALUES (1,1,'opened',1,?,1,'human')", (NOW,))
    conn.commit()
    return conn


_SLUG_COUNTER = iter(range(1000))


@pytest.fixture
def scratch_tenant(client):
    # One tenant per test, not one shared across the module: `client` is
    # session-scoped, and re-posting the same slug twice is a 409, not a
    # fresh tenant. The slug pattern caps out around 40 chars, so a short
    # counter-based slug is used rather than the (much longer) test name.
    slug = f"scratch-conn-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Scratch Conn Test Co"})
    assert r.status_code == 201, r.text
    return r.json()


def test_migrate_accepts_an_open_connection_directly(scratch_conn, scratch_tenant):
    """No file path anywhere in this call — `migrate()` reads straight off
    the connection the caller already built and populated."""
    result = migrate(scratch_conn, scratch_tenant["slug"])
    assert result["counts"]["work_item"] == 1
    assert result["counts"]["actor"] == 1

    with db.tenant_tx(scratch_tenant["id"]) as conn:
        row = conn.execute("SELECT title, source_number FROM work_item WHERE id=%s",
                           (result["idmap"]["work_item"][1],)).fetchone()
    assert row["title"] == "Add retry budget"
    assert row["source_number"] == 701


def test_migrate_does_not_close_a_connection_it_did_not_open(scratch_conn, scratch_tenant):
    """The connection is the caller's to close, not migrate_sqlite's — this
    is what makes it safe for a future worker to reuse the same connection
    for migrate() and then record_phase6_run() in one ingest run."""
    migrate(scratch_conn, scratch_tenant["slug"])
    # Still usable: a closed sqlite3.Connection raises ProgrammingError on use.
    assert scratch_conn.execute("SELECT COUNT(*) FROM work_item").fetchone()[0] == 1


def test_record_phase6_run_accepts_the_same_open_connection_after_migrate(
    scratch_conn, scratch_tenant):
    """The exact sequence a live ingestion run will make: migrate() first
    (entities into Postgres), then record_phase6_run() against the SAME
    still-open connection (engine verdicts + digest into Postgres) — no path,
    no second file, no reconnect."""
    migrated = migrate(scratch_conn, scratch_tenant["slug"])
    run = record_phase6_run(scratch_conn, scratch_tenant["slug"], migrated["idmap"]["work_item"])
    assert run["results"] == 1

    with db.tenant_tx(scratch_tenant["id"]) as conn:
        alerts = conn.execute("SELECT outcome FROM alert WHERE ingest_run_id=%s",
                              (run["ingest_run_id"],)).fetchall()
        delivery = conn.execute("SELECT payload_json FROM digest_delivery WHERE ingest_run_id=%s",
                                (run["ingest_run_id"],)).fetchone()
    assert len(alerts) == 1
    assert delivery["payload_json"] is not None

    # And the connection is STILL open after both calls — ours to close.
    assert scratch_conn.execute("SELECT 1").fetchone()[0] == 1
    scratch_conn.close()


def test_the_file_path_calling_convention_is_unchanged(scratch_tenant, tmp_path):
    """The original callers (migrate_sqlite.py's own __main__, and
    test_real_phase6_data.py) pass a path, not a connection. That path must
    behave exactly as before: opened read-only here, and closed here — a
    caller who only ever passes paths should see no difference at all."""
    db_path = tmp_path / "scratch.sqlite"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    with open(os.path.join(SRC, "schema.sql")) as f:
        conn.executescript(f.read())
    conn.execute("INSERT INTO source (id, name, base_url) VALUES (1,'github','https://github.com')")
    conn.execute("INSERT INTO project (id, source_id, source_key, display_name)"
                " VALUES (1,1,'acme/scratch2','acme/scratch2')")
    conn.execute("INSERT INTO snapshot (id, source_id, project_id, observed_at, started_at,"
                " is_complete) VALUES (1,1,1,?,?,1)", (NOW, NOW))
    conn.commit()
    conn.close()

    result = migrate(str(db_path), scratch_tenant["slug"])
    assert result["counts"]["source"] >= 1
