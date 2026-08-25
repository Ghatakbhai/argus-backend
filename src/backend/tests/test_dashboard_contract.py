"""Phase 7.4b: proves the data-contract gap `src/dashboard/CONTRACT.md` named
is actually closed — not just that the code runs, but that a real HTTP caller
gets the real shape back, sourced from real data written by
`migrate_sqlite.record_phase6_run`.

Uses its OWN tenant ('dash74b'), created here rather than borrowing the
'acme'/'globex' tenants conftest.py already seeded: those are session-scoped
and shared with test_isolation.py and test_real_phase6_data.py, and migrating
five more Phase 6 work items into them would silently change what those other
files count — the kind of cross-file, order-dependent breakage this project's
own working agreement calls out as the failure mode to fear most.
"""
import json
import os

import pytest

from backend import db, migrate_sqlite

SQLITE = "/mnt/user-data/uploads/ARGUS/data/phase6_9_scenarios.sqlite"
pytestmark = pytest.mark.skipif(not os.path.exists(SQLITE),
                                reason="Phase 6 live database not staged")

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}


@pytest.fixture(scope="module")
def dash_tenant(client):
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": "dash74b", "display_name": "Dashboard 7.4b Test Co"})
    assert r.status_code == 201, r.text
    body = r.json()
    return {**body, "headers": {"Authorization": f"Bearer {body['api_key']}"}}


@pytest.fixture(scope="module")
def loaded(dash_tenant):
    res = migrate_sqlite.migrate(SQLITE, "dash74b")
    run = migrate_sqlite.record_phase6_run(SQLITE, "dash74b", res["idmap"]["work_item"])
    return {"idmap": res["idmap"], "run": run}


def test_payload_json_is_written_and_parses(loaded, dash_tenant):
    with db.tenant_tx(dash_tenant["id"]) as conn:
        row = conn.execute(
            "SELECT rendered_text, payload_json FROM digest_delivery WHERE ingest_run_id=%s",
            (loaded["run"]["ingest_run_id"],),
        ).fetchone()
    assert row["rendered_text"], "rendered_text must still be written (CONTRACT.md: from the SAME Digest)"
    assert row["payload_json"], "payload_json must be written alongside it, not left NULL"
    payload = json.loads(row["payload_json"])
    for key in ("tenant", "freshness", "digest", "clusters", "people_out", "suppressed_items"):
        assert key in payload, f"envelope missing {key!r}"
    assert payload["digest"]["counts"]["items_checked"] == loaded["run"]["results"]


def test_format_json_over_real_http_matches_the_stored_row(loaded, dash_tenant, client):
    h = dash_tenant["headers"]
    r = client.get("/v1/digests/latest?format=json", headers=h)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["tenant"]["slug"] == "dash74b"
    assert payload["contract_version"] == "7.4b"
    with db.tenant_tx(dash_tenant["id"]) as conn:
        stored = conn.execute(
            "SELECT payload_json FROM digest_delivery ORDER BY delivered_at DESC, id DESC LIMIT 1"
        ).fetchone()
    assert payload == json.loads(stored["payload_json"])


def test_format_text_is_unaffected(loaded, dash_tenant, client):
    h = dash_tenant["headers"]
    r = client.get("/v1/digests/latest", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "rendered_text" in body and "payload_json" not in body


def test_format_json_409s_on_a_digest_with_no_payload(client):
    """A digest_delivery row written the pre-7.4b way (rendered_text only,
    no payload_json) must not be silently upgraded or invented for — it must
    say plainly that it has none."""
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": "dash74b-nopayload", "display_name": "No Payload Co"})
    body = r.json()
    headers = {"Authorization": f"Bearer {body['api_key']}"}
    with db.tenant_tx(body["id"]) as conn:
        run = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','succeeded',%s) RETURNING id",
            (body["id"], "2026-08-24T00:00:00Z"),
        ).fetchone()["id"]
        conn.execute(
            "INSERT INTO digest_delivery (tenant_id, ingest_run_id, channel, status,"
            " rendered_text, delivered_at) VALUES (%s,%s,'dashboard','delivered',%s,%s)",
            (body["id"], run, "some rendered text, no payload", "2026-08-24T00:00:05Z"),
        )
    r = client.get("/v1/digests/latest?format=json", headers=headers)
    assert r.status_code == 409, r.text


def test_alert_out_carries_item_key_title_url_detail(loaded, dash_tenant, client):
    h = dash_tenant["headers"]
    rows = client.get("/v1/alerts?limit=500", headers=h).json()
    real = [a for a in rows if a["ingest_run_id"] == loaded["run"]["ingest_run_id"]]
    assert real, "the migrated run's alerts should be visible"
    for a in real:
        assert a["item_key"], a
        assert "#" in a["item_key"]
        assert a["title"]
        assert a["url"] and a["url"].startswith("https://")
        if a["outcome"] != "ABSTAIN":
            # FIRE/SUPPRESSED always carry the gate's own evidence sentence
            # (sprint_filter._apply_gate always sets it). ABSTAIN rows come
            # from _abstain(), which never sets `evidence` at all — an empty
            # detail there is the real, honest shape, not a bug.
            assert a["detail"], "alert.detail must be the filter's own evidence sentence"


def test_me_lists_members(dash_tenant, client):
    h = dash_tenant["headers"]
    body = client.get("/v1/me", headers=h).json()
    assert "members" in body
    assert isinstance(body["members"], list)


def test_migration_file_is_idempotent():
    """schema_7_4_dashboard.sql must survive being re-applied against a
    database that already has both columns — exactly what happens on every
    real restart (D-141)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "schema_7_4_dashboard.sql")) as f:
        sql = f.read()
    # Applied as the owner role, the same connection bootstrap_schema_if_needed
    # uses — argus_app/argus_admin have no DDL rights at all.
    import psycopg

    from backend import config
    from backend.tests.conftest import CI_OWNER, CI_OWNER_PASSWORD
    dsn = (f"host={config.PGHOST} port={config.PGPORT} dbname={config.PGDATABASE}"
          f" user={CI_OWNER} password={CI_OWNER_PASSWORD}")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(sql)  # must not raise
        conn.execute(sql)  # a second time — must still not raise
