"""Milestone 1, Task 5.2/5.3: `system_health.compute_system_health()` — the
orthogonal CLEAN/DEGRADED tenant-health signal, and its wiring into
`GET /v1/alerts` and `GET /v1/digests/latest` as a response header.

Each of the three conditions 5.2 names is tested in isolation against a
fresh, single-purpose tenant — never `tenants`' shared 'acme'/'globex',
which other test files write into (the same isolation rule
`test_ingest_worker.py`'s own fixtures already hold themselves to).
"""
from __future__ import annotations

import itertools

import pytest

from backend import config, db, system_health as SH
from backend.auth import now_iso

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}

_SLUG_COUNTER = itertools.count()

NOW = "2026-08-28T12:00:00Z"


def _new_tenant(client, status: str = "shadow") -> dict:
    slug = f"health-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Health Test Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()
    tenant["headers"] = {"Authorization": f"Bearer {tenant['api_key']}"}
    if status != "shadow":
        r = client.post(f"/v1/admin/tenants/{slug}/status", headers=ADMIN,
                        params={"new_status": status})
        assert r.status_code == 200, r.text
    return tenant


def _github_source_id(conn) -> int:
    return conn.execute("SELECT id FROM source WHERE name='github'").fetchone()["id"]


def _install_github(conn, tenant_id: str, *, installed_at: str = NOW) -> int:
    src = _github_source_id(conn)
    return conn.execute(
        "INSERT INTO integration (tenant_id, source_id, external_account_id,"
        " credential_ref, installed_at) VALUES (%s,%s,'999','ref',%s) RETURNING id",
        (tenant_id, src, installed_at),
    ).fetchone()["id"]


def _succeeded_run(conn, tenant_id: str, *, started_at: str, finished_at: str,
                   error_detail: str | None = None) -> int:
    return conn.execute(
        "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at, finished_at,"
        " error_detail) VALUES (%s,'manual','succeeded',%s,%s,%s) RETURNING id",
        (tenant_id, started_at, finished_at, error_detail),
    ).fetchone()["id"]


def test_no_github_integration_is_degraded_with_missing_integration_reason(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        health = SH.compute_system_health(conn, tenant["id"], NOW)
    assert health.status == SH.DEGRADED
    kinds = [r.kind for r in health.reasons]
    assert "missing_integration" in kinds


def test_fresh_github_with_a_recent_successful_run_is_clean(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        _succeeded_run(conn, tenant["id"],
                       started_at="2026-08-28T11:00:00Z", finished_at="2026-08-28T11:05:00Z")
        health = SH.compute_system_health(conn, tenant["id"], NOW)
    assert health.status == SH.CLEAN, health.reasons
    assert health.reasons == []


def test_installed_but_never_synced_is_degraded_as_stale(client):
    """GitHub connected, but no webhook has ever arrived and no run has ever
    finished — an honest 'we have not heard anything yet' DEGRADED, not a
    guessed CLEAN."""
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        health = SH.compute_system_health(conn, tenant["id"], NOW)
    assert health.status == SH.DEGRADED
    kinds = [r.kind for r in health.reasons]
    assert kinds == ["stale_webhook"]


def test_last_signal_older_than_24h_is_degraded_as_stale(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-20T00:00:00Z")
        _succeeded_run(conn, tenant["id"],
                       started_at="2026-08-26T11:00:00Z", finished_at="2026-08-26T11:05:00Z")
        health = SH.compute_system_health(conn, tenant["id"], NOW)  # ~49h later
    assert health.status == SH.DEGRADED
    kinds = [r.kind for r in health.reasons]
    assert kinds == ["stale_webhook"]


def test_last_signal_at_exactly_23_hours_is_clean(client):
    """The threshold is >24h, not >=24h-ish — a run 23 hours old must not
    trip the banner."""
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-20T00:00:00Z")
        _succeeded_run(conn, tenant["id"],
                       started_at="2026-08-27T13:00:00Z", finished_at="2026-08-27T13:00:00Z")
        health = SH.compute_system_health(conn, tenant["id"], NOW)  # exactly 23h later
    assert health.status == SH.CLEAN


def test_rate_limited_error_detail_is_degraded(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        run_id = _succeeded_run(
            conn, tenant["id"], started_at="2026-08-28T11:00:00Z", finished_at="2026-08-28T11:05:00Z",
            error_detail="pilotco/widgets: HTTP 429 (rate limited or forbidden)")
        health = SH.compute_system_health(conn, tenant["id"], NOW, run_id=run_id)
    assert health.status == SH.DEGRADED
    kinds = [r.kind for r in health.reasons]
    assert "rate_limited" in kinds


def test_ordinary_error_detail_is_not_mistaken_for_rate_limiting(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        run_id = _succeeded_run(
            conn, tenant["id"], started_at="2026-08-28T11:00:00Z", finished_at="2026-08-28T11:05:00Z",
            error_detail="pilotco/widgets: ConnectionResetError")
        health = SH.compute_system_health(conn, tenant["id"], NOW, run_id=run_id)
    assert health.status == SH.CLEAN


def test_optional_integration_never_connected_does_not_degrade(client):
    """Jira/Linear/Slack are optional per tenant — never having connected
    one is the ordinary state for most pilots, not a degraded one."""
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        _succeeded_run(conn, tenant["id"],
                       started_at="2026-08-28T11:00:00Z", finished_at="2026-08-28T11:05:00Z")
        health = SH.compute_system_health(conn, tenant["id"], NOW)
    assert health.status == SH.CLEAN


def test_optional_integration_revoked_after_being_connected_does_degrade(client):
    """A regression (had Jira, lost it) is worth a flag; never having had it
    is not — this is the distinction that separates the two tests."""
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        _succeeded_run(conn, tenant["id"],
                       started_at="2026-08-28T11:00:00Z", finished_at="2026-08-28T11:05:00Z")
        jira_src = conn.execute("SELECT id FROM source WHERE name='jira'").fetchone()["id"]
        conn.execute(
            "INSERT INTO integration (tenant_id, source_id, external_account_id,"
            " credential_ref, installed_at, revoked_at)"
            " VALUES (%s,%s,'PROJ','ref','2026-08-01T00:00:00Z','2026-08-15T00:00:00Z')",
            (tenant["id"], jira_src))
        health = SH.compute_system_health(conn, tenant["id"], NOW)
    assert health.status == SH.DEGRADED
    kinds = [r.kind for r in health.reasons]
    assert kinds.count("missing_integration") == 1
    assert "jira" in health.reasons[[r.kind for r in health.reasons].index("missing_integration")].detail


# --- API wiring: the response header on /v1/alerts and /v1/digests/latest -

def test_alerts_endpoint_carries_system_health_header(client):
    tenant = _new_tenant(client)  # no GitHub integration -> DEGRADED
    r = client.get("/v1/alerts", headers=tenant["headers"])
    assert r.status_code == 200, r.text
    assert r.headers["x-argus-system-health"] == "DEGRADED"


def test_digests_latest_endpoint_carries_system_health_header(client):
    tenant = _new_tenant(client)
    with db.tenant_tx(tenant["id"]) as conn:
        _install_github(conn, tenant["id"], installed_at="2026-08-27T00:00:00Z")
        run_id = _succeeded_run(conn, tenant["id"],
                                started_at=now_iso(), finished_at=now_iso())
        conn.execute(
            "INSERT INTO digest_delivery (tenant_id, ingest_run_id, channel, status,"
            " rendered_text, delivered_at) VALUES (%s,%s,'dashboard','shadow','hi',%s)",
            (tenant["id"], run_id, now_iso()))
    r = client.get("/v1/digests/latest", headers=tenant["headers"])
    assert r.status_code == 200, r.text
    assert r.headers["x-argus-system-health"] == "CLEAN"
