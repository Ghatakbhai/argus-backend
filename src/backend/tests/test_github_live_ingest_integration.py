"""7.4c-b's actual end-to-end proof: an installation token's worth of live
GitHub data (HTTP mocked — see `verify_github_live_ingest.py`'s module
docstring for why a REAL api.github.com call still is not possible from
here) ingested into a scratch DB by `github_live_ingest.ingest_installation`,
then carried into real Postgres by 7.4c-a's `migrate()`/`record_phase6_run()`
— the exact two-step sequence the future in-process poller (7.4c-c) will
run, minus only the installation-token minting and the trigger itself.

This is deliberately a SHAPED review-request candidate (§3.1.2's own
worked example, "review requested with 0 response >48h" — P2), not a
hand-picked trivial item: it exercises the real `sprint_filter.evaluate_p2`
detector, not just "some alert row got written." The expected verdict is
SUPPRESSED, reason `no_ticket_link` — not FIRE — and that is itself the
correct, named finding, not a test bug: `sprint_filter.sprint_gate()`
requires at least one linked Jira/Linear ticket in an active sprint before
ANY pattern can fire (`src/sprint_filter.py` lines ~432-438), and GitHub-only
ingestion (this step; Jira/Linear live ingestion is 7.4c-d/e, not built yet)
never populates `ticket_link`. Confirmed here, not assumed: a live GitHub-only
pilot install would see every real stall candidate SUPPRESSED until Blocker
4's Jira/Linear ingestion lands, exactly as D-159's decision to bundle
Blocker 4 anticipated.
"""
import os
import sqlite3
import sys
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import db  # noqa: E402
from backend.migrate_sqlite import migrate, record_phase6_run  # noqa: E402
import github_live_ingest as GLI  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}
_SLUG_COUNTER = iter(range(2000))


class _FakeHTTPResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body
        self.headers = {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _route(rules):
    def _fake(req, timeout=None):
        for substr, resp in rules.items():
            if substr in req.full_url:
                return resp
        raise AssertionError(f"unrouted URL in test fixture: {req.full_url}")
    return _fake


@pytest.fixture
def live_ingest_tenant(client):
    slug = f"live-ingest-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Live Ingest Test Co"})
    assert r.status_code == 201, r.text
    return r.json()


def _github_response_rules():
    """One installation, one repo (`pilotco/widgets`), one open PR (#42):
    review requested from `riya` on day 1, item created on day 0, "now" is
    day 20 — 19 days (well past the 48h threshold) with no response and no
    other approval. Shaped exactly like §4.2's Pattern 2 ("review requested
    with 0 response >48h") from the operational checklist Dirgh reviewed.
    """
    issue = (
        b'{"number":42,"title":"Fix flaky retry budget in the worker pool",'
        b'"user":{"login":"amy"},"state":"open","created_at":"2026-08-01T00:00:00Z",'
        b'"labels":[],"html_url":"https://github.com/pilotco/widgets/pull/42",'
        b'"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
    )
    pr = b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}'
    timeline = (
        b'[{"event":"review_requested","actor":{"login":"amy"},'
        b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]'
    )
    return {
        "installation/repositories": _FakeHTTPResponse(
            200, b'{"total_count":1,"repositories":['
                 b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}}]}'),
        "pilotco/widgets/pulls?state=open": _FakeHTTPResponse(200, b'[{"number":42,"title":"x"}]'),
        "pilotco/widgets/issues/42/timeline": _FakeHTTPResponse(200, timeline),
        "pilotco/widgets/issues/42/comments": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42/reviews": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42": _FakeHTTPResponse(200, pr),
        "pilotco/widgets/issues/42": _FakeHTTPResponse(200, issue),
    }


def test_a_live_installation_ingest_carries_through_to_real_postgres_alert_rows(
        live_ingest_tenant):
    """The full 7.4c-a + 7.4c-b chain, proven together: a mocked installation
    token's GitHub data becomes a scratch DB (github_live_ingest, new at
    7.4c-b), which migrate()/record_phase6_run() (open-connection path, new
    at 7.4c-a/D-160) carries into this tenant's real, isolated Postgres rows
    — no temp file anywhere in the whole chain.
    """
    conn = GLI.build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=_route(_github_response_rules())):
        summary = GLI.ingest_installation(conn, "fake-installation-token",
                                          "2026-08-20T09:00:00Z")

    assert summary.repos_seen == 1
    assert summary.repos_failed == 0
    assert summary.prs_seen == 1
    assert summary.work_items_ingested == 1

    # Sanity on the scratch DB itself before it ever touches Postgres — if
    # THIS is wrong, a failure downstream would be ambiguous about which
    # layer broke.
    wi = conn.execute("SELECT title, source_number FROM work_item").fetchone()
    assert wi["title"] == "Fix flaky retry budget in the worker pool"
    assert wi["source_number"] == 42

    migrated = migrate(conn, live_ingest_tenant["slug"])
    assert migrated["counts"]["work_item"] == 1
    assert migrated["counts"]["project"] == 1

    run = record_phase6_run(conn, live_ingest_tenant["slug"], migrated["idmap"]["work_item"])
    assert run["results"] == 1

    with db.tenant_tx(live_ingest_tenant["id"]) as pg:
        alert = pg.execute(
            "SELECT pattern, outcome, reason FROM alert WHERE ingest_run_id=%s",
            (run["ingest_run_id"],)).fetchone()
        delivery = pg.execute(
            "SELECT payload_json, rendered_text FROM digest_delivery WHERE ingest_run_id=%s",
            (run["ingest_run_id"],)).fetchone()

    assert alert is not None
    assert alert["pattern"] == "P2-review-ghosted", alert["pattern"]
    # SUPPRESSED, not FIRE — the correct, named result. See this file's
    # module docstring: GitHub-only ingestion cannot pass sprint_gate()
    # until Jira/Linear ticket linkage (7.4c-d/e) exists.
    assert alert["outcome"] == "SUPPRESSED", alert["outcome"]
    assert alert["reason"] == "no_ticket_link", alert["reason"]
    assert delivery is not None
    assert delivery["payload_json"] is not None
    assert delivery["rendered_text"] is not None

    conn.close()


def test_one_bad_repo_still_lets_the_rest_of_the_installation_reach_postgres(
        live_ingest_tenant):
    """Two repos, one (`pilotco/broken`) whose sole PR blows up mid-ingest.
    The OTHER repo's real work item still makes it all the way through to a
    Postgres alert row for this tenant — github_live_ingest's per-repo
    isolation (verify_github_live_ingest.py's check 4) actually holding up
    across the full chain into Postgres, not just inside the scratch DB.
    """
    rules = dict(_github_response_rules())
    rules["installation/repositories"] = _FakeHTTPResponse(
        200, b'{"total_count":2,"repositories":['
             b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}},'
             b'{"name":"broken","full_name":"pilotco/broken","owner":{"login":"pilotco"}}]}')
    rules["pilotco/broken/pulls?state=open"] = _FakeHTTPResponse(200, b'[{"number":9,"title":"y"}]')
    rules["pilotco/broken/issues/9"] = _FakeHTTPResponse(
        200, b'{"number":9,"title":"broken item","user":{"login":"amy"},"state":"open",'
             b'"created_at":"2026-08-01T00:00:00Z","labels":[],"html_url":"h",'
             b'"updated_at":"2026-08-01T00:00:00Z","pull_request":{},"assignees":[]}')
    rules["pilotco/broken/pulls/9"] = _FakeHTTPResponse(
        200, b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}')
    rules["pilotco/broken/issues/9/timeline"] = _FakeHTTPResponse(200, b'[]')
    rules["pilotco/broken/issues/9/comments"] = _FakeHTTPResponse(200, b'[]')
    rules["pilotco/broken/pulls/9/reviews"] = _FakeHTTPResponse(200, b'[]')

    real_ingest_work_item = GLI.ingest_work_item

    def flaky(conn, snapshot_id, project_id, source_id, bundle):
        if bundle.repo == "broken":
            raise RuntimeError("simulated: a real bug ingesting this item")
        return real_ingest_work_item(conn, snapshot_id, project_id, source_id, bundle)

    conn = GLI.build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=_route(rules)), \
         mock.patch.object(GLI, "ingest_work_item", side_effect=flaky):
        summary = GLI.ingest_installation(conn, "fake-installation-token",
                                          "2026-08-20T09:00:00Z")

    assert summary.repos_seen == 2
    assert summary.repos_failed == 1
    assert "pilotco/broken" in summary.repo_errors
    assert summary.work_items_ingested == 1  # widgets' item, not broken's

    migrated = migrate(conn, live_ingest_tenant["slug"])
    assert migrated["counts"]["work_item"] == 1
    assert migrated["counts"]["project"] == 1  # broken's project row was rolled back, not left dangling

    run = record_phase6_run(conn, live_ingest_tenant["slug"], migrated["idmap"]["work_item"])
    with db.tenant_tx(live_ingest_tenant["id"]) as pg:
        alerts = pg.execute(
            "SELECT pattern FROM alert WHERE ingest_run_id=%s",
            (run["ingest_run_id"],)).fetchall()
    assert len(alerts) == 1
    assert alerts[0]["pattern"] == "P2-review-ghosted"

    conn.close()
