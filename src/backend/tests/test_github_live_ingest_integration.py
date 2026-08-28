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


# ===========================================================================
# Milestone 1 / Task 3 — Pattern 1 (approved, CI green, unmerged, idle >48h)
#
# D-161's finding #1 was that Pattern 1 could not fire in live ingestion at
# all, no matter what the data looked like, because nothing in the fetch
# path ever populated a PR's CI state — `ingest.py` hard-wrote
# `readiness.checks_state = 'unknown'`, and `sprint_filter.evaluate_p1`
# requires 'clean' as a POSITIVE condition. Half of the "2-Pattern MVP"
# was therefore unreachable code.
#
# These tests are the proof that it is reachable now, and — just as
# importantly — that the guard is still real: the same PR with red CI, with
# CI still running, and with no CI reported at all must each still ABSTAIN.
# A test that only proved the green case would not distinguish "Pattern 1
# now works" from "Pattern 1 now fires on everything".
#
# `ingest_worker.run_one` is used rather than the scratch-DB chain the two
# tests above use, for one reason: Pattern 1, like Pattern 2, must still
# pass `sprint_filter.sprint_gate()`, which needs a linked active-sprint
# ticket — and that means Jira ingestion in the same run, which is what
# `run_one` orchestrates. This is the real production entry point.
# ===========================================================================

from backend import ingest_worker  # noqa: E402
from backend.auth import now_iso  # noqa: E402

_P1_SLUG_COUNTER = iter(range(6000))

_CI_GREEN_STATUS = (b'{"state":"success","total_count":1,"sha":"deadbeefcafe",'
                    b'"statuses":[{"state":"success","context":"ci/build"}]}')
_CI_GREEN_CHECKS = (b'{"total_count":1,"check_runs":[{"name":"build",'
                    b'"status":"completed","conclusion":"success"}]}')


def _p1_rules(status_body=_CI_GREEN_STATUS, checks_body=_CI_GREEN_CHECKS,
              ticket_key="ENG-42", sprint_state="active"):
    """One approved-but-unmerged GitHub PR whose head commit has CI state,
    plus the Jira ticket that lets it through the sprint gate.

    Shaped as Pattern 1 and NOT Pattern 2: there is no `review_requested`
    event on the timeline at all, so `evaluate_p2` abstains and the verdict
    under test is unambiguously P1's own.

    Note the ordering of the keys below — `_route` returns the FIRST rule
    whose substring appears in the URL, and 'pilotco/widgets/pulls/42' is a
    substring of '.../pulls/42/reviews'. The more specific URLs must come
    first, the same way `_github_response_rules()` above already orders them.
    """
    issue = (
        ('{"number":42,"title":"[%s] Fix flaky retry budget",'
         '"user":{"login":"amy","type":"User"},"state":"open",'
         '"created_at":"2026-08-01T00:00:00Z","labels":[],'
         '"html_url":"https://github.com/pilotco/widgets/pull/42",'
         '"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
         % ticket_key).encode()
    )
    # `head.sha` is the new load-bearing field: without it `live_github`
    # correctly makes no CI call at all and readiness stays 'unknown'.
    pr = (b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean",'
          b'"head":{"sha":"deadbeefcafe","ref":"eng-42-retry-budget"}}')
    reviews = (b'[{"user":{"login":"riya","type":"User"},"state":"APPROVED",'
               b'"submitted_at":"2026-08-02T00:00:00Z","body":"lgtm"}]')

    project = b'{"key":"ENG","name":"Engineering"}'
    boards = b'{"values":[{"id":10,"name":"ENG board"}]}'
    sprints = (('{"values":[{"id":501,"name":"Sprint 12","state":"%s",'
                '"startDate":"2026-08-18T00:00:00.000Z",'
                '"endDate":"2026-09-01T00:00:00.000Z"}]}' % sprint_state).encode())
    sprint_issues = (
        ('{"issues":[{"key":"%s","fields":{"summary":"Fix flaky retry budget",'
         '"issuetype":{"name":"Story","subtask":false},'
         '"status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},'
         '"assignee":{"accountId":"acc-amy","displayName":"Amy","accountType":"atlassian"},'
         '"created":"2026-08-01T00:00:00.000+0000",'
         '"updated":"2026-08-19T00:00:00.000+0000"}}]}' % ticket_key).encode()
    )

    rules = {
        "installation/repositories": _FakeHTTPResponse(
            200, b'{"total_count":1,"repositories":['
                 b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}}]}'),
        "pilotco/widgets/pulls?state=open": _FakeHTTPResponse(200, b'[{"number":42,"title":"x"}]'),
        "pilotco/widgets/issues/42/timeline": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/issues/42/comments": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42/reviews": _FakeHTTPResponse(200, reviews),
        "commits/deadbeefcafe/check-runs": _FakeHTTPResponse(200, checks_body)
        if checks_body is not None else _FakeHTTPResponse(404, b'{}'),
        "commits/deadbeefcafe/status": _FakeHTTPResponse(200, status_body)
        if status_body is not None else _FakeHTTPResponse(404, b'{}'),
        "pilotco/widgets/pulls/42": _FakeHTTPResponse(200, pr),
        "pilotco/widgets/issues/42": _FakeHTTPResponse(200, issue),
        "rest/api/3/project/ENG": _FakeHTTPResponse(200, project),
        "rest/agile/1.0/board?projectKeyOrId=ENG": _FakeHTTPResponse(200, boards),
        "rest/agile/1.0/board/10/sprint": _FakeHTTPResponse(200, sprints),
        "rest/agile/1.0/sprint/501/issue": _FakeHTTPResponse(200, sprint_issues),
        "rest/agile/1.0/board/10/backlog": _FakeHTTPResponse(200, b'{"issues":[]}'),
        f"rest/api/3/issue/{ticket_key}/changelog": _FakeHTTPResponse(200, b'{"histories":[]}'),
    }
    return rules


@pytest.fixture
def p1_tenant(client):
    """A tenant with a claimed GitHub installation and Jira credentials for
    project ENG — the same two-integration setup 7.4c-d's own tests use."""
    n = next(_P1_SLUG_COUNTER)
    slug = f"p1-ci-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Pattern 1 CI Test Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()

    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    assert link.status_code == 201, link.text
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(760000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    cred = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                       json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                             "email": "a@acme.com", "api_token": "tok-real"})
    assert cred.status_code == 201, cred.text
    return tenant


def _run_p1(tenant, rules):
    tid = tenant["id"]
    with db.tenant_tx(tid) as conn:
        run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','running',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]
    with mock.patch.object(ingest_worker._TOKEN_CACHE, "get",
                           return_value="fake-installation-token"), \
         mock.patch("urllib.request.urlopen", side_effect=_route(rules)):
        result = ingest_worker.run_one(tid, tenant["slug"], run_id)
    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT pattern, outcome, reason, detail FROM alert WHERE ingest_run_id=%s",
            (run_id,)).fetchone()
        readiness = conn.execute(
            "SELECT checks_state, merge_state, evidence_note FROM readiness").fetchone()
    return result, alert, readiness


def test_pattern_1_fires_on_an_approved_green_ci_idle_pull_request(p1_tenant):
    """The claim Milestone 1 Task 3 exists to make true, end to end through
    the production entry point: an approved, CI-green, unmerged, 26-day-idle
    PR on an active-sprint ticket produces a real `alert` row with
    `pattern='P1-approved-unmerged'` and `outcome='FIRE'` in this tenant's
    Postgres. Before this task that outcome was structurally unreachable.
    """
    result, alert, readiness = _run_p1(p1_tenant, _p1_rules())

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 1
    assert result["FIRE"] == 1, result

    # The new input, stored where the detector actually reads it.
    assert readiness["checks_state"] == "clean", readiness
    assert "success" in (readiness["evidence_note"] or "")

    assert alert is not None
    assert alert["pattern"] == "P1-approved-unmerged", (alert["pattern"], alert["reason"])
    assert alert["outcome"] == "FIRE", (alert["outcome"], alert["reason"])
    assert "CI green" in (alert["detail"] or ""), alert["detail"]


def test_check_runs_alone_are_enough_when_the_repo_uses_no_commit_statuses(p1_tenant):
    """A repo on GitHub Actions only has ZERO commit statuses — the combined
    status endpoint reports `state='pending', total_count=0`, which is not a
    build at all. Reading only that endpoint would call every such repo
    'unknown' forever and silently disable Pattern 1 for the majority of
    modern repos. Both sources are read; either one being green is enough.
    """
    rules = _p1_rules(status_body=b'{"state":"pending","total_count":0,"statuses":[]}')
    result, alert, readiness = _run_p1(p1_tenant, rules)

    assert readiness["checks_state"] == "clean", readiness
    assert alert["outcome"] == "FIRE", (alert["outcome"], alert["reason"])
    assert alert["pattern"] == "P1-approved-unmerged"


def test_red_ci_does_not_fire_pattern_1(p1_tenant):
    """The guard is real. Same approved, idle, active-sprint PR — failing CI
    — must not fire. A red build is the team's own signal that the ball is
    not in the merger's court, and nagging about it is exactly the noise
    'precision over coverage' exists to prevent.
    """
    rules = _p1_rules(
        status_body=b'{"state":"failure","total_count":1,'
                    b'"statuses":[{"state":"failure","context":"ci/build"}]}',
        checks_body=b'{"total_count":1,"check_runs":[{"name":"build",'
                    b'"status":"completed","conclusion":"failure"}]}')
    result, alert, readiness = _run_p1(p1_tenant, rules)

    assert readiness["checks_state"] == "blocked", readiness
    assert result["FIRE"] == 0, result
    assert alert["outcome"] == "ABSTAIN", (alert["outcome"], alert["reason"])
    assert "ci_not_known_green" in alert["reason"], alert["reason"]


def test_still_running_ci_does_not_fire_pattern_1(p1_tenant):
    """One green check and one still-queued check is not a green commit.
    'pending' maps to 'unknown', never to 'clean' and never to 'blocked' —
    an unfinished build is neither a pass nor a failure, and Pattern 1
    requires a positive pass.
    """
    rules = _p1_rules(
        status_body=b'{"state":"pending","total_count":1,'
                    b'"statuses":[{"state":"pending","context":"ci/build"}]}',
        checks_body=b'{"total_count":2,"check_runs":['
                    b'{"name":"build","status":"completed","conclusion":"success"},'
                    b'{"name":"e2e","status":"in_progress","conclusion":null}]}')
    result, alert, readiness = _run_p1(p1_tenant, rules)

    assert readiness["checks_state"] == "unknown", readiness
    assert result["FIRE"] == 0, result
    assert alert["outcome"] == "ABSTAIN"
    assert "ci_not_known_green" in alert["reason"], alert["reason"]


def test_a_pr_whose_ci_endpoints_are_unreachable_stays_unknown_not_green(p1_tenant):
    """Failure to look must never read as 'we looked and it was fine'. Both
    CI endpoints 404 — readiness stays 'unknown' and Pattern 1 abstains,
    the same three-valued discipline D-031/D-037/D-042 set for merge state.
    """
    rules = _p1_rules(status_body=None, checks_body=None)
    result, alert, readiness = _run_p1(p1_tenant, rules)

    assert readiness["checks_state"] == "unknown", readiness
    assert result["FIRE"] == 0, result
    assert "ci_not_known_green" in alert["reason"], alert["reason"]


def test_green_ci_still_cannot_bypass_the_sprint_gate(p1_tenant):
    """CI state is an input to the pattern, not a way around the gate. The
    same green, approved, idle PR whose ticket sits in a NON-active sprint
    must come out SUPPRESSED — proving Task 3 widened what can fire without
    weakening what Phase 6 decided may not.
    """
    rules = _p1_rules(sprint_state="future")
    result, alert, readiness = _run_p1(p1_tenant, rules)

    assert readiness["checks_state"] == "clean", readiness
    assert result["FIRE"] == 0, result
    assert alert["pattern"] == "P1-approved-unmerged", alert["pattern"]
    assert alert["outcome"] == "SUPPRESSED", (alert["outcome"], alert["reason"])
    assert alert["reason"] == "not_active_sprint_work", alert["reason"]
