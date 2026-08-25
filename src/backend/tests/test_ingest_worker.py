"""7.4c-c: the in-process ingestion poller and the manual admin run-now
endpoint — the piece D-156 named as still missing after 7.4c-a (scratch-DB
plumbing, D-160) and 7.4c-b (GitHub live fetch, D-161): something that
actually decides WHEN those run, for WHICH tenant, against a real
`ingest_run` row.

The one thing worth proving above everything else here: a real `ingest_run`
row created by a GitHub webhook (status 'queued') is the SAME row that ends
up 'succeeded' with `alert`/`digest_delivery` pointing at it — not a second,
duplicate row. `migrate_sqlite.record_phase6_run()`'s original behavior
(every caller before this one) always INSERTed a fresh 'backfill' row; the
whole point of `existing_run_id` (this step's change to that function) is
that a live, webhook-triggered run does not get a phantom second row and a
`ingest_run` stuck at 'running' forever.

Network is mocked throughout — no real api.github.com call is possible from
here (D-121, reconfirmed at 7.4c-b) or, separately, from Render's own free
tier's inactivity-window behavior worth testing against. `test_ingest_worker
_end_to_end_on_render.md` (this session's manual runbook, not a pytest file)
is where the ACTUAL live proof against the deployed service happens — the
one thing no amount of mocking here can substitute for.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import config, db, ingest_worker  # noqa: E402
from backend.auth import now_iso  # noqa: E402
import github_live_ingest as GLI  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}
_SLUG_COUNTER = iter(range(3000))


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


def _github_response_rules(owner="pilotco", repo="widgets", number=42):
    """One installation, one repo, one open PR shaped as §4.2 Pattern 2
    ("review requested with 0 response >48h") — the same shape
    test_github_live_ingest_integration.py's own fixture uses, kept minimal
    here since this file is testing the trigger layer, not re-proving the
    detector.
    """
    issue = (
        b'{"number":%d,"title":"Fix flaky retry budget",'
        b'"user":{"login":"amy"},"state":"open","created_at":"2026-08-01T00:00:00Z",'
        b'"labels":[],"html_url":"https://github.com/%s/%s/pull/%d",'
        b'"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
        % (number, owner.encode(), repo.encode(), number)
    )
    pr = b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}'
    timeline = (
        b'[{"event":"review_requested","actor":{"login":"amy"},'
        b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]'
    )
    return {
        "installation/repositories": _FakeHTTPResponse(
            200, ('{"total_count":1,"repositories":['
                  '{"name":"%s","full_name":"%s/%s","owner":{"login":"%s"}}]}'
                  % (repo, owner, repo, owner)).encode()),
        f"{owner}/{repo}/pulls?state=open": _FakeHTTPResponse(
            200, ('[{"number":%d,"title":"x"}]' % number).encode()),
        f"{owner}/{repo}/issues/{number}/timeline": _FakeHTTPResponse(200, timeline),
        f"{owner}/{repo}/issues/{number}/comments": _FakeHTTPResponse(200, b'[]'),
        f"{owner}/{repo}/pulls/{number}/reviews": _FakeHTTPResponse(200, b'[]'),
        f"{owner}/{repo}/pulls/{number}": _FakeHTTPResponse(200, pr),
        f"{owner}/{repo}/issues/{number}": _FakeHTTPResponse(200, issue),
    }


@pytest.fixture(autouse=True)
def _cancel_stray_queued_runs(tenants):
    """`argus_claim_next_queued_run` scans EVERY tenant's `ingest_run`, not
    just the one a test cares about — and this whole suite shares one
    session-scoped database. `test_github_webhooks.py` (this session's own
    earlier test file) posts several real webhooks for 'acme'/'globex' that
    each leave a real 'queued' row behind on purpose (nothing before this
    step ever consumed the queue, so that was always harmless). Without this
    cleanup, a test in THIS file expecting to claim its own freshly-created
    row could instead claim one of those leftovers first — and since this
    file's mocked GitHub responses answer any installation the same way
    regardless of which tenant is actually being processed, that would
    silently write fabricated work items into 'acme'/'globex', corrupting
    the exact-row-count assertions `test_isolation.py` makes against those
    same two tenants. Cancelled (not claimed-and-run) here, once before every
    test in this file, so nothing in this module can be affected by, or
    accidentally corrupt data for, a tenant it never created.
    """
    for slug in ("acme", "globex"):
        tid = tenants[slug]["id"]
        with db.tenant_tx(tid) as conn:
            conn.execute("UPDATE ingest_run SET status='cancelled' WHERE status='queued'")
    yield


@pytest.fixture
def worker_tenant(client):
    """A tenant with a claimed GitHub installation — every ingest_worker test
    needs `_github_installation_id` to find a real, unrevoked `integration`
    row, the same claim flow test_github_webhooks.py already proves works.
    """
    n = next(_SLUG_COUNTER)
    slug = f"worker-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Worker Test Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()

    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    assert link.status_code == 201, link.text
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(600000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text
    tenant["installation_id"] = str(600000 + n)
    return tenant


@pytest.fixture
def bare_tenant(client):
    """A tenant with NO GitHub integration at all — deliberately not 'acme'/
    'globex' (conftest.py's shared fixture tenants): by the time this file's
    tests run, `test_github_webhooks.py` has already claimed a real, live
    installation for both of them (installation 500100 for acme; several for
    globex), so neither is actually installation-free in a full suite run.
    """
    slug = f"bare-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Bare Test Co"})
    assert r.status_code == 201, r.text
    return r.json()


def _mock_network(rules=None):
    """Patches both halves of a live fetch: the token mint (InstallationTokenCache,
    normally an httpx call to GitHub) and the REST calls github_live_ingest
    makes through live_github.py's urllib-based `_get_with_retry`."""
    return (
        mock.patch.object(ingest_worker._TOKEN_CACHE, "get",
                          return_value="fake-installation-token"),
        mock.patch("urllib.request.urlopen",
                   side_effect=_route(rules if rules is not None else _github_response_rules())),
    )


# --- argus_claim_next_queued_run: the cross-tenant claim function ----------

def test_claim_next_queued_run_returns_nothing_when_queue_is_empty(client, tenants):
    with db.admin_tx() as conn:
        row = conn.execute("SELECT * FROM argus_claim_next_queued_run(%s)",
                           (now_iso(),)).fetchone()
    assert row is None or row["out_run_id"] is None


def test_claim_next_queued_run_picks_the_oldest_and_flips_it_to_running(client, worker_tenant):
    """Also claims 'newer' at the end (rather than leaving it dangling) so
    this test does not itself pollute the shared, session-scoped database
    with a permanently-queued row other tests could stumble over.
    """
    tid = worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        older = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','queued','2026-08-20T00:00:00Z') RETURNING id",
            (tid,)).fetchone()["id"]
        newer = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','queued','2026-08-21T00:00:00Z') RETURNING id",
            (tid,)).fetchone()["id"]

    with db.admin_tx() as conn:
        claimed = conn.execute("SELECT * FROM argus_claim_next_queued_run(%s)",
                               (now_iso(),)).fetchone()
    assert claimed["out_run_id"] == older
    assert str(claimed["out_tenant_id"]) == tid
    assert claimed["out_tenant_slug"] == worker_tenant["slug"]

    with db.tenant_tx(tid) as conn:
        rows = {r["id"]: r["status"] for r in
                conn.execute("SELECT id, status FROM ingest_run WHERE id IN (%s,%s)",
                             (older, newer)).fetchall()}
    assert rows[older] == "running"
    assert rows[newer] == "queued"  # untouched — only the oldest was claimed

    with db.admin_tx() as conn:
        second = conn.execute("SELECT * FROM argus_claim_next_queued_run(%s)",
                              (now_iso(),)).fetchone()
    assert second["out_run_id"] == newer  # and now cleaned up, not left queued


def test_claim_next_queued_run_never_claims_the_same_row_twice(client, worker_tenant):
    """Asserts against THIS test's own row specifically, not against the
    queue being globally empty — the database is shared across this whole
    session's tests, so another test's row could legitimately still be
    'queued' at this point without that meaning this function is broken.
    """
    tid = worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        my_run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','queued',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]

    with db.admin_tx() as conn:
        first = conn.execute("SELECT * FROM argus_claim_next_queued_run(%s)",
                             (now_iso(),)).fetchone()
    assert first["out_run_id"] == my_run_id

    with db.tenant_tx(tid) as conn:
        status_after_first = conn.execute("SELECT status FROM ingest_run WHERE id=%s",
                                          (my_run_id,)).fetchone()["status"]
    assert status_after_first == "running"

    # A second claim may legitimately find and claim SOME other queued row
    # left by a different test — it must never be THIS one again.
    with db.admin_tx() as conn:
        second = conn.execute("SELECT * FROM argus_claim_next_queued_run(%s)",
                              (now_iso(),)).fetchone()
    if second is not None and second["out_run_id"] is not None:
        assert second["out_run_id"] != my_run_id


# --- run_one: the real chain, against a row that already exists ------------

def test_run_one_updates_the_existing_row_rather_than_creating_a_second_one(
        client, worker_tenant):
    """The core fix this step makes: before 7.4c-c, `record_phase6_run` had
    no way to avoid inserting a brand-new 'backfill' row — a live run against
    an existing webhook-created row would have left TWO ingest_run rows
    (one forever 'running', one new 'succeeded' with the real data) instead
    of one. Asserting `len(rows) == 1` is the assertion that would have
    failed before this session's change to `record_phase6_run`.
    """
    tid = worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','running',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]

    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["prs_seen"] == 1
    assert result["work_items_ingested"] == 1

    with db.tenant_tx(tid) as conn:
        rows = conn.execute("SELECT id, status FROM ingest_run WHERE tenant_id=%s",
                            (tid,)).fetchall()
        alert = conn.execute("SELECT pattern, outcome FROM alert WHERE ingest_run_id=%s",
                             (run_id,)).fetchone()
        delivery = conn.execute(
            "SELECT payload_json FROM digest_delivery WHERE ingest_run_id=%s",
            (run_id,)).fetchone()

    assert len(rows) == 1, "run_one must update the existing row, not insert a second one"
    assert rows[0]["id"] == run_id
    assert rows[0]["status"] == "succeeded"
    assert alert is not None
    assert alert["pattern"] == "P2-review-ghosted"
    assert delivery is not None and delivery["payload_json"] is not None


def test_run_one_records_a_clean_failure_when_the_tenant_has_no_github_installation(
        client, bare_tenant):
    """This is the ordinary state of a tenant mid-onboarding, or one whose
    only installation was uninstalled: `run_one` must leave the row 'failed'
    with a readable reason, never raise past this function or leave the row
    stuck 'running'.
    """
    tid = bare_tenant["id"]
    with db.tenant_tx(tid) as conn:
        run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','running',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]

    result = ingest_worker.run_one(tid, bare_tenant["slug"], run_id)
    assert result["status"] == "failed"
    assert "NoGitHubInstallation" in result["error"]

    with db.tenant_tx(tid) as conn:
        row = conn.execute("SELECT status, error_detail, finished_at FROM ingest_run WHERE id=%s",
                           (run_id,)).fetchone()
    assert row["status"] == "failed"
    assert row["error_detail"] and "no active" in row["error_detail"]
    assert row["finished_at"] is not None


def test_run_one_survives_a_repo_level_failure_without_failing_the_whole_run(
        client, worker_tenant):
    """Mirrors test_github_live_ingest_integration.py's own multi-repo
    isolation check ('a real cross-repo data-loss bug ... found and fixed
    while testing') one layer up: a repo that blows up mid-ingest costs that
    repo's data, not the whole run — and it shows up as `error_detail` on an
    otherwise-'succeeded' row, not silently dropped. Forces a genuine
    exception via a patched `ingest_work_item`, the same technique that
    test uses — an HTTP error response alone would not reach this path at
    all, since `live_github.py`'s own retry layer already swallows a single
    failed call and reports it the same as a repo with zero open PRs
    (github_live_ingest.py's own module docstring names this explicitly).
    """
    tid = worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','running',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]

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

    token_patch, url_patch = _mock_network(rules)
    with token_patch, url_patch, mock.patch.object(GLI, "ingest_work_item", side_effect=flaky):
        result = ingest_worker.run_one(tid, worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded"  # widgets still made it through
    assert result["work_items_ingested"] == 1
    assert result["repos_failed"] == 1

    with db.tenant_tx(tid) as conn:
        row = conn.execute("SELECT status, error_detail FROM ingest_run WHERE id=%s",
                           (run_id,)).fetchone()
    assert row["status"] == "succeeded"
    assert row["error_detail"] and "pilotco/broken" in row["error_detail"]


# --- claim_and_run_one: the real webhook -> queued -> succeeded round trip -

def test_claim_and_run_one_drains_a_real_webhook_created_queued_row(client, worker_tenant):
    """The actual scenario 7.4c-c exists for: a live GitHub webhook queues a
    run (exactly what `/v1/webhooks/github` already does, unchanged since
    7.2); this function finds it with no tenant hint, no run id passed in —
    only that it is the oldest 'queued' row anywhere — and finishes it.
    """
    import hashlib
    import hmac
    import json as jsonlib

    payload = {
        "action": "opened", "number": 42,
        "pull_request": {"number": 42, "title": "x", "state": "open"},
        "repository": {"full_name": "pilotco/widgets"},
        "installation": {"id": int(worker_tenant["installation_id"]),
                         "account": {"login": "pilotco", "type": "Organization"}},
    }
    body = jsonlib.dumps(payload).encode()
    sig = "sha256=" + hmac.new(config.GITHUB_WEBHOOK_SECRET.encode(), body,
                               hashlib.sha256).hexdigest()
    webhook = client.post("/v1/webhooks/github", content=body, headers={
        "x-github-event": "pull_request", "x-github-delivery": "d-worker-1",
        "x-hub-signature-256": sig, "content-type": "application/json"})
    assert webhook.status_code == 200, webhook.text
    queued_run_id = webhook.json()["ingest_run_id"]
    assert queued_run_id is not None

    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        processed = ingest_worker.claim_and_run_one()
    assert processed is True

    with db.tenant_tx(worker_tenant["id"]) as conn:
        rows = conn.execute("SELECT id, status FROM ingest_run WHERE tenant_id=%s",
                            (worker_tenant["id"],)).fetchall()
        alert = conn.execute("SELECT pattern FROM alert WHERE ingest_run_id=%s",
                             (queued_run_id,)).fetchone()

    assert len(rows) == 1, "the webhook's own row must be the one that finishes, not a second one"
    assert rows[0]["id"] == queued_run_id
    assert rows[0]["status"] == "succeeded"
    assert alert is not None


def test_claim_and_run_one_returns_false_when_nothing_is_queued(client, tenants):
    assert ingest_worker.claim_and_run_one() is False


# --- the admin run-now endpoint, over HTTP ----------------------------------

def test_run_now_requires_admin_and_a_real_tenant(client, worker_tenant):
    unauthed = client.post(f"/v1/admin/tenants/{worker_tenant['slug']}/ingest/run-now")
    assert unauthed.status_code == 401
    missing = client.post("/v1/admin/tenants/does-not-exist/ingest/run-now", headers=ADMIN)
    assert missing.status_code == 404


def test_run_now_runs_synchronously_and_returns_the_real_outcome(client, worker_tenant):
    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        r = client.post(f"/v1/admin/tenants/{worker_tenant['slug']}/ingest/run-now",
                        headers=ADMIN)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "succeeded"
    assert body["detail"]["work_items_ingested"] == 1
    run_id = body["ingest_run_id"]

    with db.tenant_tx(worker_tenant["id"]) as conn:
        row = conn.execute("SELECT status, trigger_kind FROM ingest_run WHERE id=%s",
                           (run_id,)).fetchone()
        alert = conn.execute("SELECT pattern FROM alert WHERE ingest_run_id=%s",
                             (run_id,)).fetchone()
    assert row["status"] == "succeeded"
    assert row["trigger_kind"] == "manual"
    assert alert is not None


def test_run_now_is_invisible_to_the_poller_since_it_never_leaves_it_queued(
        client, worker_tenant):
    """run-now inserts its row already 'running' (app.py), specifically so
    the background poller — which only ever looks for 'queued' rows — can
    never also pick up the same run. Proven directly: call run-now, then
    immediately try to claim a queued run; nothing should be there."""
    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        client.post(f"/v1/admin/tenants/{worker_tenant['slug']}/ingest/run-now", headers=ADMIN)

    assert ingest_worker.claim_and_run_one() is False


# --- poll_forever: the actual background loop -------------------------------

def test_poll_forever_drains_a_queued_run_then_stops_cleanly_on_cancel(client, worker_tenant):
    """Exercises the real asyncio loop `app.py`'s lifespan starts — not just
    the synchronous pieces it calls — with a short interval so this stays
    fast. Plain `asyncio.run()` inside a normal sync test function; no extra
    pytest plugin needed for one bounded async check.
    """
    tid = worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        run_id = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'webhook','queued',%s) RETURNING id",
            (tid, now_iso())).fetchone()["id"]

    async def _drive():
        task = asyncio.create_task(ingest_worker.poll_forever(interval_seconds=0.02))
        finished = False
        for _ in range(200):  # up to ~2s
            await asyncio.sleep(0.01)
            with db.tenant_tx(tid) as conn:
                status_now = conn.execute("SELECT status FROM ingest_run WHERE id=%s",
                                          (run_id,)).fetchone()["status"]
            if status_now == "succeeded":
                finished = True
                break
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return finished

    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        finished = asyncio.run(_drive())

    assert finished, "poll_forever did not pick up and finish the queued run in time"
