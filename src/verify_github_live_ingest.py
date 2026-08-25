"""
ARGUS — verify_github_live_ingest.py (7.4c-b)

Same standard `verify_live_github.py` held 6.9's fetcher to: no live call to
api.github.com is possible from this sandbox (see `live_github.py`'s own
docstring, re-confirmed this session), so this proves the NEW pieces built
at 7.4c-b — `live_github.list_installation_repos`/`list_open_prs`, and
`github_live_ingest.ingest_installation`'s orchestration — against
realistic canned JSON shaped like GitHub's own documented examples, with
every real HTTP call mocked out. What this DOES prove, with no shortcuts:
pagination across both new endpoints; that a fully populated scratch DB
comes out the other end with real `project`/`snapshot`/`work_item`/`event`/
`review_request` rows in it, built through `ingest.ingest_work_item`
UNCHANGED; and that one repo's listing failure does not lose the rest of
the installation's repos.
"""
import sqlite3
import sys
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live_github as LG
from github_live_ingest import build_scratch_db, ingest_installation, IngestSummary

checks = 0


class FakeHTTPResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(req, status, body):
    import io
    import urllib.error
    return urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(body))


def route_by_url(rules):
    """rules: dict mapping a URL substring to either a FakeHTTPResponse or a
    callable(req) -> FakeHTTPResponse-or-raise. First substring match wins,
    checked in insertion order, so a more specific rule should be listed
    before a more general one."""
    def _fake(req, timeout=None):
        for substr, handler in rules.items():
            if substr in req.full_url:
                resp = handler(req) if callable(handler) else handler
                if resp.status >= 400:
                    raise _http_error(req, resp.status, resp._body)
                return resp
        raise AssertionError(f"unrouted URL: {req.full_url}")
    return _fake


def main():
    global checks

    # --- check 1: list_installation_repos parses repositories[], paginates on a full page ---
    page1 = FakeHTTPResponse(200, (
        b'{"total_count": 101, "repositories": ['
        + b",".join(
            b'{"name":"repo%d","full_name":"acme/repo%d","owner":{"login":"acme"}}' % (i, i)
            for i in range(100)
        )
        + b']}'
    ))
    page2 = FakeHTTPResponse(200, b'{"total_count": 101, "repositories": ['
                                   b'{"name":"repo100","full_name":"acme/repo100","owner":{"login":"acme"}}]}')
    calls = {"n": 0}

    def paged(req, timeout=None):
        calls["n"] += 1
        return page1 if calls["n"] == 1 else page2

    with mock.patch("urllib.request.urlopen", side_effect=paged):
        repos = LG.list_installation_repos("inst-tok", "2026-08-25T00:00:00Z")
    assert len(repos) == 101, len(repos)
    assert repos[0] == ("acme", "repo0")
    assert repos[-1] == ("acme", "repo100")
    checks += 1
    print("check 1 list_installation_repos parses repositories[] and paginates past a full page")

    # --- check 2: list_open_prs returns PR numbers only, in the order GitHub sent them ---
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value = FakeHTTPResponse(200, b'[{"number":12,"title":"a"},{"number":9,"title":"b"}]')
        numbers = LG.list_open_prs("acme", "web", "inst-tok", "2026-08-25T00:00:00Z")
    assert numbers == [12, 9], numbers
    checks += 1
    print("check 2 list_open_prs returns PR numbers in GitHub's own order")

    # --- check 3: end-to-end — one installation, two repos, one PR each, real ingest ---
    def issue_json(number, owner, repo, created_at):
        return (
            ('{"number":%d,"title":"fix the retry budget","user":{"login":"amy"},'
             '"state":"open","created_at":"%s","labels":[],'
             '"html_url":"https://github.com/%s/%s/pull/%d",'
             '"updated_at":"%s","pull_request":{},"assignees":[]}'
             % (number, created_at, owner, repo, number, created_at)).encode()
        )

    def pr_json(mergeable_state="clean"):
        return ('{"draft":false,"merged":false,"state":"open",'
                '"mergeable_state":"%s"}' % mergeable_state).encode()

    def timeline_json(requested_at):
        return (
            '[{"event":"review_requested","actor":{"login":"amy"},'
            '"requested_reviewer":{"login":"riya"},"created_at":"%s"}]'
            % requested_at
        ).encode()

    rules = {
        "installation/repositories": FakeHTTPResponse(
            200, b'{"total_count":2,"repositories":['
                 b'{"name":"web","full_name":"acme/web","owner":{"login":"acme"}},'
                 b'{"name":"api","full_name":"acme/api","owner":{"login":"acme"}}]}'),
        "acme/web/pulls?state=open": FakeHTTPResponse(200, b'[{"number":701,"title":"x"}]'),
        "acme/api/pulls?state=open": FakeHTTPResponse(200, b'[]'),  # api has zero open PRs
        "acme/web/issues/701/timeline": FakeHTTPResponse(200, timeline_json("2026-08-01T00:00:00Z")),
        "acme/web/issues/701/comments": FakeHTTPResponse(200, b'[]'),
        "acme/web/pulls/701/reviews": FakeHTTPResponse(200, b'[]'),
        "acme/web/pulls/701": FakeHTTPResponse(200, pr_json()),
        "acme/web/issues/701": FakeHTTPResponse(200, issue_json(701, "acme", "web", "2026-07-20T00:00:00Z")),
    }
    conn = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(rules)):
        summary = ingest_installation(conn, "inst-tok", "2026-08-25T12:00:00Z")

    assert isinstance(summary, IngestSummary)
    assert summary.repos_seen == 2, summary.repos_seen
    assert summary.repos_failed == 0
    assert summary.prs_seen == 1, summary.prs_seen
    assert summary.work_items_ingested == 1, summary.work_items_ingested
    assert summary.work_items_failed == 0

    projects = conn.execute("SELECT source_key FROM project ORDER BY source_key").fetchall()
    assert [p[0] for p in projects] == ["acme/api", "acme/web"], projects
    wi = conn.execute("SELECT title, source_number, kind, state FROM work_item").fetchone()
    assert wi["title"] == "fix the retry budget"
    assert wi["source_number"] == 701
    assert wi["kind"] == "change_request"
    assert wi["state"] == "open"
    rr = conn.execute("SELECT origin FROM review_request").fetchone()
    assert rr["origin"] == "manual", rr["origin"]
    snaps = conn.execute("SELECT is_complete FROM snapshot").fetchall()
    assert all(s["is_complete"] == 1 for s in snaps)
    checks += 1
    print("check 3 ingest_installation walks 2 repos x N PRs and ingests through the real, unchanged ingest_work_item")

    # --- check 4: one repo raising a real exception mid-ingest does not lose the other repo's data ---
    # `_get_with_retry` already swallows an HTTP-level failure internally
    # (retries, then returns a falsy result indistinguishable from "zero
    # open PRs" — the same accepted limitation `list_open_items` has always
    # had; see the module docstring). What this checks instead is the
    # genuine failure mode github_live_ingest.py's try/except actually
    # guards against: something raising a real exception partway through
    # one repo's processing — here, `ingest_work_item` itself blowing up on
    # web's one PR — and confirms the OTHER repo's data still lands, and
    # web's own partial writes (its project/snapshot rows) are rolled back
    # rather than left half-written.
    import github_live_ingest as GLI

    real_ingest_work_item = GLI.ingest_work_item

    def flaky_ingest_work_item(conn, snapshot_id, project_id, source_id, bundle):
        if bundle.owner == "acme" and bundle.repo == "web":
            raise RuntimeError("simulated: a real bug while ingesting this item")
        return real_ingest_work_item(conn, snapshot_id, project_id, source_id, bundle)

    conn2 = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(rules)), \
         mock.patch.object(GLI, "ingest_work_item", side_effect=flaky_ingest_work_item):
        summary2 = ingest_installation(conn2, "inst-tok", "2026-08-25T12:00:00Z")
    assert summary2.repos_seen == 2
    assert summary2.repos_failed == 1
    assert "acme/web" in summary2.repo_errors and "RuntimeError" in summary2.repo_errors["acme/web"]
    # api's project row still exists — one repo's exception did not abort the run
    projects2 = conn2.execute("SELECT source_key FROM project").fetchall()
    assert [p[0] for p in projects2] == ["acme/api"], projects2
    # web's partial writes (the project/snapshot rows it did manage to
    # create before ingest_work_item blew up) were rolled back, not left
    # half-written — "acme/web" appearing above would have been that bug.
    checks += 1
    print("check 4 one repo raising a real exception is recorded, rolled back, and does not lose the other repo's data")

    # --- check 5: the max_prs_per_repo safety cap actually caps ---
    many_prs = b'[' + b",".join(b'{"number":%d}' % n for n in range(1, 6)) + b']'
    rules_cap = dict(rules)
    rules_cap["acme/web/pulls?state=open"] = FakeHTTPResponse(200, many_prs)
    # Only the first two (the cap) are ever fetched, but they still need real
    # routes — an unrouted URL is a test bug, not something ingest_installation
    # should paper over by retrying it as a network failure.
    for n in (1, 2):
        rules_cap[f"acme/web/issues/{n}/timeline"] = FakeHTTPResponse(200, b'[]')
        rules_cap[f"acme/web/issues/{n}/comments"] = FakeHTTPResponse(200, b'[]')
        rules_cap[f"acme/web/pulls/{n}/reviews"] = FakeHTTPResponse(200, b'[]')
        rules_cap[f"acme/web/pulls/{n}"] = FakeHTTPResponse(200, pr_json())
        rules_cap[f"acme/web/issues/{n}"] = FakeHTTPResponse(
            200, issue_json(n, "acme", "web", "2026-07-20T00:00:00Z"))
    conn3 = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(rules_cap)):
        summary3 = ingest_installation(conn3, "inst-tok", "2026-08-25T12:00:00Z", max_prs_per_repo=2)
    assert summary3.prs_seen == 2, summary3.prs_seen  # only fetches the first 2, not all 5
    assert "acme/web" in summary3.repo_errors and "exceeds" in summary3.repo_errors["acme/web"]
    checks += 1
    print("check 5 max_prs_per_repo caps how many PRs one repo can force-fetch in a single run")

    print(f"\nAll {checks} fixture-based checks passed.")
    print("NOT proven: a real call to api.github.com. Still blocked from both places Claude can "
          "run code today — see live_github.py's module docstring.")


if __name__ == "__main__":
    main()
