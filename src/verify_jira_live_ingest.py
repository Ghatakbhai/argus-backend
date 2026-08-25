"""
ARGUS — verify_jira_live_ingest.py (7.4c-d)

Same standard `verify_github_live_ingest.py` held 7.4c-b to: no live call to
a real Jira Cloud site is possible from this sandbox (`live_jira.py`'s own
docstring — the one live auth probe ever made from here, at 6.9, returned
HTTP 401 on a real credential problem, not a network block), so this proves
the NEW pieces built at 7.4c-d — `live_jira.fetch_project_bundle`'s HTTP
orchestration and `jira_live_ingest.ingest_jira_project`'s scratch-DB
wiring — against realistic canned JSON shaped like Jira's own documented
REST/Agile API responses, every real HTTP call mocked out.

Check 3 is the check that actually matters for this build step and for the
user's own ask: not just "tickets land in the table" but "the frozen Phase 6
engine, unmodified, produces a real FIRE verdict once a live-shaped GitHub
PR and a live-shaped Jira ticket share one scratch DB and ticket_link
resolution runs" — the concrete, end-to-end proof that live ingestion can
legitimately fire, not just suppress.
"""
import sqlite3
import sys
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live_github as LG
import live_jira as LJ
import sprint_filter as SF
from github_live_ingest import build_scratch_db
from ingest import get_or_create_source, get_or_create_project, create_snapshot, ingest_work_item
from jira_live_ingest import ingest_jira_project, JiraIngestSummary

checks = 0

BASE = "https://acme.atlassian.net"


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
    def _fake(req, timeout=None):
        for substr, handler in rules.items():
            if substr in req.full_url:
                resp = handler(req) if callable(handler) else handler
                if resp.status >= 400:
                    raise _http_error(req, resp.status, resp._body)
                return resp
        raise AssertionError(f"unrouted URL: {req.full_url}")
    return _fake


def _eng42_rules():
    """One board (id 10), one active sprint (id 501, "Sprint 12") holding
    one in-progress story ENG-42, empty backlog. Field shapes checked
    against the same Atlassian OpenAPI schema D-111/6.9 already verified
    against — statusCategory.key='indeterminate' + status name 'In
    Progress' is exactly `jira_adapter.propose_status_category`'s
    'in_progress' case.
    """
    project = b'{"key":"ENG","name":"Engineering"}'
    boards = b'{"values":[{"id":10,"name":"ENG board"}]}'
    sprints = (b'{"values":[{"id":501,"name":"Sprint 12","state":"active",'
              b'"startDate":"2026-08-18T00:00:00.000Z","endDate":"2026-09-01T00:00:00.000Z"}]}')
    sprint_issues = (
        b'{"issues":[{"key":"ENG-42","fields":{"summary":"Fix flaky retry budget",'
        b'"issuetype":{"name":"Story","subtask":false},'
        b'"status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},'
        b'"assignee":{"accountId":"acc-amy","displayName":"Amy","accountType":"atlassian"},'
        b'"created":"2026-08-01T00:00:00.000+0000","updated":"2026-08-19T00:00:00.000+0000"}}]}'
    )
    backlog = b'{"issues":[]}'
    changelog = b'{"histories":[]}'
    return {
        "rest/api/3/project/ENG": FakeHTTPResponse(200, project),
        "rest/agile/1.0/board?projectKeyOrId=ENG": FakeHTTPResponse(200, boards),
        "rest/agile/1.0/board/10/sprint": FakeHTTPResponse(200, sprints),
        "rest/agile/1.0/sprint/501/issue": FakeHTTPResponse(200, sprint_issues),
        "rest/agile/1.0/board/10/backlog": FakeHTTPResponse(200, backlog),
        "rest/api/3/issue/ENG-42/changelog": FakeHTTPResponse(200, changelog),
    }


def main():
    global checks

    # --- check 1: fetch_project_bundle assembles one sprint + one ticket ---
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(_eng42_rules())):
        bundle, fetches = LJ.fetch_project_bundle(BASE, "ENG", "a@b.com", "tok",
                                                   "2026-08-20T09:00:00Z")
    assert bundle.project_name == "Engineering", bundle.project_name
    assert len(bundle.sprints) == 1 and bundle.sprints[0]["id"] == 501
    assert bundle.sprint_issues["501"][0]["key"] == "ENG-42"
    assert bundle.backlog_issues == []
    assert "ENG-42" in bundle.changelogs
    assert all(f.outcome == "ok" for f in fetches), [f.outcome for f in fetches]
    checks += 1
    print("check 1 fetch_project_bundle assembles one active sprint and one ticket from live-shaped JSON")

    # --- check 2: ingest_jira_project writes real ticket/sprint rows ---
    conn = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(_eng42_rules())):
        summary = ingest_jira_project(conn, BASE, "ENG", "a@b.com", "tok",
                                      "2026-08-20T09:00:00Z")
    assert isinstance(summary, JiraIngestSummary)
    assert summary.error is None, summary.error
    assert summary.sprints == 1, summary.sprints
    assert summary.tickets == 1, summary.tickets
    ticket = conn.execute(
        "SELECT source_key, status_category, source_status FROM ticket").fetchone()
    assert ticket["source_key"] == "ENG-42"
    assert ticket["status_category"] == "in_progress", ticket["status_category"]
    sprint = conn.execute("SELECT name, state FROM sprint").fetchone()
    assert sprint["name"] == "Sprint 12" and sprint["state"] == "active"
    checks += 1
    print("check 2 ingest_jira_project writes real ticket/sprint rows via the unchanged jira_adapter.ingest_project")

    # --- check 3: THE proof — a live-shaped GitHub PR + a live-shaped Jira
    # ticket in the SAME scratch DB, ticket-link resolution run, and the
    # frozen sprint_filter engine (unmodified) produces a real FIRE. ---
    gh_source_id = get_or_create_source(conn)
    gh_project_id = get_or_create_project(conn, gh_source_id, "pilotco", "widgets")
    gh_snapshot_id = create_snapshot(conn, gh_source_id, gh_project_id,
                                     "2026-08-20T09:00:00Z", "2026-08-20T09:00:00Z")

    # Title deliberately carries the ticket key ("[ENG-42] ...") — the
    # pr_title_key link method sprint_filter.py's own priority ordering
    # ranks weaker than branch_name/smart_commit but is still enough to
    # resolve a real link (METHOD_CONFIDENCE['pr_title_key'] = 'medium').
    # Same review-request shape §4.2/D-161's own worked P2 example used:
    # requested day 1, no response, "now" is day 19 — 18 days past the
    # 48h threshold.
    issue_json = (
        b'{"number":42,"title":"[ENG-42] Fix flaky retry budget",'
        b'"user":{"login":"amy"},"state":"open","created_at":"2026-08-01T00:00:00Z",'
        b'"labels":[],"html_url":"https://github.com/pilotco/widgets/pull/42",'
        b'"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
    )
    pr_json = b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}'
    timeline_json = (
        b'[{"event":"review_requested","actor":{"login":"amy"},'
        b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]'
    )
    gh_rules = {
        "pilotco/widgets/issues/42/timeline": FakeHTTPResponse(200, timeline_json),
        "pilotco/widgets/issues/42/comments": FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42/reviews": FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42": FakeHTTPResponse(200, pr_json),
        "pilotco/widgets/issues/42": FakeHTTPResponse(200, issue_json),
    }
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(gh_rules)):
        gh_bundle = LG.fetch_work_item("pilotco", "widgets", 42, "fake-token",
                                       "2026-08-20T09:00:00Z")
    wid = ingest_work_item(conn, gh_snapshot_id, gh_project_id, gh_source_id, gh_bundle)
    assert wid is not None, "GitHub work item failed to ingest"

    link_sources = [SF.link_sources_from_db(conn, wid)]
    link_stats = SF.ingest_ticket_links(conn, link_sources, "2026-08-20T09:00:00Z")
    assert link_stats["inserted"] == 1, link_stats

    results = SF.run_pipeline(conn, work_item_ids=[wid])
    assert len(results) == 1
    result = results[0]
    assert result.outcome == "FIRE", (result.outcome, result.reason, result.evidence)
    assert result.pattern == "P2-review-ghosted", result.pattern
    checks += 1
    print("check 3 a live-shaped GitHub PR + a live-shaped active-sprint Jira ticket, linked and gated, produces a real FIRE")

    # --- check 4: every call failing (bad credentials / unreachable site)
    # is recorded as a real, visible error — not silently read as "empty
    # project, zero tickets" (time.sleep mocked out; live_jira's own retry
    # backoff is exercised elsewhere, not what this check is about) ---
    conn2 = build_scratch_db()
    with mock.patch("urllib.request.urlopen",
                    side_effect=RuntimeError("simulated DNS failure")), \
         mock.patch("time.sleep"):
        summary2 = ingest_jira_project(conn2, BASE, "ENG", "a@b.com", "tok",
                                       "2026-08-20T09:00:00Z")
    assert summary2.error is not None and "simulated DNS failure" in summary2.error, summary2.error
    assert summary2.tickets == 0 and summary2.sprints == 0
    checks += 1
    print("check 4 every call failing is recorded as a real error, not misread as an empty project")

    # --- check 5: a real, empty-but-reachable project records zero counts,
    # not a fabricated error (bad credentials vs. "nothing here yet" must
    # stay distinguishable) ---
    empty_rules = dict(_eng42_rules())
    empty_rules["rest/agile/1.0/sprint/501/issue"] = FakeHTTPResponse(200, b'{"issues":[]}')
    empty_rules["rest/agile/1.0/board/10/sprint"] = FakeHTTPResponse(200, b'{"values":[]}')
    conn3 = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_url(empty_rules)):
        summary3 = ingest_jira_project(conn3, BASE, "ENG", "a@b.com", "tok",
                                       "2026-08-20T09:00:00Z")
    assert summary3.error is None, summary3.error
    assert summary3.sprints == 0 and summary3.tickets == 0
    snap = conn3.execute("SELECT is_complete FROM snapshot").fetchone()
    assert snap["is_complete"] == 1
    checks += 1
    print("check 5 a reachable-but-empty project records zero counts, not a fabricated error")

    print(f"\nAll {checks} fixture-based checks passed.")
    print("NOT proven: a real call to a Jira Cloud site. Still blocked from both places Claude can "
          "run code today — see live_jira.py's module docstring.")


if __name__ == "__main__":
    main()
