"""
ARGUS — verify_linear_live_ingest.py (7.4c-e)

Same standard `verify_jira_live_ingest.py` held 7.4c-d to: no live call to
a real Linear workspace is possible from this sandbox (`live_linear.py`'s
own docstring — no network path to api.linear.app from either place Claude
can run code), so this proves the NEW pieces built at 7.4c-e —
`live_linear.fetch_team_bundle`'s GraphQL orchestration and
`linear_live_ingest.ingest_linear_team`'s scratch-DB wiring — against
realistic canned JSON shaped from the two independent sources
`live_linear.py`'s module docstring names (a real Linear SDK bug report
and a third-party Go client's generated types), every real HTTP call
mocked out.

One real difference from `verify_jira_live_ingest.py`'s mock shape: Linear
is a SINGLE GraphQL endpoint, so a request can't be routed by URL the way
Jira's REST calls are (one URL per resource). Every query below carries
its own distinct operation name (`ArgusTeamLookup`, `ArgusTeamCycles`, ...)
specifically so `route_by_query` can dispatch on the POST body instead.

Check 3 is the check that matters most, same as Jira's own check 3: not
just "tickets land in the table" but "the frozen Phase 6 engine,
unmodified, produces a real FIRE verdict once a live-shaped GitHub PR and
a live-shaped Linear ticket share one scratch DB and ticket_link
resolution runs."

Check 6 is new relative to Jira's script: Linear's GraphQL API answers a
nonexistent team key with an ordinary 200 OK and zero results (no REST
404 to key off), so "team not found" needs its own proof distinct from
"every call failed" (check 4).
"""
import json
import sqlite3
import sys
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import live_github as LG
import live_linear as LL
import sprint_filter as SF
from github_live_ingest import build_scratch_db
from ingest import get_or_create_source, get_or_create_project, create_snapshot, ingest_work_item
from linear_live_ingest import ingest_linear_team, LinearIngestSummary

checks = 0

API_KEY = "lin_api_fake_key"


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


def route_by_query(rules):
    """Dispatches a mocked POST to Linear's single GraphQL endpoint by
    matching a substring (an operation name, e.g. 'ArgusTeamLookup')
    against the request body's `query` text — the GraphQL analogue of
    verify_jira_live_ingest.py's URL-substring routing."""
    def _fake(req, timeout=None):
        body = json.loads(req.data)
        query_text = body.get("query", "")
        for substr, handler in rules.items():
            if substr in query_text:
                resp = handler(req) if callable(handler) else handler
                if resp.status >= 400:
                    raise _http_error(req, resp.status, resp._body)
                return resp
        raise AssertionError(f"unrouted GraphQL operation: {query_text[:80]!r}")
    return _fake


def _team_found(status=200):
    return FakeHTTPResponse(status, json.dumps({
        "data": {"teams": {"nodes": [{"id": "team-1", "name": "Engineering", "key": "ENG"}]}}
    }).encode())


def _cycles_one_active():
    return FakeHTTPResponse(200, json.dumps({
        "data": {"team": {"cycles": {"nodes": [
            {"id": 601, "number": 12, "name": "Cycle 12",
             "startsAt": "2026-08-18T00:00:00.000Z", "endsAt": "2026-09-01T00:00:00.000Z",
             "completedAt": None},
        ]}}}
    }).encode())


def _cycle_issues_one_in_progress():
    return FakeHTTPResponse(200, json.dumps({
        "data": {"team": {"issues": {"nodes": [
            {"id": "issue-1", "identifier": "ENG-42", "title": "Fix flaky retry budget",
             "createdAt": "2026-08-01T00:00:00.000Z", "updatedAt": "2026-08-19T00:00:00.000Z",
             "state": {"id": "state-started", "name": "In Progress", "type": "started"},
             "assignee": {"id": "user-amy", "name": "Amy"},
             "labels": {"nodes": []}, "parent": None},
        ], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}
    }).encode())


def _backlog_empty():
    return FakeHTTPResponse(200, json.dumps({
        "data": {"team": {"issues": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}
    }).encode())


def _history_one_transition():
    return FakeHTTPResponse(200, json.dumps({
        "data": {"issue": {"history": {"nodes": [
            {"id": "h1", "createdAt": "2026-08-05T00:00:00.000Z",
             "fromState": {"name": "Todo", "type": "unstarted"},
             "toState": {"name": "In Progress", "type": "started"}},
            # A non-status edit (title change) — toState null. Must be
            # filtered out, not turned into a bogus status event. This is
            # exactly the shape live_linear.py's module docstring names as
            # finding #1 confirmed via linear/linear#91 and the Go client's
            # IssueHistoryEntry struct (fromTitle/toTitle alongside
            # fromState/toState in the same connection).
            {"id": "h2", "createdAt": "2026-08-06T00:00:00.000Z",
             "fromState": None, "toState": None,
             "fromTitle": "Fix retry", "toTitle": "Fix flaky retry budget"},
        ], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}
    }).encode())


def _eng42_rules():
    return {
        "ArgusTeamLookup": _team_found(),
        "ArgusTeamCycles": _cycles_one_active(),
        "ArgusCycleIssues": _cycle_issues_one_in_progress(),
        "ArgusBacklogIssues": _backlog_empty(),
        "ArgusIssueHistory": _history_one_transition(),
    }


def main():
    global checks

    # --- check 1: fetch_team_bundle assembles one cycle + one ticket +
    # one real transition (with the fake non-status history node dropped) ---
    with mock.patch("urllib.request.urlopen", side_effect=route_by_query(_eng42_rules())):
        bundle, fetches, team_found = LL.fetch_team_bundle("ENG", API_KEY, "2026-08-20T09:00:00Z")
    assert team_found is True
    assert bundle.team_name == "Engineering", bundle.team_name
    assert len(bundle.cycles) == 1 and bundle.cycles[0]["id"] == 601
    assert bundle.cycle_issues["601"][0]["identifier"] == "ENG-42"
    assert bundle.cycle_issues["601"][0]["labels"] == [], bundle.cycle_issues["601"][0]["labels"]
    assert bundle.backlog_issues == []
    transitions = bundle.histories["ENG-42"]
    assert len(transitions) == 1, transitions  # the toState:null node must be dropped
    assert transitions[0].to_status == "In Progress"
    assert transitions[0].to_status_type == "started"
    assert transitions[0].from_status == "Todo"
    assert all(f.outcome in ("ok",) for f in fetches), [f.outcome for f in fetches]
    checks += 1
    print("check 1 fetch_team_bundle assembles one cycle, one ticket, and one real transition "
          "from live-shaped GraphQL JSON — dropping the non-status history node")

    # --- check 2: ingest_linear_team writes real ticket/cycle rows ---
    conn = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_query(_eng42_rules())):
        summary = ingest_linear_team(conn, "ENG", API_KEY, "2026-08-20T09:00:00Z")
    assert isinstance(summary, LinearIngestSummary)
    assert summary.error is None, summary.error
    assert summary.cycles == 1, summary.cycles
    assert summary.tickets == 1, summary.tickets
    assert summary.status_events == 1, summary.status_events
    ticket = conn.execute(
        "SELECT source_key, status_category, source_status FROM ticket").fetchone()
    assert ticket["source_key"] == "ENG-42"
    assert ticket["status_category"] == "in_progress", ticket["status_category"]
    cycle = conn.execute("SELECT name, state FROM sprint").fetchone()
    assert cycle["name"] == "Cycle 12" and cycle["state"] == "active", cycle["state"]
    checks += 1
    print("check 2 ingest_linear_team writes real ticket/cycle rows via the unchanged "
          "linear_adapter.ingest_team")

    # --- check 3: THE proof — a live-shaped GitHub PR + a live-shaped
    # Linear ticket in the SAME scratch DB, ticket-link resolution run, and
    # the frozen sprint_filter engine (unmodified) produces a real FIRE. ---
    gh_source_id = get_or_create_source(conn)
    gh_project_id = get_or_create_project(conn, gh_source_id, "pilotco", "widgets")
    gh_snapshot_id = create_snapshot(conn, gh_source_id, gh_project_id,
                                     "2026-08-20T09:00:00Z", "2026-08-20T09:00:00Z")

    # Same P2-review-ghosted shape verify_jira_live_ingest.py's own check 3
    # uses: requested day 1, no response, "now" is day 19 — 18 days past
    # the 48h threshold. Title carries the ticket key for pr_title_key
    # resolution.
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

    def _route_gh(req, timeout=None):
        for substr, resp in gh_rules.items():
            if substr in req.full_url:
                return resp
        raise AssertionError(f"unrouted URL: {req.full_url}")

    with mock.patch("urllib.request.urlopen", side_effect=_route_gh):
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
    print("check 3 a live-shaped GitHub PR + a live-shaped active-cycle Linear ticket, "
          "linked and gated, produces a real FIRE")

    # --- check 4: every call failing (network blip / bad API key) is
    # recorded as a real, visible error — not silently read as "empty
    # team, zero tickets" ---
    conn2 = build_scratch_db()
    with mock.patch("urllib.request.urlopen",
                    side_effect=RuntimeError("simulated DNS failure")), \
         mock.patch("time.sleep"):
        summary2 = ingest_linear_team(conn2, "ENG", API_KEY, "2026-08-20T09:00:00Z")
    assert summary2.error is not None and "could not reach" in summary2.error, summary2.error
    assert summary2.tickets == 0 and summary2.cycles == 0
    checks += 1
    print("check 4 every call failing is recorded as a real, distinguishable 'could not "
          "reach' error, not misread as an empty-but-real team")

    # --- check 5: a real, empty-but-reachable team records zero counts,
    # not a fabricated error (a bad key vs. "nothing here yet" must stay
    # distinguishable) ---
    empty_rules = dict(_eng42_rules())
    empty_rules["ArgusTeamCycles"] = FakeHTTPResponse(200, json.dumps(
        {"data": {"team": {"cycles": {"nodes": []}}}}).encode())
    conn3 = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_query(empty_rules)):
        summary3 = ingest_linear_team(conn3, "ENG", API_KEY, "2026-08-20T09:00:00Z")
    assert summary3.error is None, summary3.error
    assert summary3.cycles == 0 and summary3.tickets == 0
    snap = conn3.execute("SELECT is_complete FROM snapshot").fetchone()
    assert snap["is_complete"] == 1
    checks += 1
    print("check 5 a reachable-but-empty team records zero counts, not a fabricated error")

    # --- check 6 (new relative to Jira): a NONEXISTENT team key — the
    # GraphQL call succeeds (HTTP 200, real 'teams' connection), it simply
    # matches zero teams. No REST 404 exists to key off, unlike Jira's
    # project lookup — this is exactly the gap live_linear.fetch_team_
    # bundle's 3-tuple return (bundle, fetches, team_found) exists to close
    # honestly, named in this module's own docstring. ---
    not_found_rules = dict(_eng42_rules())
    not_found_rules["ArgusTeamLookup"] = FakeHTTPResponse(
        200, json.dumps({"data": {"teams": {"nodes": []}}}).encode())
    conn4 = build_scratch_db()
    with mock.patch("urllib.request.urlopen", side_effect=route_by_query(not_found_rules)):
        summary4 = ingest_linear_team(conn4, "NOPE", API_KEY, "2026-08-20T09:00:00Z")
    assert summary4.error is not None, "a nonexistent team key must be a visible error"
    assert "no Linear team found" in summary4.error, summary4.error
    assert "could not reach" not in summary4.error, (
        "a genuinely reachable-but-nonexistent team must not be misreported as unreachable: "
        + summary4.error)
    assert summary4.cycles == 0 and summary4.tickets == 0
    checks += 1
    print("check 6 a nonexistent team key (HTTP 200, zero results — Linear has no REST-style "
          "404) is reported as 'team not found', correctly distinguished from 'could not reach'")

    print(f"\nAll {checks} fixture-based checks passed.")
    print("NOT proven: a real call to a Linear workspace. Still blocked from both places "
          "Claude can run code today — see live_linear.py's module docstring.")


if __name__ == "__main__":
    main()
