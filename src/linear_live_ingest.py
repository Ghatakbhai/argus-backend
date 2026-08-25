"""
ARGUS — 7.4c-e: Linear live ingestion into a scratch DB.

Turns one Linear team's credentials into a scratch SQLite database
populated with real cycle/ticket data: `live_linear.fetch_team_bundle`
(new, this session) does the fetching; `linear_adapter.ingest_team` (6.3,
fixture-proven) does the parsing and writing — both UNCHANGED, the exact
split D-156/7.4c-b/7.4c-d already established for GitHub/Jira and §3.1.2
step 4 named for Linear specifically: "build `live_linear.py` from
scratch... Hand results to `jira_adapter.ingest_project()` /
`linear_adapter.ingest_team()`, unchanged."

Deliberately does NOT know about tenants, Postgres, or encrypted
credentials — only ever sees a team key, an API key, and an open scratch
`sqlite3.Connection`, matching `jira_live_ingest.py`'s own scope exactly.
Decrypting the tenant's stored credential (`backend.linear_crypto.
decrypt_credential`) and everything after this module runs stay one layer
up, in `backend.ingest_worker`.

One team's fetch failing (a bad API key, a network blip, a team that no
longer exists) does not abort the run this module is part of — recorded on
`LinearIngestSummary.error` and left non-fatal by the caller, the same
"one integration's bad night must not lose GitHub's/Jira's already-good
data" isolation `jira_live_ingest.py`'s docstring names.

**Unlike Jira, Linear has no REST-style 404 to distinguish "team doesn't
exist" from "team exists but is genuinely empty."** `live_linear.
fetch_team_bundle`'s own 3-tuple return (`bundle, fetches, team_found`)
carries that distinction explicitly — see its docstring — and this module
reads `team_found` directly rather than reconstructing the answer from the
fetch log the way `jira_live_ingest.ingest_jira_project` does for Jira's
`project_fetches` check.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

import live_linear as LL
from ingest import create_snapshot
from linear_adapter import get_or_create_linear_source, get_or_create_project, ingest_team


@dataclass
class LinearIngestSummary:
    """Mirrors `jira_live_ingest.JiraIngestSummary`'s role exactly — what
    one `ingest_linear_team()` call actually did."""
    cycles: int = 0
    tickets: int = 0
    status_events: int = 0
    fetch_failures: int = 0
    error: str | None = None


def ingest_linear_team(conn: sqlite3.Connection, team_key: str, api_key: str,
                        requested_at: str, base_url: str = "https://api.linear.app"
                        ) -> LinearIngestSummary:
    """Populate `conn` (an open scratch DB, `schema.sql` already applied)
    with one Linear team's live cycle/ticket/status-history data.

    Creates its own `snapshot` row (via the same generic `ingest.
    create_snapshot` GitHub's and Jira's own paths use — `source`/
    `project`/`snapshot` are source-agnostic tables by design, D-006) under
    the 'linear' source, separate from GitHub's/Jira's own project/snapshot
    rows already in the same scratch DB.
    """
    summary = LinearIngestSummary()
    try:
        bundle, fetches, team_found = LL.fetch_team_bundle(team_key, api_key, requested_at,
                                                             base_url)
    except Exception as e:
        # Mirrors jira_live_ingest.py's own outer try/except: a bug in THIS
        # module's assembly logic, not a transport failure (those are
        # already swallowed and logged inside live_linear._post_with_retry).
        summary.error = f"{type(e).__name__}: {e}"
        return summary

    summary.fetch_failures = sum(1 for f in fetches if f.outcome == "failed")

    if not team_found:
        team_fetches = [f for f in fetches if f.purpose == "team"]
        if team_fetches and any(f.outcome == "ok" for f in team_fetches):
            # The lookup call itself succeeded — Linear was reachable and
            # answered — it simply has no team with this key. A real,
            # visible configuration problem (a typo'd team key at
            # onboarding), not a transport issue.
            summary.error = f"no Linear team found for key {team_key!r} at {base_url!r}"
        else:
            last = team_fetches[-1] if team_fetches else None
            detail = last.error_detail if last else "no response"
            summary.error = f"could not reach Linear team {team_key!r} at {base_url!r}: {detail}"
        return summary

    source_id = get_or_create_linear_source(conn, base_url)
    project_id = get_or_create_project(conn, source_id, team_key, bundle.team_name)
    snapshot_id = create_snapshot(conn, source_id, project_id, requested_at, requested_at)

    # live_linear.py logs every fetch under LinearFetchAttempt, the same
    # dataclass linear_adapter.insert_fetch already knows how to write —
    # reused unchanged here, matching jira_live_ingest.py's identical line.
    from linear_adapter import insert_fetch
    for fa in fetches:
        insert_fetch(conn, snapshot_id, fa)

    if not bundle.cycles and not bundle.backlog_issues:
        # Reachable AND a real team, but genuinely no active-cycle or
        # backlog tickets right now — recorded as zero counts, not a
        # fabricated error, matching jira_live_ingest.py's identical case.
        conn.execute("UPDATE snapshot SET is_complete=1 WHERE id=?", (snapshot_id,))
        return summary

    result = ingest_team(conn, snapshot_id, bundle)
    summary.cycles = result["cycles"]
    summary.tickets = result["tickets"]
    summary.status_events = result["status_events"]
    conn.execute("UPDATE snapshot SET is_complete=1 WHERE id=?", (snapshot_id,))
    return summary
