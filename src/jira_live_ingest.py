"""
ARGUS — 7.4c-d: Jira live ingestion into a scratch DB.

Turns one Jira Cloud project's credentials into a scratch SQLite database
populated with real sprint/ticket data: `live_jira.fetch_project_bundle()`
(built at 6.9, exists, never wired into a production path before now) does
the fetching; `jira_adapter.ingest_project()` (6.2, fixture-proven) does the
parsing and writing — both UNCHANGED, the exact split D-156/7.4c-b already
established for GitHub (`github_live_ingest.py`) and D-156 §3.1.2 step 4
named for Jira/Linear specifically: "reuse `live_jira.fetch_project_bundle`
... Hand results to `jira_adapter.ingest_project()`, unchanged."

Deliberately does NOT know about tenants, Postgres, or encrypted
credentials — only ever sees a base URL, a project key, an email/API-token
pair, and an open scratch `sqlite3.Connection`, so it can be fully tested
(`verify_jira_live_ingest.py`) with no database and no live network,
matching 6.9/7.4c-b's standard. Decrypting the tenant's stored credential
(`backend.jira_crypto.decrypt_credential`) and everything after this module
runs stay one layer up, in `backend.ingest_worker` (the same split
`github_app.InstallationTokenCache` / `github_live_ingest` already have).

A real, structural gap this module's *caller* must also close, named here
so it is not missed: populating `ticket`/`sprint` rows alone does not make
`sprint_filter.sprint_gate()` pass. `sprint_gate` reads `ticket_link` rows,
and nothing in the ingestion path before this session ever called
`sprint_filter.ingest_ticket_links()` in a live-ingestion run — GitHub-only
ingestion (7.4c-b) never noticed because it never had a ticket to link
against (D-161's finding #1: GitHub-only can only ever SUPPRESS, never
FIRE). `backend.migrate_sqlite.record_phase6_run()` is where that missing
call is added (this session), not here — see that module's docstring.

One project's fetch failing (a real Jira credential problem, a network
blip, a site that has moved) does not abort the run this module is part
of — recorded on `JiraIngestSummary.error` and left non-fatal by the
caller, matching `github_live_ingest`'s "one repo's bad night must not
wedge the rest" isolation one level down: one integration's bad night must
not lose GitHub's already-good data in the same run either.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

import live_jira as LJ
from ingest import create_snapshot
from jira_adapter import (get_or_create_jira_source, get_or_create_project,
                          ingest_project, insert_fetch)


@dataclass
class JiraIngestSummary:
    """What one `ingest_jira_project()` call actually did — the shape a
    future `ingest_run` row's `items_checked`/`error_detail` can be built
    from, the same role `github_live_ingest.IngestSummary` plays for GitHub."""
    sprints: int = 0
    tickets: int = 0
    status_events: int = 0
    fetch_failures: int = 0     # count of individual FetchAttempt rows that outright failed
    error: str | None = None    # set only when the WHOLE project could not be ingested


def ingest_jira_project(conn: sqlite3.Connection, base_url: str, project_key: str,
                        email: str, api_token: str, requested_at: str) -> JiraIngestSummary:
    """Populate `conn` (an open scratch DB, `schema.sql` already applied)
    with one Jira project's live sprint/ticket/changelog data.

    Creates its own `snapshot` row (via the same generic `ingest.
    create_snapshot` GitHub's own path uses — `source`/`project`/`snapshot`
    are source-agnostic tables by design, D-006) under the 'jira' source,
    separate from GitHub's own project/snapshot rows already in the same
    scratch DB. `jira_adapter.ingest_project` needs a `snapshot_id` only to
    attach `evidence_gap` rows for the rare changelog entry with no date
    (schema.sql's own comment on `ticket_status_event`); nothing about
    tickets is otherwise "snapshotted" the way GitHub work items are.
    """
    summary = JiraIngestSummary()
    try:
        bundle, fetches = LJ.fetch_project_bundle(base_url, project_key, email, api_token,
                                                   requested_at)
    except Exception as e:
        # `live_jira._get_with_retry` already swallows an individual HTTP
        # call's failure internally (retries, then gives up and returns a
        # falsy result) — this branch is for something ELSE going wrong: a
        # bug in the assembly logic itself, not a transport failure. Kept
        # for the same reason github_live_ingest.py's per-repo try/except
        # exists: this project's data must never lose whatever the caller
        # already ingested (GitHub's work items) just because this one
        # integration blew up.
        summary.error = f"{type(e).__name__}: {e}"
        return summary

    summary.fetch_failures = sum(1 for f in fetches if f.outcome == "failed")

    # Distinguish "the project itself could never be seen" (every attempt
    # at the one project-metadata call failed — almost always a real
    # credentials or base-URL problem, the live 401 6.9 actually hit
    # against Dirgh's own site) from "the project was seen and is
    # genuinely empty" (a brand-new project, or a project with no active
    # sprint work). `fetch_project_bundle` returns the same *shape* —
    # zero sprints, zero backlog — for both, so this module has to look at
    # the fetch log itself to tell them apart; conflating them would turn
    # a broken credential into a silent, misleadingly successful "0
    # tickets" run instead of a visible failure worth surfacing to whoever
    # is onboarding this tenant (`backend.ingest_worker`, §3.1.4's
    # credential endpoint).
    project_fetches = [f for f in fetches if f.purpose == "project"]
    if project_fetches and not any(f.outcome == "ok" for f in project_fetches):
        last = project_fetches[-1]
        summary.error = (f"could not reach Jira project {project_key!r} at {base_url!r}: "
                         f"{last.error_detail or last.outcome}")
        return summary

    source_id = get_or_create_jira_source(conn, base_url)
    project_id = get_or_create_project(conn, source_id, project_key, bundle.project_name)
    snapshot_id = create_snapshot(conn, source_id, project_id, requested_at, requested_at)

    for fa in fetches:
        insert_fetch(conn, snapshot_id, fa)

    if not bundle.sprints and not bundle.backlog_issues:
        # The project WAS reachable (checked above) — it genuinely has no
        # active-sprint or backlog tickets right now. Recorded as zero
        # counts, not a fabricated error, so a caller distinguishes "ran,
        # found nothing" from "did not run."
        conn.execute("UPDATE snapshot SET is_complete=1 WHERE id=?", (snapshot_id,))
        return summary

    result = ingest_project(conn, snapshot_id, bundle)
    summary.sprints = result["sprints"]
    summary.tickets = result["tickets"]
    summary.status_events = result["status_events"]
    conn.execute("UPDATE snapshot SET is_complete=1 WHERE id=?", (snapshot_id,))
    return summary
