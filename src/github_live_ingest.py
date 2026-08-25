"""
ARGUS — 7.4c-b: GitHub live ingestion into a scratch DB.

Turns one GitHub App installation access token into a fully populated
scratch SQLite database: every repository the installation can see, every
currently-open pull request in each of those repos, fetched and ingested
through the exact same `ingest.ingest_work_item()` path 2.2's Tavily-fixture
tests and 6.9's `live_github.py` already prove. This module owns exactly
the "which repos, which PRs, hand each to fetch_work_item" orchestration
layer D-156/`docs/PHASE7_5_OPERATIONAL_CHECKLIST.md` §3.1.2 step 4 named —
step b of the six-step build order at §3.1.5.

Deliberately does NOT know about tenants, Postgres, or installation ids —
only ever sees a bearer token and a scratch `sqlite3.Connection`, so it can
be fully tested (`verify_github_live_ingest.py`) with no database and no
live network, matching 6.9/7.4c-a's standard. Minting the token itself
(`backend.github_app.InstallationTokenCache.get(installation_id)`) and
everything after this module runs (`migrate_sqlite.migrate()` then
`record_phase6_run()`, both already accept an open connection as of
7.4c-a/D-160) stay one layer up, in whatever calls this — the in-process
poller, `backend.ingest_worker` (built at 7.4c-c/D-162).

One repository's PR-listing failure (rate limit exhausted mid-run, the repo
was deleted since the installation last saw it, ...) does not abort the
rest of the installation — recorded on `IngestSummary.repo_errors` and
skipped, matching D-156 step 6's "one tenant's bad night must never wedge
the poller for the other fourteen" rule one level down: one repo's bad
night must not lose the other repos in the same run either. A single work
item's own fetch failing is already handled beneath this, by
`ingest.ingest_work_item` returning None and recording a `fetch_failed`
evidence gap (D-072's precedent) — this module just counts that outcome,
it does not treat it as fatal either.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field

import live_github as LG
from ingest import (
    get_or_create_source, get_or_create_project, create_snapshot,
    ingest_work_item,
)

_SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


@dataclass
class IngestSummary:
    """What one `ingest_installation()` call actually did — the shape a
    future `ingest_run` row (`items_checked`, and the makings of
    `error_detail` on partial failure) will be built from at 7.4c-c."""
    repos_seen: int = 0
    repos_failed: int = 0
    prs_seen: int = 0
    work_items_ingested: int = 0
    work_items_failed: int = 0
    repo_errors: dict[str, str] = field(default_factory=dict)  # "owner/repo" -> detail


def build_scratch_db() -> sqlite3.Connection:
    """A fresh, empty, in-memory SQLite database with `schema.sql` already
    applied — the exact per-run scratch shape §3.1.1 describes ("a fresh,
    empty, in-memory SQLite database per ingest run"). Nothing about the
    rest of this module requires `:memory:` specifically; a caller that
    wants a temp *file* instead (e.g. to hand to `migrate_sqlite`'s
    original file-path calling convention) can open one the same way and
    skip this helper.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(_SCHEMA_PATH) as f:
        conn.executescript(f.read())
    return conn


def ingest_installation(conn: sqlite3.Connection, token: str, requested_at: str,
                        max_repo_pages: int = 10, max_pr_pages: int = 10,
                        max_prs_per_repo: int = 200) -> IngestSummary:
    """Populate `conn` (an open scratch DB, `schema.sql` already applied)
    with every open PR from every repo this installation token can see.

    One `source` row total (`get_or_create_source` — 'github', same as
    every other GitHub path in this codebase), one `project`/`snapshot`
    pair per repo — the same shape `get_or_create_project`/`create_snapshot`
    already produce for the Tavily and 6.9 paths, nothing new there. Every
    PR is handed to `ingest.ingest_work_item` completely unchanged, the
    same function this whole project has trusted since Phase 2.2.

    `max_prs_per_repo` is a safety cap, not a design assumption — a
    misconfigured installation pointed at a huge monorepo should not turn
    one ingest run into an unbounded GitHub API bill. 200 open PRs is far
    beyond what a 15-team pilot's single repo should ever actually have
    open at once; hitting the cap is itself worth surfacing later (via
    `IngestSummary`), not silently truncating without a trace.
    """
    summary = IngestSummary()
    source_id = get_or_create_source(conn)
    # Committed immediately, before any repo's own try/except below: a
    # later repo's failure calls conn.rollback() to discard only ITS
    # partial writes (see the loop), which would otherwise also wipe out
    # this uncommitted `source` row out from under every other repo still
    # to come — found by testing the multi-repo failure path directly, not
    # assumed safe because the single-repo case looked fine.
    conn.commit()

    repos = LG.list_installation_repos(token, requested_at, max_pages=max_repo_pages)

    for owner, repo in repos:
        summary.repos_seen += 1
        # The whole repo, not just the PR-listing call, is the unit of
        # isolation: `_get_with_retry` already swallows an individual HTTP
        # call's failure internally (retries, then gives up and returns a
        # falsy result — the same "empty" a repo with genuinely zero open
        # PRs would also produce; a real, accepted limitation this module
        # inherits from `list_open_items`'s established 6.9 precedent, not
        # a new one). What CAN still go wrong at the repo level is a real
        # exception — malformed data reaching `ingest_work_item`, a DB
        # error — and that must not cost the other repos in this
        # installation their data, per D-156 step 6's rule one level down.
        try:
            pr_numbers = LG.list_open_prs(owner, repo, token, requested_at,
                                          max_pages=max_pr_pages)

            if len(pr_numbers) > max_prs_per_repo:
                summary.repo_errors[f"{owner}/{repo}"] = (
                    f"{len(pr_numbers)} open PRs exceeds the {max_prs_per_repo} safety cap; "
                    f"only the first {max_prs_per_repo} were ingested this run")
                pr_numbers = pr_numbers[:max_prs_per_repo]

            project_id = get_or_create_project(conn, source_id, owner, repo)
            snapshot_id = create_snapshot(conn, source_id, project_id, requested_at, requested_at)

            for number in pr_numbers:
                summary.prs_seen += 1
                bundle = LG.fetch_work_item(owner, repo, number, token, requested_at)
                work_item_id = ingest_work_item(conn, snapshot_id, project_id, source_id, bundle)
                if work_item_id is None:
                    summary.work_items_failed += 1
                else:
                    summary.work_items_ingested += 1

            # This repo really was enumerated in full this run (every open
            # PR GitHub reported was fetched, or the cap above already
            # named the ones that weren't) — distinct from the Tavily/2.3
            # snapshots D-080 found never set this, and left that way
            # deliberately since nothing reads it. Setting it accurately
            # here costs nothing and is simply true; no detector relies on
            # it today.
            conn.execute("UPDATE snapshot SET is_complete=1 WHERE id=?", (snapshot_id,))
            # Committed per-repo, not just once at the end: a LATER repo's
            # failure rolls back only its own partial writes (below), never
            # an earlier repo's already-finished ones — the isolation this
            # whole try/except exists for would be a lie otherwise, since
            # sqlite3's implicit transaction spans every statement since the
            # last commit, not just the current repo's.
            conn.commit()
        except Exception as e:
            summary.repos_failed += 1
            summary.repo_errors[f"{owner}/{repo}"] = f"{type(e).__name__}: {e}"
            conn.rollback()  # discard only THIS repo's partial writes
            continue

    conn.commit()
    return summary
