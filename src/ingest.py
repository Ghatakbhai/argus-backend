"""
ARGUS — Ingestion orchestration (Phase 2.2)

Takes one work item's bundle of already-fetched GitHub API JSON (issue,
timeline, comments, and — for PRs — the pull and its reviews) plus the
FetchAttempt log for every URL involved (including failed retries), and
writes it into the Phase 2.1 schema for one snapshot.

Retry policy lives here, explicitly, per D-060 ("not a patch added after
it breaks"): MAX_ATTEMPTS = 3 per URL. The calling session performs the
actual re-fetch (Tavily is only callable as a live tool from inside a
session); this module's job is to record every attempt made and, if all
three failed, write a fetch_failed evidence gap rather than silently
treating a missing page as "nothing happened."
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from github_adapter import (
    FetchAttempt, insert_fetch, record_fetch_failed_gap,
    upsert_actor, upsert_label, classify_actor, is_ai_drafted,
    extract_mentions, has_question_mark, map_event_type,
    infer_review_request_origin, infer_is_automatic_assignment,
)

MAX_ATTEMPTS = 3


class WorkItemBundle:
    """Everything fetched for one issue/PR, plus the fetch log for it."""

    def __init__(self, owner: str, repo: str, number: int):
        self.owner = owner
        self.repo = repo
        self.number = number
        self.fetches: list[FetchAttempt] = []
        self.issue_json: Optional[dict] = None
        self.pr_json: Optional[dict] = None
        self.timeline_json: Optional[list] = None
        self.comments_json: Optional[list] = None
        self.reviews_json: Optional[list] = None

    def add_fetch(self, fa: FetchAttempt) -> None:
        self.fetches.append(fa)

    def latest_ok(self, purpose_url_suffix: str):
        """Return the raw_json of the highest-attempt 'ok' fetch whose url
        ends with the given suffix, or None if every attempt failed."""
        candidates = [f for f in self.fetches if f.url.endswith(purpose_url_suffix)]
        ok = [f for f in candidates if f.outcome == "ok"]
        if ok:
            return max(ok, key=lambda f: f.attempt).raw_json
        return None

    def all_attempts_for(self, purpose_url_suffix: str) -> list[FetchAttempt]:
        return [f for f in self.fetches if f.url.endswith(purpose_url_suffix)]


def get_or_create_source(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT id FROM source WHERE name='github'").fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO source (name, base_url) VALUES ('github','https://github.com')"
    )
    return cur.lastrowid


def get_or_create_project(conn: sqlite3.Connection, source_id: int, owner: str, repo: str) -> int:
    key = f"{owner}/{repo}"
    row = conn.execute(
        "SELECT id FROM project WHERE source_id=? AND source_key=?", (source_id, key)
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO project (source_id, source_key, display_name) VALUES (?,?,?)",
        (source_id, key, key),
    )
    return cur.lastrowid


def create_snapshot(conn: sqlite3.Connection, source_id: int, project_id: int,
                     observed_at: str, started_at: str) -> int:
    cur = conn.execute(
        """INSERT INTO snapshot (source_id, project_id, observed_at, started_at, is_complete, tool_version)
           VALUES (?,?,?,?,0,'adapter-2.2-demo')""",
        (source_id, project_id, observed_at, started_at),
    )
    return cur.lastrowid


def _log_fetches(conn: sqlite3.Connection, snapshot_id: int, bundle: WorkItemBundle,
                  work_item_id_by_number: dict) -> dict[str, int]:
    """Insert every fetch attempt for this bundle; return {url: last_fetch_id}."""
    last_fetch_id: dict[str, int] = {}
    for fa in bundle.fetches:
        fid = insert_fetch(conn, snapshot_id, fa)
        last_fetch_id[fa.url] = fid
    return last_fetch_id


def ingest_work_item(conn: sqlite3.Connection, snapshot_id: int, project_id: int,
                      source_id: int, bundle: WorkItemBundle) -> Optional[int]:
    """Writes one work item and everything attached to it. Returns the new
    work_item.id, or None if the issue itself could never be fetched (in
    which case only fetch rows and an evidence gap are written)."""

    fetch_ids = _log_fetches(conn, snapshot_id, bundle, {})

    issue = bundle.issue_json
    if issue is None:
        # Every attempt at the core issue page failed. Record the gap at
        # project level (no work_item_id yet) and stop — there is nothing
        # to attach comments or timeline events to.
        record_fetch_failed_gap(
            conn, snapshot_id, None,
            f"{bundle.owner}/{bundle.repo}#{bundle.number}: issue page unreachable after "
            f"{len(bundle.all_attempts_for(f'/issues/{bundle.number}'))} attempts",
            bundle.fetches[-1].requested_at if bundle.fetches else "",
        )
        return None

    author_id = upsert_actor(conn, source_id, issue.get("user"))
    author_login = (issue.get("user") or {}).get("login")
    is_pr = "pull_request" in issue
    pr = bundle.pr_json if is_pr else None

    kind = "change_request" if is_pr else "issue"
    if is_pr and pr is not None:
        if pr.get("merged"):
            state = "merged"
        else:
            state = pr.get("state", issue.get("state"))
    else:
        state = issue.get("state")

    is_draft = bool((pr or {}).get("draft", False))

    milestone_id = None
    ms = issue.get("milestone")
    if ms:
        row = conn.execute(
            "SELECT id FROM milestone WHERE project_id=? AND title=?",
            (project_id, ms["title"]),
        ).fetchone()
        if row:
            milestone_id = row[0]
        else:
            cur = conn.execute(
                """INSERT INTO milestone (project_id, title, state, due_on, closed_at)
                   VALUES (?,?,?,?,?)""",
                (project_id, ms["title"], ms["state"], ms.get("due_on"), ms.get("closed_at")),
            )
            milestone_id = cur.lastrowid

    item_fetch_id = fetch_ids.get(issue.get("url"))
    cur = conn.execute(
        """INSERT INTO work_item (snapshot_id, project_id, source_number, kind, title, body,
                                    state, is_draft, author_id, created_at, closed_at,
                                    milestone_id, url, source_updated_at, fetch_id, source_payload)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (snapshot_id, project_id, bundle.number, kind, issue.get("title"), issue.get("body"),
         state, int(is_draft), author_id, issue.get("created_at"), issue.get("closed_at"),
         milestone_id, issue.get("html_url"), issue.get("updated_at"), item_fetch_id,
         None),  # source_payload omitted in the demo to keep the DB small; adapter can store it
    )
    work_item_id = cur.lastrowid
    item_created_at = issue.get("created_at")

    # -- opened event -------------------------------------------------------
    conn.execute(
        """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,
                                date_precision, counts_as_human, human_reason, fetch_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (snapshot_id, work_item_id, "opened", author_id, item_created_at, "exact",
         1 if classify_actor(issue.get("user"))[0] == "human" else 0,
         "human" if classify_actor(issue.get("user"))[0] == "human" else "bot_account",
         item_fetch_id),
    )

    # -- readiness (only meaningful for PRs) --------------------------------
    if is_pr:
        if pr is not None:
            mergeable_state = pr.get("mergeable_state")
            merge_state = {
                "clean": "clean", "unstable": "clean", "has_hooks": "clean",
                "dirty": "blocked", "behind": "blocked",
            }.get(mergeable_state, "unknown")
            conn.execute(
                """INSERT INTO readiness (work_item_id, merge_state, checks_state, cla_state, evidence_note)
                   VALUES (?,?,?,?,?)""",
                (work_item_id, merge_state, "unknown", "unknown",
                 f"mergeable_state from API: {mergeable_state!r}"),
            )
        else:
            conn.execute(
                "INSERT INTO readiness (work_item_id, merge_state, checks_state, cla_state) VALUES (?,?,?,?)",
                (work_item_id, "unknown", "unknown", "unknown"),
            )
            record_fetch_failed_gap(
                conn, snapshot_id, work_item_id,
                f"pulls/{bundle.number}: PR detail page unreachable; readiness left unknown",
                bundle.fetches[-1].requested_at if bundle.fetches else "",
            )

    # -- labels ---------------------------------------------------------------
    for lbl in issue.get("labels", []):
        label_id = upsert_label(conn, project_id, lbl["name"], lbl.get("description"))
        conn.execute(
            """INSERT INTO work_item_label (work_item_id, label_id, applied_at, applied_by, removed_at)
               VALUES (?,?,?,?,NULL)""",
            (work_item_id, label_id, item_created_at, None),
        )
        # applied_at/applied_by refined below from timeline 'labeled' events, when present.

    # -- assignees (current-state fallback; refined by timeline below) ------
    assignee_logins_seen: set[str] = set()

    # -- timeline events ------------------------------------------------------
    timeline = bundle.timeline_json or []
    if bundle.timeline_json is None:
        record_fetch_failed_gap(
            conn, snapshot_id, work_item_id,
            f"issues/{bundle.number}/timeline: unreachable after all attempts",
            bundle.fetches[-1].requested_at if bundle.fetches else "",
        )

    timeline_fetch_id = fetch_ids.get(f"https://api.github.com/repos/{bundle.owner}/{bundle.repo}/issues/{bundle.number}/timeline")

    for ev in timeline:
        gh_type = ev.get("event")
        if gh_type is None:
            continue
        if gh_type == "commented":
            # GitHub's timeline duplicates every comment already returned by
            # the dedicated /comments endpoint (same id, same body). Found
            # while testing this adapter on real data: skip it here so the
            # comment loop below — which also does mention extraction and
            # writes the `comment` row — is the single source, not two.
            continue
        etype = map_event_type(gh_type)
        # 'reviewed' timeline entries carry the actor under 'user', not
        # 'actor', and their timestamp is 'submitted_at' — a real shape
        # difference found while testing this adapter against live data,
        # not documented in the design doc's field sketch.
        if gh_type == "reviewed":
            actor_obj = ev.get("user")
        else:
            actor_obj = ev.get("actor")
        actor_id = upsert_actor(conn, source_id, actor_obj)
        kind, _ = classify_actor(actor_obj)

        if gh_type == "reviewed":
            occurred_at = ev.get("submitted_at")
        else:
            occurred_at = ev.get("created_at")
        date_precision = "exact"
        if gh_type == "committed":
            author_info = ev.get("author") or {}
            occurred_at = author_info.get("date") or occurred_at
            if not occurred_at:
                date_precision = "unknown"
        if occurred_at is None:
            date_precision = "unknown"

        counts_as_human = 1 if kind == "human" else 0
        human_reason = "human" if kind == "human" else ("bot_account" if kind == "bot" else "unknown_actor")

        if kind == "unknown":
            record_fetch_failed_gap  # (not used here; separate gap type below)
            conn.execute(
                """INSERT INTO evidence_gap (snapshot_id, work_item_id, gap_type, detail, detected_at)
                   VALUES (?,?,?,?,?)""",
                (snapshot_id, work_item_id, "actor_unresolved",
                 f"timeline event {gh_type!r} had no resolvable actor", occurred_at or item_created_at),
            )

        subject_id = None
        if gh_type in ("assigned", "unassigned"):
            subject_id = upsert_actor(conn, source_id, ev.get("assignee") or ev.get("assigner"))
        elif gh_type in ("review_requested", "review_request_removed"):
            subject_id = upsert_actor(conn, source_id, ev.get("requested_reviewer"))

        conn.execute(
            """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, subject_actor_id,
                                    occurred_at, date_precision, counts_as_human, human_reason,
                                    detail, fetch_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (snapshot_id, work_item_id, etype, actor_id, subject_id, occurred_at, date_precision,
             counts_as_human, human_reason, gh_type, timeline_fetch_id),
        )

        # -- assignment intervals -------------------------------------------
        if gh_type == "assigned":
            assignee = ev.get("assignee") or {}
            assignee_login = assignee.get("login")
            is_auto = infer_is_automatic_assignment(assignee_login, author_login, occurred_at, item_created_at)
            conn.execute(
                """INSERT INTO assignment (work_item_id, actor_id, assigned_at, assigned_by, is_automatic)
                   VALUES (?,?,?,?,?)""",
                (work_item_id, subject_id, occurred_at, actor_id, int(is_auto)),
            )
            if assignee_login:
                assignee_logins_seen.add(assignee_login)
        elif gh_type == "unassigned":
            assignee = ev.get("assignee") or {}
            open_row = conn.execute(
                """SELECT id FROM assignment WHERE work_item_id=? AND actor_id=?
                   AND unassigned_at IS NULL ORDER BY id DESC LIMIT 1""",
                (work_item_id, subject_id),
            ).fetchone()
            if open_row:
                conn.execute(
                    "UPDATE assignment SET unassigned_at=? WHERE id=?",
                    (occurred_at, open_row[0]),
                )

        # -- review requests --------------------------------------------------
        if gh_type == "review_requested":
            requested_team = None
            requested_actor_login = None
            if ev.get("requested_reviewer"):
                requested_actor_login = ev["requested_reviewer"].get("login")
            elif ev.get("requested_team"):
                requested_team = ev["requested_team"].get("slug") or ev["requested_team"].get("name")
            requester_login = (actor_obj or {}).get("login")
            origin = "unknown"
            if requested_actor_login:
                origin = infer_review_request_origin(requester_login, author_login, occurred_at, item_created_at)
            conn.execute(
                """INSERT INTO review_request (work_item_id, actor_id, team, requested_by,
                                                 requested_at, removed_at, origin)
                   VALUES (?,?,?,?,?,NULL,?)""",
                (work_item_id, subject_id if requested_actor_login else None,
                 requested_team, actor_id, occurred_at, origin),
            )
        elif gh_type == "review_request_removed":
            requested_actor_login = (ev.get("requested_reviewer") or {}).get("login")
            if requested_actor_login:
                open_row = conn.execute(
                    """SELECT id FROM review_request WHERE work_item_id=? AND actor_id=?
                       AND removed_at IS NULL ORDER BY id DESC LIMIT 1""",
                    (work_item_id, subject_id),
                ).fetchone()
                if open_row:
                    conn.execute(
                        "UPDATE review_request SET removed_at=? WHERE id=?",
                        (occurred_at, open_row[0]),
                    )

        # -- labels via timeline (refines applied_at/applied_by) --------------
        if gh_type in ("labeled", "unlabeled") and ev.get("label"):
            label_id = upsert_label(conn, project_id, ev["label"]["name"], None)
            if gh_type == "labeled":
                # If we already inserted a placeholder row from current-state
                # labels (applied_at = created_at), replace it with the real
                # timeline-derived applied_at/applied_by for this label.
                placeholder = conn.execute(
                    """SELECT id FROM work_item_label WHERE work_item_id=? AND label_id=?
                       AND applied_by IS NULL ORDER BY id DESC LIMIT 1""",
                    (work_item_id, label_id),
                ).fetchone()
                if placeholder:
                    conn.execute(
                        "UPDATE work_item_label SET applied_at=?, applied_by=? WHERE id=?",
                        (occurred_at, actor_id, placeholder[0]),
                    )
                else:
                    conn.execute(
                        """INSERT INTO work_item_label (work_item_id, label_id, applied_at, applied_by)
                           VALUES (?,?,?,?)""",
                        (work_item_id, label_id, occurred_at, actor_id),
                    )
            else:
                open_row = conn.execute(
                    """SELECT id FROM work_item_label WHERE work_item_id=? AND label_id=?
                       AND removed_at IS NULL ORDER BY id DESC LIMIT 1""",
                    (work_item_id, label_id),
                ).fetchone()
                if open_row:
                    conn.execute(
                        "UPDATE work_item_label SET removed_at=? WHERE id=?",
                        (occurred_at, open_row[0]),
                    )

        # -- milestones via timeline -------------------------------------------
        if gh_type in ("milestoned", "demilestoned") and ev.get("milestone"):
            ms_title = ev["milestone"].get("title")
            row = conn.execute(
                "SELECT id FROM milestone WHERE project_id=? AND title=?", (project_id, ms_title)
            ).fetchone()
            if row:
                conn.execute("UPDATE work_item SET milestone_id=? WHERE id=?", (row[0], work_item_id))

        # -- cross-references (D-050) -------------------------------------------
        if gh_type == "cross-referenced":
            source_ev = ev.get("source", {})
            src_issue = source_ev.get("issue", {})
            target_repo_full = (src_issue.get("repository") or {}).get("full_name")
            target_number = src_issue.get("number")
            is_cross = bool(target_repo_full) and target_repo_full != f"{bundle.owner}/{bundle.repo}"
            conn.execute(
                """INSERT INTO reference (from_work_item_id, to_project_key, to_number,
                                            relation, is_cross_project, detected_at)
                   VALUES (?,?,?,?,?,?)""",
                (work_item_id, target_repo_full or f"{bundle.owner}/{bundle.repo}", target_number,
                 "mentions", int(is_cross), occurred_at),
            )

    # -- assignee reconciliation (D-074) ---------------------------------------
    # GitHub does not emit an 'assigned' timeline event for assignees set at
    # the moment an issue/PR is *opened* (only for assignment changes made
    # afterward) — so an item assigned at creation, with no later
    # reassignment, has a current assignee that never generated an
    # 'assigned' timeline row above, and `assignee_logins_seen` (declared
    # as a "current-state fallback" but never actually consulted) stayed
    # empty. Backfill: any login in the issue's own current `assignees`
    # list that the timeline loop didn't already record gets an assignment
    # row here, dated to the item's creation (the only date we have for it)
    # and flagged `is_automatic=0` since we have no timing evidence either
    # way — distinct from H9's CODEOWNERS-style inference, which needs a
    # real 'assigned' event to compare timestamps against.
    for a in issue.get("assignees", []) or []:
        login = a.get("login")
        if not login or login in assignee_logins_seen:
            continue
        assignee_actor_id = upsert_actor(conn, source_id, a)
        conn.execute(
            """INSERT INTO assignment (work_item_id, actor_id, assigned_at, assigned_by, is_automatic)
               VALUES (?,?,?,?,0)""",
            (work_item_id, assignee_actor_id, item_created_at, author_id),
        )
        assignee_logins_seen.add(login)

    # -- label reconciliation (D-074) ------------------------------------------
    # GitHub's timeline records a 'labeled' event using the label's *name at
    # the time it was applied*. If a maintainer later renames that label
    # object (not uncommon — e.g. pytest prefixing 'enhancement' to
    # 'type: enhancement'), GitHub does not retroactively rewrite the old
    # timeline entry, and does not emit a synthetic 'unlabeled' event for the
    # old name either. Left alone, this leaves an open (removed_at IS NULL)
    # work_item_label row under a name the project's label list no longer
    # has — silently overstating the item's currently-applied labels, which
    # matters directly for S-02 (which reads current label state). The
    # issue's own fresh fetch (issue.get("labels")) is authoritative for
    # "currently applied right now," so any open row whose name isn't in
    # that list is known-removed as of this snapshot, even though the exact
    # removal moment (rename or real unlabel) wasn't observed. We close it
    # out at the snapshot's observed_at — an honest upper bound, not a
    # fabricated exact timestamp, matching D-064's rule that clocks read
    # from observed_at rather than invented precision.
    current_label_names = {lbl["name"] for lbl in issue.get("labels", [])}
    observed_at_row = conn.execute(
        "SELECT observed_at FROM snapshot WHERE id=?", (snapshot_id,)
    ).fetchone()
    observed_at = observed_at_row[0] if observed_at_row else item_created_at
    stale_rows = conn.execute(
        """SELECT wil.id, l.name FROM work_item_label wil
           JOIN label l ON l.id = wil.label_id
           WHERE wil.work_item_id=? AND wil.removed_at IS NULL""",
        (work_item_id,),
    ).fetchall()
    for wil_id, lbl_name in stale_rows:
        if lbl_name not in current_label_names:
            conn.execute(
                "UPDATE work_item_label SET removed_at=? WHERE id=?",
                (observed_at, wil_id),
            )

    # -- comments -------------------------------------------------------------
    comments = bundle.comments_json or []
    if bundle.comments_json is None:
        record_fetch_failed_gap(
            conn, snapshot_id, work_item_id,
            f"issues/{bundle.number}/comments: unreachable after all attempts",
            bundle.fetches[-1].requested_at if bundle.fetches else "",
        )
    comments_fetch_id = fetch_ids.get(f"https://api.github.com/repos/{bundle.owner}/{bundle.repo}/issues/{bundle.number}/comments")

    for c in comments:
        actor_id = upsert_actor(conn, source_id, c.get("user"))
        kind, _ = classify_actor(c.get("user"))
        body = c.get("body") or ""
        ai_drafted = is_ai_drafted(body)

        if kind == "bot":
            authorship = "bot"
            counts_as_human, human_reason = 0, "bot_account"
        elif ai_drafted:
            authorship = "ai_drafted_under_human_account"
            counts_as_human, human_reason = 0, "ai_drafted_footnote"
        elif kind == "unknown":
            authorship = "human"  # best guess for the comment record itself
            counts_as_human, human_reason = 0, "unknown_actor"
            conn.execute(
                """INSERT INTO evidence_gap (snapshot_id, work_item_id, gap_type, detail, detected_at)
                   VALUES (?,?,?,?,?)""",
                (snapshot_id, work_item_id, "actor_unresolved",
                 "comment author could not be resolved", c.get("created_at")),
            )
        else:
            authorship = "human"
            counts_as_human, human_reason = 1, "human"

        cur = conn.execute(
            """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,
                                    date_precision, counts_as_human, human_reason, fetch_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (snapshot_id, work_item_id, "commented", actor_id, c.get("created_at"), "exact",
             counts_as_human, human_reason, comments_fetch_id),
        )
        event_id = cur.lastrowid

        cur2 = conn.execute(
            """INSERT INTO comment (event_id, work_item_id, actor_id, created_at, body,
                                      authorship, has_question_mark)
               VALUES (?,?,?,?,?,?,?)""",
            (event_id, work_item_id, actor_id, c.get("created_at"), body, authorship,
             int(has_question_mark(body))),
        )
        comment_id = cur2.lastrowid

        for m in extract_mentions(body):
            if m["is_team"]:
                conn.execute(
                    """INSERT INTO mention (comment_id, work_item_id, mentioned_team, in_code_or_quote)
                       VALUES (?,?,?,?)""",
                    (comment_id, work_item_id, m["team_slug"], int(m["in_code_or_quote"])),
                )
            else:
                mentioned_actor_id = upsert_actor(conn, source_id, {"login": m["login"]})
                conn.execute(
                    """INSERT INTO mention (comment_id, work_item_id, mentioned_actor_id, in_code_or_quote)
                       VALUES (?,?,?,?)""",
                    (comment_id, work_item_id, mentioned_actor_id, int(m["in_code_or_quote"])),
                )

    # -- reviews (PRs only) -----------------------------------------------------
    if is_pr:
        reviews = bundle.reviews_json
        if reviews is None:
            record_fetch_failed_gap(
                conn, snapshot_id, work_item_id,
                f"pulls/{bundle.number}/reviews: unreachable after all attempts",
                bundle.fetches[-1].requested_at if bundle.fetches else "",
            )
        else:
            reviews_fetch_id = fetch_ids.get(f"https://api.github.com/repos/{bundle.owner}/{bundle.repo}/pulls/{bundle.number}/reviews")
            state_map = {
                "APPROVED": "approved", "CHANGES_REQUESTED": "changes_requested",
                "COMMENTED": "commented", "DISMISSED": "dismissed", "PENDING": "commented",
            }
            for r in reviews:
                actor_id = upsert_actor(conn, source_id, r.get("user"))
                kind, _ = classify_actor(r.get("user"))
                counts_as_human = 1 if kind == "human" else 0
                human_reason = "human" if kind == "human" else "bot_account"
                cur = conn.execute(
                    """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,
                                            date_precision, counts_as_human, human_reason, fetch_id)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (snapshot_id, work_item_id, "review_submitted", actor_id,
                     r.get("submitted_at"), "exact", counts_as_human, human_reason, reviews_fetch_id),
                )
                event_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO review (event_id, work_item_id, actor_id, state, submitted_at)
                       VALUES (?,?,?,?,?)""",
                    (event_id, work_item_id, actor_id,
                     state_map.get(r.get("state"), "commented"), r.get("submitted_at")),
                )

    return work_item_id
