"""
ARGUS — JiraAdapter (Phase 6.2)

Translates Jira Cloud REST API JSON (platform API v3 for issues/changelog,
Agile API v1.0 for boards/sprints — see docs/PHASE6_2_JIRA_ADAPTER.md) into
the source-agnostic entity model extended at Phase 6.1
(docs/PHASE6_1_SCHEMA.md, src/schema.sql §11: sprint / ticket /
ticket_status_event / ticket_link).

Same design principle as github_adapter.py (D-006's source-agnostic model,
Phase 2.2's own architecture): this module does not call the network
itself. It takes already-fetched JSON and writes it into the schema. That
was true for GitHub for testability; for Jira it is currently the *only*
option — this sandbox's egress proxy and the device-side tool both refuse
Atlassian's API (confirmed by direct test, D-111), so no live call can be
made from anywhere Claude can currently reach. Keeping fetching and parsing
strictly separate means that gap costs nothing structural: the day a live
fetch path exists (most likely step 6.9, on Dirgh's own staging
environment), it hands its JSON to the exact same functions tested here
against fixtures, unchanged.

Field shapes below were checked against Atlassian's own published OpenAPI
v3 schema (developer.atlassian.com/cloud/jira/platform/swagger.v3.json and
.../software/swagger.v3.json), not guessed from memory — see D-111.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Ticket-type classification
#
# Jira's issuetype.subtask boolean is authoritative where present (unlike
# GitHub, which gives the adapter no such flag at all) and is checked first.
# Everything else is a name keyword match, same ordered-keyword style as
# github_adapter.propose_label_classification (D-068's precedent): checked
# most-specific first so e.g. "Sub-task" (which also contains "task") can't
# be caught by the generic "task" branch before the subtask branch runs.
# ---------------------------------------------------------------------------

def map_ticket_type(issuetype_name: Optional[str], is_subtask: bool) -> str:
    if is_subtask:
        return "subtask"
    name = (issuetype_name or "").lower()
    if "epic" in name:
        return "epic"
    if "sub-task" in name or "subtask" in name:
        return "subtask"
    if "story" in name:
        return "story"
    if "bug" in name:
        return "bug"
    if "task" in name:
        return "task"
    return "unknown"


# ---------------------------------------------------------------------------
# Status classification
#
# Jira only natively distinguishes THREE status categories (new /
# indeterminate / done — Atlassian's own fixed vocabulary, confirmed
# against the swagger schema, D-111). The schema's 5-value status_category
# (backlog/ready/in_progress/in_review/done) makes distinctions Jira's API
# doesn't: backlog vs. ready-for-sprint both read as category 'new';
# in_progress vs. in_review both read as category 'indeterminate'. There is
# no way to derive these without reading the status *name* text, which is
# workflow-specific per Jira site — this is a judgement call, same shape
# as D-068's label-keyword heuristic, and for the identical reason:
# source_status is kept verbatim on the ticket row precisely so a wrong
# guess here is auditable, never silently trusted (see schema.sql §11
# comment on the `ticket` table).
#
# category_key is optional because a changelog entry (ticket_status_event)
# only ever gives a status *name* (fromString/toString), never a category —
# so historical transitions are classified by name alone, a real, narrower
# signal than a live ticket's classification. Named here, not hidden.
# ---------------------------------------------------------------------------

_BACKLOG_NAME_HINTS = ("backlog",)
_REVIEW_NAME_HINTS = ("review", "qa", "test", "verification")
_DONE_NAME_HINTS = ("done", "closed", "resolved", "complete", "released", "shipped")
# Deliberately narrow: "progress"/"doing" are unambiguous in-progress
# words. An earlier version also matched the substring "dev" (to catch
# statuses like "In Development"), but that silently swallowed "Selected
# for Development" — a common ready/queued-for-next-sprint status name at
# many companies, not an in-progress one — into the wrong bucket. Caught
# by this step's own fixture test (ENG-103) before being called done, the
# same bar D-067 and D-082 held earlier adapters to. If a real Jira site's
# "In Development"-style status name needs catching later, it should be
# added back explicitly (the full phrase, not the bare "dev" substring).
_IN_PROGRESS_NAME_HINTS = ("progress", "doing", "in development")
_READY_NAME_HINTS = ("to do", "todo", "open", "ready", "selected", "new", "triage")


def propose_status_category(status_name: Optional[str],
                             category_key: Optional[str] = None) -> str:
    name = (status_name or "").lower()

    if category_key == "done":
        return "done"
    if category_key == "new":
        if any(h in name for h in _BACKLOG_NAME_HINTS):
            return "backlog"
        return "ready"
    if category_key == "indeterminate":
        if any(h in name for h in _REVIEW_NAME_HINTS):
            return "in_review"
        return "in_progress"

    # No category_key (changelog history entry) or an unrecognised key
    # (a custom statusCategory some Jira sites define) — fall back to
    # name-only matching, most-specific first, 'unknown' if nothing hits.
    if any(h in name for h in _DONE_NAME_HINTS):
        return "done"
    if any(h in name for h in _REVIEW_NAME_HINTS):
        return "in_review"
    if any(h in name for h in _BACKLOG_NAME_HINTS):
        return "backlog"
    if any(h in name for h in _IN_PROGRESS_NAME_HINTS):
        return "in_progress"
    if any(h in name for h in _READY_NAME_HINTS):
        return "ready"
    return "unknown"


# ---------------------------------------------------------------------------
# Actor classification
#
# Jira's User object carries accountType ('atlassian' | 'app' | 'customer'),
# confirmed against the swagger schema (D-111) — a real is-this-a-bot signal
# GitHub's API never gives the adapter at all (github_adapter.classify_actor
# has to infer it from a login suffix and a hand-maintained bot list
# instead). 'app' is Jira/Forge automation acting as a user (the Jira
# equivalent of a GitHub Action bot); anything else is treated as human,
# the same 'assumed_human' default direction github_adapter.py takes.
# ---------------------------------------------------------------------------

def classify_jira_actor(user: Optional[dict]) -> tuple[str, str]:
    if user is None or not user.get("accountId"):
        return "unknown", "unresolved"
    if user.get("accountType") == "app":
        return "bot", "profile_flag"
    return "human", "assumed_human"


# ---------------------------------------------------------------------------
# A single fetch attempt, as handed in by the calling session — same shape
# and same reasoning as github_adapter.FetchAttempt (D-063), redefined
# locally rather than imported so this module has no hard dependency on
# GitHub-specific code, per D-006's source-agnostic intent.
# ---------------------------------------------------------------------------

@dataclass
class JiraFetchAttempt:
    url: str
    purpose: str            # 'ticket_search' | 'sprint_list' | 'sprint_issues' |
                             # 'backlog_issues' | 'changelog'
    attempt: int
    tool: str
    outcome: str             # 'ok' | 'failed' | 'corrupt' | 'empty'
    raw_json: Any = None
    http_status: Optional[int] = None
    error_detail: Optional[str] = None
    requested_at: Optional[str] = None


def insert_fetch(conn: sqlite3.Connection, snapshot_id: int, fa: JiraFetchAttempt) -> int:
    cur = conn.execute(
        """INSERT INTO fetch (snapshot_id, url, purpose, attempt, tool,
                               requested_at, outcome, http_status, error_detail)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (snapshot_id, fa.url, fa.purpose, fa.attempt, fa.tool,
         fa.requested_at, fa.outcome, fa.http_status, fa.error_detail),
    )
    return cur.lastrowid


def record_evidence_gap(conn: sqlite3.Connection, snapshot_id: int,
                         gap_type: str, detail: str, detected_at: str) -> None:
    # work_item_id is left NULL — schema.sql §11's comment on
    # ticket_status_event explicitly names this as "the ticket-side
    # equivalent of work_item's date_precision='unknown'" and instructs
    # whichever step first ingests a ticket to record it this way, since
    # evidence_gap (a frozen Phase-2 table) has no ticket_id column of its
    # own. detail carries the ticket/sprint key so the gap is still
    # traceable to a real record, not just a bare count.
    conn.execute(
        """INSERT INTO evidence_gap (snapshot_id, work_item_id, gap_type, detail, detected_at)
           VALUES (?, NULL, ?, ?, ?)""",
        (snapshot_id, gap_type, detail, detected_at),
    )


# ---------------------------------------------------------------------------
# Source / project / actor upserts — 'source' and 'project' are the exact
# same tables GitHub uses (D-006/D-110's reuse), so a Jira site is just
# another row in 'source' and a Jira project is just another row in
# 'project', the same way schema.sql §11 intended.
# ---------------------------------------------------------------------------

def get_or_create_jira_source(conn: sqlite3.Connection, base_url: str) -> int:
    row = conn.execute("SELECT id FROM source WHERE name='jira'").fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO source (name, base_url) VALUES ('jira', ?)", (base_url,)
    )
    return cur.lastrowid


def get_or_create_project(conn: sqlite3.Connection, source_id: int,
                           project_key: str, project_name: str) -> int:
    row = conn.execute(
        "SELECT id FROM project WHERE source_id=? AND source_key=?",
        (source_id, project_key),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO project (source_id, source_key, display_name, uses_work_items)
           VALUES (?,?,?,1)""",
        (source_id, project_key, project_name),
    )
    return cur.lastrowid


def upsert_actor(conn: sqlite3.Connection, source_id: int, user: Optional[dict]) -> Optional[int]:
    if user is None or not user.get("accountId"):
        return None
    account_id = user["accountId"]
    kind, reason = classify_jira_actor(user)
    row = conn.execute(
        "SELECT id FROM actor WHERE source_id=? AND source_key=?",
        (source_id, account_id),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO actor (source_id, source_key, display_name, kind, kind_reason)
           VALUES (?,?,?,?,?)""",
        (source_id, account_id, user.get("displayName") or account_id, kind, reason),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Sprint upsert
# ---------------------------------------------------------------------------

_VALID_SPRINT_STATES = {"future", "active", "closed"}


def upsert_sprint(conn: sqlite3.Connection, project_id: int, sprint_json: dict) -> int:
    source_key = str(sprint_json["id"])
    state = sprint_json.get("state") or "unknown"
    if state not in _VALID_SPRINT_STATES:
        state = "unknown"
    row = conn.execute(
        "SELECT id FROM sprint WHERE project_id=? AND source_key=?",
        (project_id, source_key),
    ).fetchone()
    if row:
        conn.execute(
            """UPDATE sprint SET name=?, state=?, starts_at=?, ends_at=? WHERE id=?""",
            (sprint_json.get("name") or source_key, state,
             sprint_json.get("startDate"), sprint_json.get("endDate"), row[0]),
        )
        return row[0]
    cur = conn.execute(
        """INSERT INTO sprint (project_id, source_key, name, state, starts_at, ends_at)
           VALUES (?,?,?,?,?,?)""",
        (project_id, source_key, sprint_json.get("name") or source_key, state,
         sprint_json.get("startDate"), sprint_json.get("endDate")),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Ticket upsert
#
# sprint_id is passed in rather than read off the issue JSON on purpose —
# see docs/PHASE6_2_JIRA_ADAPTER.md's judgement-call section. Sprint
# membership on the classic issue-fields payload lives behind a
# per-Jira-site custom field id (e.g. 'customfield_10020') that is not
# stable across Jira instances; deriving it instead from "which sprint's
# issue list did this ticket appear in" (the Agile API's own
# /sprint/{id}/issue and /board/{id}/backlog endpoints) needs no
# instance-specific guessing and is what the ingestion orchestration below
# actually does.
# ---------------------------------------------------------------------------

def upsert_ticket(conn: sqlite3.Connection, source_id: int, project_id: int,
                   issue_json: dict, sprint_id: Optional[int],
                   fetch_id: Optional[int]) -> int:
    key = issue_json["key"]
    fields = issue_json.get("fields") or {}
    issuetype = fields.get("issuetype") or {}
    status = fields.get("status") or {}
    status_category = status.get("statusCategory") or {}
    assignee = fields.get("assignee")

    assignee_actor_id = upsert_actor(conn, source_id, assignee)
    ticket_type = map_ticket_type(issuetype.get("name"), bool(issuetype.get("subtask")))
    norm_status = propose_status_category(status.get("name"), status_category.get("key"))

    row = conn.execute(
        "SELECT id FROM ticket WHERE source_id=? AND project_id=? AND source_key=?",
        (source_id, project_id, key),
    ).fetchone()

    payload = json.dumps(issue_json)
    if row:
        ticket_id = row[0]
        conn.execute(
            """UPDATE ticket SET title=?, ticket_type=?, source_status=?,
                   status_category=?, sprint_id=?, assignee_actor_id=?,
                   source_updated_at=?, fetch_id=?, source_payload=?
               WHERE id=?""",
            (fields.get("summary") or "", ticket_type, status.get("name") or "unknown",
             norm_status, sprint_id, assignee_actor_id, fields.get("updated"),
             fetch_id, payload, ticket_id),
        )
        return ticket_id

    cur = conn.execute(
        """INSERT INTO ticket (source_id, project_id, source_key, title, ticket_type,
                                source_status, status_category, sprint_id,
                                assignee_actor_id, created_at, source_updated_at,
                                fetch_id, source_payload)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source_id, project_id, key, fields.get("summary") or "", ticket_type,
         status.get("name") or "unknown", norm_status, sprint_id, assignee_actor_id,
         fields.get("created"), fields.get("updated"), fetch_id, payload),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Status changelog -> ticket_status_event
#
# Each Jira 'history' entry can bundle several field changes together
# (e.g. a status change and an assignee change logged in the same
# timestamped event); only items where field == 'status' are relevant
# here. A history entry missing 'created' has never been observed live
# (every real changelog entry this adapter's fixtures model carries one),
# but the schema comment treats a missing date as an expected possibility,
# not a hypothetical, so it is handled defensively and recorded as an
# evidence_gap rather than silently dropped or crashing.
# ---------------------------------------------------------------------------

def ingest_status_changelog(conn: sqlite3.Connection, snapshot_id: int, ticket_id: int,
                             ticket_key: str, changelog_json: dict,
                             fetch_id: Optional[int]) -> int:
    histories = (changelog_json or {}).get("histories") or []
    inserted = 0
    for history in histories:
        changed_at = history.get("created")
        for item in history.get("items") or []:
            if item.get("field") != "status":
                continue
            from_status = item.get("fromString")
            to_status = item.get("toString") or "unknown"
            to_category = propose_status_category(to_status)

            # ticket_status_event has no UNIQUE constraint of its own (unlike
            # ticket/sprint, which are upserted on their real source key) —
            # a changelog has no id ARGUS can key off, so identity here is
            # the transition itself. Without this check, re-ingesting the
            # same already-seen snapshot (e.g. a retried fetch) would double
            # every status event and corrupt any later "days in status X"
            # clock built on top of this table. Found and fixed while
            # building this, not left as a known gap — same bar D-067 held
            # the GitHub adapter's comment-counting to.
            dup = conn.execute(
                """SELECT 1 FROM ticket_status_event
                   WHERE ticket_id=? AND to_status=?
                     AND (from_status IS ? OR from_status = ?)
                     AND (changed_at IS ? OR changed_at = ?)""",
                (ticket_id, to_status, from_status, from_status, changed_at, changed_at),
            ).fetchone()
            if dup:
                continue

            conn.execute(
                """INSERT INTO ticket_status_event
                       (ticket_id, from_status, to_status, to_status_category,
                        changed_at, fetch_id)
                   VALUES (?,?,?,?,?,?)""",
                (ticket_id, from_status, to_status, to_category,
                 changed_at, fetch_id),
            )
            inserted += 1
            if changed_at is None:
                record_evidence_gap(
                    conn, snapshot_id, "event_without_date",
                    f"ticket {ticket_key}: status change to '{to_status}' has no changelog date",
                    detected_at=history.get("__detected_at", "unknown"),
                )
    return inserted


# ---------------------------------------------------------------------------
# Orchestration — given one project's already-fetched bundle (project info,
# every sprint plus its issues, the backlog's issues, and each issue's
# changelog), write it all into one snapshot. Mirrors ingest.py's role for
# GitHub (fetch elsewhere, ingest here), scaled down because Jira's ticket
# model has no equivalent of GitHub's sprawling timeline-event
# reconciliation — a ticket's full history is just its changelog.
# ---------------------------------------------------------------------------

@dataclass
class JiraProjectBundle:
    project_key: str
    project_name: str
    base_url: str
    sprints: list[dict] = field(default_factory=list)          # list of SprintBean
    sprint_issues: dict[str, list[dict]] = field(default_factory=dict)  # sprint id (str) -> issues
    backlog_issues: list[dict] = field(default_factory=list)
    changelogs: dict[str, dict] = field(default_factory=dict)  # issue key -> changelog JSON
    observed_at: str = ""


def ingest_project(conn: sqlite3.Connection, snapshot_id: int, bundle: JiraProjectBundle) -> dict:
    """Returns a small summary dict for the caller to report back
    (tickets_created, sprints_created, status_events) — mirrors the
    per-item summary github ingestion callers already print."""
    source_id = get_or_create_jira_source(conn, bundle.base_url)
    project_id = get_or_create_project(conn, source_id, bundle.project_key, bundle.project_name)

    sprint_db_ids: dict[str, int] = {}
    for sprint_json in bundle.sprints:
        sprint_db_ids[str(sprint_json["id"])] = upsert_sprint(conn, project_id, sprint_json)

    tickets_created = 0
    status_events = 0

    def _ingest_issue(issue_json: dict, sprint_db_id: Optional[int]) -> None:
        nonlocal tickets_created, status_events
        ticket_id = upsert_ticket(conn, source_id, project_id, issue_json,
                                   sprint_db_id, fetch_id=None)
        tickets_created += 1
        changelog = bundle.changelogs.get(issue_json["key"])
        if changelog is not None:
            status_events += ingest_status_changelog(
                conn, snapshot_id, ticket_id, issue_json["key"], changelog, fetch_id=None
            )

    for sprint_source_key, issues in bundle.sprint_issues.items():
        sprint_db_id = sprint_db_ids.get(sprint_source_key)
        for issue_json in issues:
            _ingest_issue(issue_json, sprint_db_id)

    for issue_json in bundle.backlog_issues:
        _ingest_issue(issue_json, sprint_db_id=None)   # backlog: sprint_id NULL, deliberately (schema §11)

    return {
        "sprints": len(sprint_db_ids),
        "tickets": tickets_created,
        "status_events": status_events,
    }
