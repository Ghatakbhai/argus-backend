"""
ARGUS — LinearAdapter (Phase 6.3)

Translates Linear's GraphQL API data (issues, their workflow-state history,
and cycles) into the same `ticket` / `ticket_status_event` / `sprint` tables
`jira_adapter.py` (Phase 6.2) writes into — reusing `project` and `actor`
per D-006/D-110's source-agnostic design, exactly like the Jira adapter
does. Same architecture principle as both earlier adapters: this module
never calls the network itself, only parses already-fetched JSON.

Field names below were checked against every source this session could
actually reach — Linear's own official docs (linear.app/docs/*,
linear.app/developers/*), third-party API-reference generators that
mirror the live schema, and Linear's own example queries — not written
from memory. Two honest exceptions, named rather than glossed over (full
reasoning in docs/PHASE6_3_LINEAR_ADAPTER.md):

1. Linear's raw `IssueHistory` wire format (the equivalent of Jira's
   changelog) could not be confirmed field-by-field through any source
   reachable this session — every attempt hit either a JS-rendered page
   WebFetch can't read, or a truncated fetch of Linear's full
   schema.graphql (a very large file). Rather than guess field names for
   something this important, `ingest_status_change` below defines ARGUS's
   OWN input contract explicitly (resolved state names/types, not raw
   Linear field names) and documents that whatever eventually fetches
   this data is responsible for resolving Linear's raw history entries
   into this shape. This should be checked against a real pull at 6.9,
   not assumed correct.
2. No Linear field reliably distinguishing a bot/integration actor from a
   real person could be confirmed either. `classify_linear_actor` below
   always returns human/assumed_human — a real, narrower gap than both
   `github_adapter.py` (a login-suffix heuristic) and `jira_adapter.py`
   (Jira's own authoritative `accountType` field) have. Named, not hidden.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Ticket-type classification
#
# Confirmed against Linear's own docs (linear.app/docs/parent-and-sub-issues,
# linear.app/docs/labels): Linear has NO native issue-type field at all —
# no story/bug/task/epic distinction the way Jira's issuetype.name is
# authoritative. This is a real, structural difference, not a gap in this
# adapter. `parent` (sub-issue linkage) is the one authoritative signal
# Linear does give; everything else falls back to a best-effort label-name
# scan, which will miss far more often than Jira's equivalent — expected,
# not a defect, and named for Dirgh as an open product question (does an
# 'unknown'-heavy ticket_type column need attention, or is it fine because
# ARGUS mainly needs status_category?), not a Claude-only engineering call.
# ---------------------------------------------------------------------------

def map_ticket_type(label_names: list[str], has_parent: bool) -> str:
    if has_parent:
        return "subtask"
    names = " ".join((n or "").lower() for n in label_names)
    if "epic" in names:
        return "epic"
    if "bug" in names:
        return "bug"
    if "story" in names or "feature" in names:
        return "story"
    if "task" in names or "chore" in names:
        return "task"
    return "unknown"


# ---------------------------------------------------------------------------
# Status classification
#
# Unlike Jira (three native categories, name-text heuristics needed for
# the finer distinctions), Linear's WorkflowState.type is a genuine
# seven-value enum confirmed via a third-party API-reference generator
# that mirrors Linear's live schema (docs/PHASE6_3_LINEAR_ADAPTER.md
# §"what was verified, and how"): 'triage', 'backlog', 'unstarted',
# 'started', 'completed', 'canceled', 'duplicate'. This is authoritative
# per-state, not per-name-guess, which is a real improvement over both
# earlier adapters for the four unambiguous buckets — only 'started'
# still needs a name hint to split in_progress from in_review, the same
# limitation Jira has, because Linear doesn't natively distinguish those
# either.
#
# 'canceled' and 'duplicate' both map to the schema's new 'canceled'
# bucket (added this step — see schema.sql's Phase 6.3 header note and
# docs/PHASE6_3_LINEAR_ADAPTER.md). A duplicate issue is, for ARGUS's
# purposes, the same "this was never going to become a completed workflow
# outcome" shape as a canceled one — collapsing them avoids inventing an
# eighth bucket no detector will ever need to tell apart from the seventh.
# ---------------------------------------------------------------------------

_REVIEW_NAME_HINTS = ("review", "qa", "test", "verification")

_STATE_TYPE_MAP = {
    "triage": "backlog",
    "backlog": "backlog",
    "unstarted": "ready",
    "completed": "done",
    "canceled": "canceled",
    "cancelled": "canceled",   # defensive: some Linear API versions/regions have used this spelling
    "duplicate": "canceled",
}


def propose_status_category(state_name: Optional[str], state_type: Optional[str]) -> str:
    t = (state_type or "").lower()
    if t == "started":
        name = (state_name or "").lower()
        if any(h in name for h in _REVIEW_NAME_HINTS):
            return "in_review"
        return "in_progress"
    return _STATE_TYPE_MAP.get(t, "unknown")


# ---------------------------------------------------------------------------
# Actor classification — see module docstring point 2. No verified
# bot-detection signal; every resolved actor is treated as human, the
# same conservative default direction both earlier adapters fall back to
# when no stronger signal is available (github_adapter.classify_actor's
# own 'assumed_human' branch; jira_adapter's identical default).
# ---------------------------------------------------------------------------

def classify_linear_actor(user: Optional[dict]) -> tuple[str, str]:
    if user is None or not user.get("id"):
        return "unknown", "unresolved"
    return "human", "assumed_human"


# ---------------------------------------------------------------------------
# A single fetch attempt — same shape and reasoning as
# jira_adapter.JiraFetchAttempt (itself mirroring github_adapter's
# FetchAttempt, D-063), redefined locally per D-006's source-agnostic,
# no-hard-cross-import intent.
# ---------------------------------------------------------------------------

@dataclass
class LinearFetchAttempt:
    url: str
    purpose: str            # 'issue_search' | 'cycle_list' | 'cycle_issues' |
                             # 'backlog_issues' | 'issue_history'
    attempt: int
    tool: str
    outcome: str             # 'ok' | 'failed' | 'corrupt' | 'empty'
    raw_json: Any = None
    http_status: Optional[int] = None
    error_detail: Optional[str] = None
    requested_at: Optional[str] = None


def insert_fetch(conn: sqlite3.Connection, snapshot_id: int, fa: LinearFetchAttempt) -> int:
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
    # Same reuse jira_adapter.record_evidence_gap makes: evidence_gap
    # (frozen Phase-2 table) has no ticket_id column, so work_item_id is
    # left NULL per schema.sql §11's own instruction, and the ticket/cycle
    # key is carried in `detail` instead so the gap stays traceable.
    conn.execute(
        """INSERT INTO evidence_gap (snapshot_id, work_item_id, gap_type, detail, detected_at)
           VALUES (?, NULL, ?, ?, ?)""",
        (snapshot_id, gap_type, detail, detected_at),
    )


# ---------------------------------------------------------------------------
# Source / project / actor upserts — identical pattern to jira_adapter.py,
# reusing the same `source`/`project`/`actor` tables. A Linear "team" is
# stored as a `project` row, the same way a Jira project or a GitHub repo
# already is (D-006/D-110).
# ---------------------------------------------------------------------------

def get_or_create_linear_source(conn: sqlite3.Connection, base_url: str) -> int:
    row = conn.execute("SELECT id FROM source WHERE name='linear'").fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO source (name, base_url) VALUES ('linear', ?)", (base_url,)
    )
    return cur.lastrowid


def get_or_create_project(conn: sqlite3.Connection, source_id: int,
                           team_key: str, team_name: str) -> int:
    row = conn.execute(
        "SELECT id FROM project WHERE source_id=? AND source_key=?",
        (source_id, team_key),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO project (source_id, source_key, display_name, uses_work_items)
           VALUES (?,?,?,1)""",
        (source_id, team_key, team_name),
    )
    return cur.lastrowid


def upsert_actor(conn: sqlite3.Connection, source_id: int, user: Optional[dict]) -> Optional[int]:
    if user is None or not user.get("id"):
        return None
    account_id = user["id"]
    kind, reason = classify_linear_actor(user)
    row = conn.execute(
        "SELECT id FROM actor WHERE source_id=? AND source_key=?",
        (source_id, account_id),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO actor (source_id, source_key, display_name, kind, kind_reason)
           VALUES (?,?,?,?,?)""",
        (source_id, account_id, user.get("name") or account_id, kind, reason),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Cycle upsert
#
# Linear's Cycle has NO native 'state' field the way Jira's Sprint does
# (confirmed: every source this session could reach describes Cycle only
# via startsAt/endsAt/completedAt). State has to be derived from those
# dates — and per D-014/D-064's standing discipline (never use wall-clock
# now(), always the snapshot's own observed_at), that derivation uses the
# snapshot's reference time, not real time, so re-running against an old
# snapshot reproduces the same sprint states it did originally.
# ---------------------------------------------------------------------------

def derive_cycle_state(starts_at: Optional[str], ends_at: Optional[str],
                        completed_at: Optional[str], observed_at: str) -> str:
    if completed_at:
        return "closed"
    if not starts_at:
        return "unknown"
    if observed_at < starts_at:
        return "future"
    # Started (per observed_at) and not yet completed — 'active' even past
    # its own endsAt, since Linear doesn't auto-close a cycle at end date
    # in every workspace configuration; only `completedAt` being set is
    # trusted as the real "this cycle is over" signal.
    return "active"


def upsert_cycle(conn: sqlite3.Connection, project_id: int, cycle_json: dict,
                  observed_at: str) -> int:
    source_key = str(cycle_json["id"])
    name = cycle_json.get("name") or f"Cycle {cycle_json.get('number', source_key)}"
    state = derive_cycle_state(
        cycle_json.get("startsAt"), cycle_json.get("endsAt"),
        cycle_json.get("completedAt"), observed_at,
    )
    row = conn.execute(
        "SELECT id FROM sprint WHERE project_id=? AND source_key=?",
        (project_id, source_key),
    ).fetchone()
    if row:
        conn.execute(
            """UPDATE sprint SET name=?, state=?, starts_at=?, ends_at=? WHERE id=?""",
            (name, state, cycle_json.get("startsAt"), cycle_json.get("endsAt"), row[0]),
        )
        return row[0]
    cur = conn.execute(
        """INSERT INTO sprint (project_id, source_key, name, state, starts_at, ends_at)
           VALUES (?,?,?,?,?,?)""",
        (project_id, source_key, name, state, cycle_json.get("startsAt"), cycle_json.get("endsAt")),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Ticket upsert
#
# cycle_id is passed in rather than read off the issue JSON, the same
# design choice jira_adapter.upsert_ticket makes for sprint_id — Linear's
# issue-level cycle reference is straightforward (no per-site custom
# field problem the way Jira has), but deriving it from "which cycle's
# issue list held this ticket" keeps both adapters' orchestration
# symmetric and needs no extra logic either way.
# ---------------------------------------------------------------------------

def upsert_ticket(conn: sqlite3.Connection, source_id: int, project_id: int,
                   issue_json: dict, cycle_id: Optional[int],
                   fetch_id: Optional[int]) -> int:
    key = issue_json["identifier"]
    state = issue_json.get("state") or {}
    assignee = issue_json.get("assignee")
    labels = [l.get("name") for l in (issue_json.get("labels") or []) if l.get("name")]
    has_parent = issue_json.get("parent") is not None

    assignee_actor_id = upsert_actor(conn, source_id, assignee)
    ticket_type = map_ticket_type(labels, has_parent)
    norm_status = propose_status_category(state.get("name"), state.get("type"))

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
            (issue_json.get("title") or "", ticket_type, state.get("name") or "unknown",
             norm_status, cycle_id, assignee_actor_id, issue_json.get("updatedAt"),
             fetch_id, payload, ticket_id),
        )
        return ticket_id

    cur = conn.execute(
        """INSERT INTO ticket (source_id, project_id, source_key, title, ticket_type,
                                source_status, status_category, sprint_id,
                                assignee_actor_id, created_at, source_updated_at,
                                fetch_id, source_payload)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (source_id, project_id, key, issue_json.get("title") or "", ticket_type,
         state.get("name") or "unknown", norm_status, cycle_id, assignee_actor_id,
         issue_json.get("createdAt"), issue_json.get("updatedAt"), fetch_id, payload),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Status history -> ticket_status_event
#
# ARGUS's OWN input contract (module docstring point 1): a list of
# already-resolved transitions, each carrying both the state name AND its
# WorkflowState.type — not Linear's raw wire fields, which this session
# could not confirm. Whatever eventually fetches Linear's real
# `Issue.history` (or equivalent) is responsible for resolving each
# entry's state reference against the team's fetched workflow-state list
# before calling this function. This is a stronger contract than Jira's
# changelog gave (Jira's raw history entries only ever carry a status
# *name*, never enough to resolve type without a second lookup) — Linear
# can support it because line-item classification only needs the state's
# own type, which the caller can resolve once per team, not per event.
# ---------------------------------------------------------------------------

@dataclass
class ResolvedTransition:
    from_status: Optional[str]
    to_status: str
    to_status_type: Optional[str]     # Linear WorkflowState.type, resolved by the caller
    changed_at: Optional[str]


def ingest_status_history(conn: sqlite3.Connection, snapshot_id: int, ticket_id: int,
                           ticket_key: str, transitions: list[ResolvedTransition],
                           fetch_id: Optional[int]) -> int:
    inserted = 0
    for tr in transitions:
        to_category = propose_status_category(tr.to_status, tr.to_status_type)

        # Same re-run safety jira_adapter.ingest_status_changelog added
        # after its own fixture test caught duplication on a second run
        # (D-112) — applied here from the start rather than waiting to
        # rediscover the identical bug.
        dup = conn.execute(
            """SELECT 1 FROM ticket_status_event
               WHERE ticket_id=? AND to_status=?
                 AND (from_status IS ? OR from_status = ?)
                 AND (changed_at IS ? OR changed_at = ?)""",
            (ticket_id, tr.to_status, tr.from_status, tr.from_status,
             tr.changed_at, tr.changed_at),
        ).fetchone()
        if dup:
            continue

        conn.execute(
            """INSERT INTO ticket_status_event
                   (ticket_id, from_status, to_status, to_status_category,
                    changed_at, fetch_id)
               VALUES (?,?,?,?,?,?)""",
            (ticket_id, tr.from_status, tr.to_status, to_category, tr.changed_at, fetch_id),
        )
        inserted += 1
        if tr.changed_at is None:
            record_evidence_gap(
                conn, snapshot_id, "event_without_date",
                f"ticket {ticket_key}: status change to '{tr.to_status}' has no history date",
                detected_at=getattr(tr, "_detected_at", "unknown"),
            )
    return inserted


# ---------------------------------------------------------------------------
# Orchestration — mirrors jira_adapter.ingest_project's role and shape.
# ---------------------------------------------------------------------------

@dataclass
class LinearTeamBundle:
    team_key: str
    team_name: str
    base_url: str
    cycles: list[dict] = field(default_factory=list)                    # list of Cycle objects
    cycle_issues: dict[str, list[dict]] = field(default_factory=dict)    # cycle id (str) -> issues
    backlog_issues: list[dict] = field(default_factory=list)
    histories: dict[str, list[ResolvedTransition]] = field(default_factory=dict)  # issue identifier -> transitions
    observed_at: str = ""


def ingest_team(conn: sqlite3.Connection, snapshot_id: int, bundle: LinearTeamBundle) -> dict:
    source_id = get_or_create_linear_source(conn, bundle.base_url)
    project_id = get_or_create_project(conn, source_id, bundle.team_key, bundle.team_name)

    cycle_db_ids: dict[str, int] = {}
    for cycle_json in bundle.cycles:
        cycle_db_ids[str(cycle_json["id"])] = upsert_cycle(
            conn, project_id, cycle_json, bundle.observed_at
        )

    tickets_created = 0
    status_events = 0

    def _ingest_issue(issue_json: dict, cycle_db_id: Optional[int]) -> None:
        nonlocal tickets_created, status_events
        ticket_id = upsert_ticket(conn, source_id, project_id, issue_json,
                                   cycle_db_id, fetch_id=None)
        tickets_created += 1
        transitions = bundle.histories.get(issue_json["identifier"])
        if transitions is not None:
            status_events += ingest_status_history(
                conn, snapshot_id, ticket_id, issue_json["identifier"], transitions, fetch_id=None
            )

    for cycle_source_key, issues in bundle.cycle_issues.items():
        cycle_db_id = cycle_db_ids.get(cycle_source_key)
        for issue_json in issues:
            _ingest_issue(issue_json, cycle_db_id)

    for issue_json in bundle.backlog_issues:
        _ingest_issue(issue_json, cycle_db_id=None)   # no active cycle: sprint_id NULL, deliberately

    return {
        "cycles": len(cycle_db_ids),
        "tickets": tickets_created,
        "status_events": status_events,
    }
