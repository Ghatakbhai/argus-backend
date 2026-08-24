"""
ARGUS — GitHubAdapter (Phase 2.2)

Translates GitHub's REST API JSON (fetched via Tavily extraction of
api.github.com URLs — see D-046) into the source-agnostic entity/event
model designed at Phase 2.1 (docs/PHASE2_1_DATA_MODEL.md, src/schema.sql).

This module is pure parsing/normalisation logic. It does not call any
network tool itself — Tavily is only reachable from inside a live Claude
session as a tool call, so the *fetching* is done by the session and handed
to this module as already-retrieved JSON (see FetchAttempt below). This
keeps the adapter testable against saved fixtures and keeps retry policy
visible rather than buried inside a library call.

No design decision here overrides Phase 2.1. Where this module has to make
a judgement call the design document did not fully specify (see the two
heuristics below), the call defaults to the conservative side per the
project's "precision over coverage" rule: when genuinely unsure, record
`unknown` rather than guess.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Bot / human classification (rubric §2, carried into D-062)
# ---------------------------------------------------------------------------

KNOWN_BOT_LOGINS = {
    "dependabot", "github-actions", "pre-commit-ci", "codecov",
    "boring-cyborg", "stale", "mergify", "renovate",
}

# The exact footnote D-057 identified on airflow's AI-assisted triage tool,
# plus a couple of close variants so small wording drift doesn't defeat it.
AI_FOOTNOTE_PATTERNS = [
    re.compile(r"drafted by an ai[- ]assisted triage tool", re.IGNORECASE),
    re.compile(r"ai[- ]assisted triage tool", re.IGNORECASE),
    re.compile(r"this comment was (?:drafted|written) by an ai", re.IGNORECASE),
]


def classify_actor(user: Optional[dict]) -> tuple[str, str]:
    """Return (kind, kind_reason) for a GitHub API 'user'/'actor' object."""
    if user is None:
        return "unknown", "unresolved"
    login = (user.get("login") or "").strip()
    if not login:
        return "unknown", "unresolved"
    if login.endswith("[bot]"):
        return "bot", "suffix_bot"
    bare = login[:-5] if login.endswith("[bot]") else login
    if bare.lower() in KNOWN_BOT_LOGINS:
        return "bot", "known_bot_list"
    # GitHub's own account-type flag, where present.
    if user.get("type") == "Bot":
        return "bot", "profile_flag"
    return "human", "assumed_human"


def is_ai_drafted(body: Optional[str]) -> bool:
    if not body:
        return False
    return any(p.search(body) for p in AI_FOOTNOTE_PATTERNS)


# ---------------------------------------------------------------------------
# Mention extraction (§3.5) — done once at ingest, not re-parsed per detector
# ---------------------------------------------------------------------------

_MENTION_RE = re.compile(r"(?<![\w`])@([A-Za-z0-9][A-Za-z0-9-]{0,38})")
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`]*`")
_QUOTE_LINE_RE = re.compile(r"^\s*>.*$", re.MULTILINE)


def _stripped_for_mentions(body: str) -> tuple[str, set[int]]:
    """Return body with code/quote spans blanked, and the set of character
    offsets (start positions) that fell inside such a span, so a mention
    found at that offset can be flagged in_code_or_quote."""
    masked = body
    spans: list[tuple[int, int]] = []
    for rx in (_CODE_FENCE_RE, _INLINE_CODE_RE, _QUOTE_LINE_RE):
        for m in rx.finditer(body):
            spans.append((m.start(), m.end()))
    return masked, spans


def extract_mentions(body: str) -> list[dict]:
    """Returns a list of {login, in_code_or_quote} for every @mention found.
    Team mentions (org/team-slug) are returned with is_team=True."""
    if not body:
        return []
    _, spans = _stripped_for_mentions(body)

    def in_span(pos: int) -> bool:
        return any(s <= pos < e for s, e in spans)

    out = []
    for m in _MENTION_RE.finditer(body):
        login = m.group(1)
        # org/team form: "@org/team-name" — GitHub renders this as a team
        # mention; re.search ahead for a following "/slug".
        tail = body[m.end():m.end() + 40]
        team_match = re.match(r"/([A-Za-z0-9][A-Za-z0-9-]{0,38})", tail)
        is_team = team_match is not None
        out.append({
            "login": login,
            "is_team": is_team,
            "team_slug": f"{login}/{team_match.group(1)}" if is_team else None,
            "in_code_or_quote": in_span(m.start()),
        })
    return out


HAS_QUESTION_RE = re.compile(r"\?")


def has_question_mark(body: Optional[str]) -> bool:
    return bool(body) and "?" in body


# ---------------------------------------------------------------------------
# Timeline event type -> schema event.type mapping
# ---------------------------------------------------------------------------

_EVENT_TYPE_MAP = {
    "commented": "commented",
    "labeled": "labeled",
    "unlabeled": "unlabeled",
    "milestoned": "milestoned",
    "demilestoned": "demilestoned",
    "assigned": "assigned",
    "unassigned": "unassigned",
    "review_requested": "review_requested",
    "review_request_removed": "review_request_removed",
    "reviewed": "review_submitted",
    "closed": "closed",
    "reopened": "reopened",
    "merged": "closed",              # our enum has no 'merged'; state distinguishes it
    "committed": "committed",
    "head_ref_force_pushed": "force_pushed",
    "ready_for_review": "ready_for_review",
    "convert_to_draft": "converted_to_draft",
    "renamed": "renamed",
    "cross-referenced": "cross_referenced",
    "referenced": "referenced",
}


def map_event_type(github_event: str) -> str:
    return _EVENT_TYPE_MAP.get(github_event, "other")


# ---------------------------------------------------------------------------
# A single fetch attempt, as handed in by the calling session (D-063)
# ---------------------------------------------------------------------------

@dataclass
class FetchAttempt:
    url: str
    purpose: str                       # 'item_page' | 'search' | 'label_list' | 'closed_sample'
    attempt: int
    tool: str
    outcome: str                       # 'ok' | 'failed' | 'corrupt' | 'empty'
    raw_json: Any = None                # parsed JSON, only when outcome == 'ok'
    http_status: Optional[int] = None
    error_detail: Optional[str] = None
    requested_at: Optional[str] = None  # ISO string; caller supplies


def insert_fetch(conn: sqlite3.Connection, snapshot_id: int, fa: FetchAttempt) -> int:
    cur = conn.execute(
        """INSERT INTO fetch (snapshot_id, url, purpose, attempt, tool,
                               requested_at, outcome, http_status, error_detail)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (snapshot_id, fa.url, fa.purpose, fa.attempt, fa.tool,
         fa.requested_at, fa.outcome, fa.http_status, fa.error_detail),
    )
    return cur.lastrowid


def record_fetch_failed_gap(conn: sqlite3.Connection, snapshot_id: int,
                             work_item_id: Optional[int], detail: str, detected_at: str) -> None:
    conn.execute(
        """INSERT INTO evidence_gap (snapshot_id, work_item_id, gap_type, detail, detected_at)
           VALUES (?,?,?,?,?)""",
        (snapshot_id, work_item_id, "fetch_failed", detail, detected_at),
    )


# ---------------------------------------------------------------------------
# Actor upsert
# ---------------------------------------------------------------------------

def upsert_actor(conn: sqlite3.Connection, source_id: int, user: Optional[dict]) -> Optional[int]:
    if user is None or not user.get("login"):
        return None
    login = user["login"]
    kind, reason = classify_actor(user)
    row = conn.execute(
        "SELECT id, kind FROM actor WHERE source_id=? AND source_key=?",
        (source_id, login),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO actor (source_id, source_key, display_name, kind, kind_reason)
           VALUES (?,?,?,?,?)""",
        (source_id, login, user.get("name") or login, kind, reason),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Label vocabulary — proposed classification (§3.2), pending Dirgh's confirm
# ---------------------------------------------------------------------------

BLOCKER_KEYWORDS = ["on hold", "on-hold", "blocked", "blocker", "awaiting",
                     "waiting", "needs-", "needs ", "wip", "do-not-merge",
                     "hold"]
HEALTHY_SLOWNESS_KEYWORDS = ["no-stale", "pinned", "keep-open", "keep open",
                              "long-term", "backlog", "help wanted",
                              "good first issue"]
TRIAGE_KEYWORDS = ["triage", "needs-triage", "needs triage", "unconfirmed"]


def propose_label_classification(name: str, description: Optional[str]) -> str:
    # D-068 narrowed this to the label's *name* only — description prose
    # produced false positives (`type: bug`'s "needs to be addressed"
    # reading as a blocker keyword purely because of the word "needs").
    # `description` is kept as a parameter for signature compatibility
    # with callers, but is not matched here (see D-078: D-068's fix was
    # never actually applied to this function until this pass).
    text = name.lower()
    if any(k in text for k in HEALTHY_SLOWNESS_KEYWORDS):
        return "healthy_slowness"
    if any(k in text for k in BLOCKER_KEYWORDS):
        return "blocker"
    if any(k in text for k in TRIAGE_KEYWORDS):
        return "triage_only"
    return "unclassified"


def upsert_label(conn: sqlite3.Connection, project_id: int, name: str,
                  description: Optional[str]) -> int:
    row = conn.execute(
        "SELECT id FROM label WHERE project_id=? AND name=?", (project_id, name)
    ).fetchone()
    if row:
        return row[0]
    classification = propose_label_classification(name, description)
    cur = conn.execute(
        """INSERT INTO label (project_id, name, description, classification, classification_status)
           VALUES (?,?,?,?,'proposed')""",
        (project_id, name, description, classification),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Heuristic 1: review-request origin (manual vs. codeowners vs. unknown)
#
# The GitHub API does not label a review request as CODEOWNERS-generated.
# D-043's examples were read by a human. Two real fixtures this session
# calibrate the rule:
#   - apache/airflow#65070 (D-043's own CODEOWNERS example): five requests,
#     all attributed to the PR's own author, all landing 2 seconds after
#     the item's created_at — a tight cluster, machine-speed.
#   - pola-rs/polars#12597: nine requests, also all attributed to the PR's
#     own author (this is normal — GitHub attributes a CODEOWNERS request
#     to whoever pushed, and a human requesting reviewers on their own PR
#     also shows up as "requester == author"), but landing anywhere from
#     15 hours to 3 months after creation.
# So "requester == author" alone does not distinguish the two cases — most
# genuinely manual requests are also self-requested by the PR author. The
# discriminator that held up against both real cases is timing: a request
# landing within a few seconds of the item's creation, by the author, is
# machine-speed and treated as 'codeowners'; the same author requesting
# hours or months later is a deliberate, later action and treated as
# 'manual'. A request from someone other than the author is unambiguous
# and always 'manual' regardless of timing. This is a technical call,
# recorded as D-065.
#
# Known honest limit: a human who selects reviewers in the same UI action
# used to open the PR is indistinguishable from CODEOWNERS by this rule —
# both land within seconds of creation. That case is under-counted as
# 'codeowners' rather than 'manual', which is the conservative direction
# for S-04 (a missed promise, not a fabricated one).
# ---------------------------------------------------------------------------

CODEOWNERS_WINDOW_SECONDS = 15


def infer_review_request_origin(requester_login: Optional[str],
                                 author_login: Optional[str],
                                 requested_at: Optional[str],
                                 item_created_at: Optional[str]) -> str:
    if not requester_login or not author_login:
        return "unknown"
    if requester_login != author_login:
        return "manual"
    if not requested_at or not item_created_at:
        return "unknown"
    try:
        from datetime import datetime
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        dt_req = datetime.strptime(requested_at, fmt)
        dt_created = datetime.strptime(item_created_at, fmt)
        delta = abs((dt_req - dt_created).total_seconds())
    except Exception:
        return "unknown"
    return "codeowners" if delta <= CODEOWNERS_WINDOW_SECONDS else "manual"


# ---------------------------------------------------------------------------
# Heuristic 2: automatic assignment (H9)
#
# Same problem: the API has no is_automatic flag. Inferred only when the
# assignee is the item's own author AND the assignment timestamp is within
# 120 seconds of item creation (self-assignment on creation is the
# documented shape of "auto-assign the author" repo settings). Anything
# else is left is_automatic=0 — the conservative default, since H9 is a
# suppressor and a false 'automatic' would wrongly suppress a real stall.
# Recorded alongside D-065.
# ---------------------------------------------------------------------------

def infer_is_automatic_assignment(assignee_login: Optional[str],
                                   author_login: Optional[str],
                                   assigned_at: Optional[str],
                                   item_created_at: Optional[str]) -> bool:
    if not assignee_login or assignee_login != author_login:
        return False
    if not assigned_at or not item_created_at:
        return False
    try:
        from datetime import datetime
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        delta = abs((datetime.strptime(assigned_at, fmt) -
                     datetime.strptime(item_created_at, fmt)).total_seconds())
    except Exception:
        return False
    return delta <= 120
