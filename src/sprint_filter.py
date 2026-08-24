"""
ARGUS — Phase 6.4: the sprint-status filter and the narrow 2-pattern
detection pipeline.

WHAT THIS STEP IS FOR
---------------------
Part I closed at a 65.5% precision ceiling on GitHub-only signals (D-106).
The structural reason was named plainly: most false positives were items
nobody had ever been asked to act on — backlog work that GitHub cannot
tell apart from live work. Jira/Linear can tell them apart, because a
sprint board is exactly the record of "what this team agreed to do now".

So this module is deliberately NOT a tenth detector. It is two things:

  1. A LINK — which GitHub pull request corresponds to which ticket.
  2. A GATE — if the linked ticket is not live work in an active sprint,
     the alert dies before anyone sees it.

and on top of those, a narrow two-pattern MVP that fires on nothing else.

THE THREE OUTCOMES, AND WHY THEY ARE THREE AND NOT TWO
------------------------------------------------------
Every open work item in the snapshot gets exactly one outcome:

  FIRE       — a pattern matched in full and the sprint gate passed.
  SUPPRESSED — the pattern shape matched in full, and the ONLY thing that
               stopped it was the sprint gate.
  ABSTAIN    — everything else. Explicitly stated, never implied by
               absence (Phase 6.4's own "default to silence" rule).

The pattern shape is always evaluated BEFORE the gate, and the gate is
the only thing that can produce SUPPRESSED. That ordering is what makes
the word "suppressed" mean something: every SUPPRESSED row is an alert
Part I would have sent and Part II does not. Counting them is how we
find out whether the sprint filter is doing any work at all — which is
the whole question Phase 6's kill criterion turns on.

WHAT 'UNKNOWN' IS ALLOWED TO DO
-------------------------------
Phase 2 made merge/CI/CLA readiness three-valued on purpose (D-031,
D-037, D-042) so that "we could not see" never silently becomes "it's
fine". That rule is applied here in both directions, and the asymmetry
is intentional, not an oversight:

  * Pattern 1 requires CI GREEN as a positive condition, so
    checks_state='unknown' does NOT satisfy it -> ABSTAIN.
  * A merge conflict SUPPRESSES, so merge_state='unknown' does NOT
    suppress -> the pattern survives on that count.

Same rule both times: an unknown is never converted into a claim, in
whichever direction a claim would have been convenient.

WHAT IS NOT IN THE SCHEMA, AND HOW THAT IS HANDLED
--------------------------------------------------
Phase 6.4's brief asks for ticket keys to be read from PR branch names,
PR titles, and commit messages. Only one of those three is in the
database today: `work_item.title`. Phase 2's sections 1-10 are frozen
(D-110 was told not to alter them), and no column anywhere stores a
branch name or a commit message body — `event.detail` on a 'committed'
row carries GitHub's own event-type string, not the message.

Rather than guess a parsing route or widen a frozen table, this module
does what the Linear adapter did with Linear's unconfirmed status-history
wire format (D-113): it defines ARGUS's own explicit contract for the
text a linker needs — `LinkTextSources` — populates whatever the current
database can actually supply, records what it could not supply, and puts
the burden of filling the rest on whichever step first has live API
access (6.9). Nothing is invented; the missing sources are counted and
reported, not silently treated as empty.

WHY A WELL-FORMED KEY IS NOT ENOUGH TO MAKE A LINK
--------------------------------------------------
`[A-Z]+-\\d+` also matches UTF-8, SHA-256, AES-256, ISO-8601, CVE-2021
and every other hyphenated technical token an engineer writes in a PR
title. Step 6.2 already shipped one over-broad substring match and its
own tests caught it; the same class of bug is far more dangerous here,
because a wrong link routes a real alert through a stranger's sprint
board. So a candidate key becomes a link only when a ticket with that
exact key has ALREADY been ingested from Jira or Linear. An unresolved
candidate is counted and reported, never linked and never guessed at.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Thresholds and vocabulary
# ---------------------------------------------------------------------------

# Both MVP patterns use the same 48-hour idle threshold, from the roadmap's
# own wording. It is expressed in HOURS and computed from raw timestamps,
# not read off v_item_clock / v_actor_item_clock: those views CAST their
# day count to INTEGER, which is fine for Part I's 14-to-180 day patterns
# and much too coarse for a two-day one (a 2.9-day silence reads as "2").
IDLE_HOURS = 48.0

# The gate's own vocabulary. A ticket is "live work" only if it is sitting
# in a sprint the source itself calls active AND its status category is
# not one of the parked ones.
PARKED_STATUS_CATEGORIES = frozenset({"backlog", "canceled"})

P1 = "P1-approved-unmerged"
P2 = "P2-review-ghosted"

FIRE = "FIRE"
SUPPRESSED = "SUPPRESSED"
ABSTAIN = "ABSTAIN"

_OUTCOME_RANK = {ABSTAIN: 0, SUPPRESSED: 1, FIRE: 2}


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def parse_dt(s: Optional[str]) -> Optional[datetime]:
    """Tolerant ISO-8601 reader.

    Three sources write three shapes into this database and all three are
    already on disk: GitHub's '...Z', Jira's '...+0000', Linear's
    '...:00.000Z'. detectors.py's strptime(ISO) handles only the first,
    which is correct for a GitHub-only phase and would silently raise here.
    """
    if not s:
        return None
    t = s.strip().replace("Z", "+00:00")
    # '+0000' -> '+00:00'
    m = re.search(r"([+-]\d{2})(\d{2})$", t)
    if m:
        t = t[: m.start()] + m.group(1) + ":" + m.group(2)
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def hours_between(later: Optional[str], earlier: Optional[str]) -> Optional[float]:
    a, b = parse_dt(later), parse_dt(earlier)
    if a is None or b is None:
        return None
    return (a - b).total_seconds() / 3600.0


# ---------------------------------------------------------------------------
# 1. Ticket-key extraction
# ---------------------------------------------------------------------------

# A Jira project key or a Linear team key, then a hyphen, then a number.
# Matched case-insensitively because branch names are conventionally
# lowercase ('feature/eng-123-oauth') while the key itself is not, and
# upper-cased before resolution. The boundary guards stop the pattern
# from biting into a longer token ('ENG-123abc', 'v1.2-3').
#
# Prefix 2-10 characters: Jira caps a project key at 10 and Linear team
# keys are shorter still. Number up to 7 digits: long-lived Jira sites do
# reach seven-figure issue numbers, and capping lower would silently drop
# real keys on exactly the biggest customers.
TICKET_KEY_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z][A-Za-z0-9]{1,9})-(\d{1,7})(?![A-Za-z0-9])")

# The three text sources, in descending order of how deliberate a mention
# in each one is, which is also this module's confidence ordering.
#
#   branch_name   — a branch is named once, on purpose, from the ticket
#                   the developer picked up. Strongest signal there is.
#   smart_commit  — a commit message key is the convention Jira itself
#                   built "smart commits" around; also deliberate.
#   pr_title_key  — real, but weaker: titles get edited, and a title can
#                   REFERENCE a ticket without being that ticket
#                   ("follow-up to ENG-123", "reverts ENG-123").
#
# The PR body is deliberately NOT a source. It is the longest and least
# disciplined text on an item — issue templates, stack traces, changelog
# pastes and review chatter all live there — and every extra key it
# would contribute is a key nobody deliberately attached to this PR.
# Precision over coverage (working agreement), applied at the input.
METHOD_CONFIDENCE = {
    "branch_name": "high",
    "smart_commit": "high",
    "pr_title_key": "medium",
}
_METHOD_RANK = {"branch_name": 3, "smart_commit": 2, "pr_title_key": 1}


@dataclass
class LinkTextSources:
    """ARGUS's own contract for the text a ticket-linker reads.

    `missing` names the sources that could not be supplied for this item
    at all, so a link failure is reported as "we never had the branch
    name" rather than as "no ticket was mentioned". Those are completely
    different facts and only one of them is about the team's behaviour.
    """
    work_item_id: int
    branch_name: Optional[str] = None
    title: Optional[str] = None
    commit_messages: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    def texts(self) -> list[tuple[str, str]]:
        """[(link_method, text)] for every source actually present."""
        out: list[tuple[str, str]] = []
        if self.branch_name:
            out.append(("branch_name", self.branch_name))
        if self.title:
            out.append(("pr_title_key", self.title))
        for msg in self.commit_messages:
            if msg:
                out.append(("smart_commit", msg))
        return out


def extract_ticket_keys(text: Optional[str]) -> list[str]:
    """Every well-formed candidate key in `text`, upper-cased, in order,
    deduplicated. This says nothing about whether the key is real —
    resolution against ingested tickets is a separate, deliberate step."""
    if not text:
        return []
    seen: dict[str, None] = {}
    for prefix, number in TICKET_KEY_RE.findall(text):
        seen.setdefault(f"{prefix.upper()}-{int(number)}", None)
    return list(seen)


def link_sources_from_db(conn: sqlite3.Connection, work_item_id: int) -> LinkTextSources:
    """Populate the contract from what THIS database can actually supply.

    Today that is: the title (always), and the branch name only when the
    adapter happened to keep the raw payload and that payload carries
    head.ref. Commit messages are never available — no column stores
    them (see the module docstring). Everything absent is named in
    `missing` rather than defaulted to empty.
    """
    row = conn.execute(
        "SELECT title, source_payload FROM work_item WHERE id=?", (work_item_id,)
    ).fetchone()
    if row is None:
        return LinkTextSources(work_item_id=work_item_id,
                               missing=["title", "branch_name", "commit_messages"])
    title, payload = row

    branch = None
    if payload:
        try:
            head = (json.loads(payload) or {}).get("head") or {}
            ref = head.get("ref")
            if isinstance(ref, str) and ref.strip():
                branch = ref.strip()
        except (ValueError, AttributeError):
            branch = None

    missing = []
    if not title:
        missing.append("title")
    if branch is None:
        missing.append("branch_name")
    missing.append("commit_messages")   # never stored by Phase 2; always a gap
    return LinkTextSources(work_item_id=work_item_id, branch_name=branch,
                           title=title, missing=missing)


# ---------------------------------------------------------------------------
# 2. Resolving candidates to real tickets, and writing ticket_link
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProposedLink:
    work_item_id: int
    ticket_id: int
    ticket_key: str
    link_method: str
    confidence: str


@dataclass
class LinkOutcome:
    proposed: list[ProposedLink] = field(default_factory=list)
    unresolved_keys: list[str] = field(default_factory=list)   # well-formed, no such ticket
    missing_sources: list[str] = field(default_factory=list)


def _ticket_index(conn: sqlite3.Connection) -> dict[str, int]:
    """{'ENG-123': ticket.id} across every ingested source.

    Keys are compared upper-cased. If two sources ever ship the same key
    (a Jira project and a Linear team both called ENG), the first ingested
    wins and the collision is left visible in the table rather than being
    resolved by a guess — cross-source identity is an unsolved problem
    this project already has open (D-110's actor.person_id gap).
    """
    idx: dict[str, int] = {}
    for tid, key in conn.execute("SELECT id, source_key FROM ticket"):
        idx.setdefault(key.upper(), tid)
    return idx


def propose_links(conn: sqlite3.Connection, sources: LinkTextSources,
                  index: Optional[dict[str, int]] = None) -> LinkOutcome:
    """Resolve one work item's text into at most one proposed link per
    ticket, keeping the strongest method that found it."""
    idx = _ticket_index(conn) if index is None else index
    best: dict[str, tuple[str, int]] = {}       # key -> (method, rank)
    unresolved: dict[str, None] = {}

    for method, text in sources.texts():
        for key in extract_ticket_keys(text):
            if key not in idx:
                unresolved.setdefault(key, None)
                continue
            rank = _METHOD_RANK[method]
            if key not in best or rank > best[key][1]:
                best[key] = (method, rank)

    proposed = [
        ProposedLink(work_item_id=sources.work_item_id, ticket_id=idx[key],
                     ticket_key=key, link_method=method,
                     confidence=METHOD_CONFIDENCE[method])
        for key, (method, _rank) in best.items()
    ]
    proposed.sort(key=lambda p: p.ticket_key)
    return LinkOutcome(proposed=proposed, unresolved_keys=list(unresolved),
                       missing_sources=list(sources.missing))


def ingest_ticket_links(conn: sqlite3.Connection,
                        sources_by_item: Iterable[LinkTextSources],
                        detected_at: str) -> dict:
    """Write proposed links into `ticket_link`, idempotently.

    `ticket_link` has UNIQUE(ticket_id, work_item_id), so a re-run must
    neither duplicate a row nor throw. It must also not DOWNGRADE one: if
    a first run only had the title and a later run also has the branch
    name, the stored method should improve. Step 6.2's changelog bug (a
    re-run doubling every status event, D-112) is the reason this is
    written as an explicit upsert with counts rather than an
    INSERT OR IGNORE — a silent ignore hides exactly that class of bug.
    """
    idx = _ticket_index(conn)
    stats = {"inserted": 0, "upgraded": 0, "unchanged": 0,
             "unresolved_keys": 0, "items_without_any_link": 0,
             "items_missing_a_source": 0}

    for src in sources_by_item:
        outcome = propose_links(conn, src, index=idx)
        stats["unresolved_keys"] += len(outcome.unresolved_keys)
        if outcome.missing_sources:
            stats["items_missing_a_source"] += 1
        if not outcome.proposed:
            stats["items_without_any_link"] += 1
        for p in outcome.proposed:
            row = conn.execute(
                "SELECT id, link_method FROM ticket_link WHERE ticket_id=? AND work_item_id=?",
                (p.ticket_id, p.work_item_id),
            ).fetchone()
            if row is None:
                conn.execute(
                    """INSERT INTO ticket_link (ticket_id, work_item_id, link_method,
                                                confidence, detected_at)
                       VALUES (?,?,?,?,?)""",
                    (p.ticket_id, p.work_item_id, p.link_method, p.confidence, detected_at),
                )
                stats["inserted"] += 1
            elif _METHOD_RANK[p.link_method] > _METHOD_RANK.get(row[1], 0):
                conn.execute(
                    "UPDATE ticket_link SET link_method=?, confidence=?, detected_at=? WHERE id=?",
                    (p.link_method, p.confidence, detected_at, row[0]),
                )
                stats["upgraded"] += 1
            else:
                stats["unchanged"] += 1
    return stats


# ---------------------------------------------------------------------------
# 3. The sprint gate
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    passed: bool
    reason: str                                     # machine-readable
    detail: str                                     # one human-readable line
    ticket_keys: list[str] = field(default_factory=list)
    passing_ticket_key: Optional[str] = None
    ticket_status: Optional[str] = None             # of the passing ticket
    sprint_name: Optional[str] = None
    sprint_state: Optional[str] = None
    link_confidence: Optional[str] = None


def sprint_gate(conn: sqlite3.Connection, work_item_id: int) -> GateResult:
    """Does this work item correspond to live sprint work?

    Passes when AT LEAST ONE linked ticket is (a) in a sprint the source
    itself calls 'active' and (b) not in a parked status category.

    "At least one" rather than "all", deliberately. A PR whose branch
    names an active-sprint ticket and whose title also mentions a parked
    epic is not parked work — somebody is doing it right now. Requiring
    every link to pass would let one stray mention silence a real alert,
    which is a coverage loss with no precision gain.

    A ticket whose category is 'done' does NOT suppress. The team saying
    the ticket is finished does not make the pull request merged; if
    anything an approved, unmerged PR under a Done ticket is the exact
    shape of work that gets forgotten. The ticket's status is carried
    into the evidence line so a human reading the digest sees it.

    `sprint.state` is the source's own three-valued read, never inferred
    from dates here (schema section 11's own rule).
    """
    rows = conn.execute(
        """SELECT t.source_key, t.status_category, t.source_status,
                  s.name, s.state, tl.confidence
           FROM ticket_link tl
           JOIN ticket t ON t.id = tl.ticket_id
           LEFT JOIN sprint s ON s.id = t.sprint_id
           WHERE tl.work_item_id = ?
           ORDER BY t.source_key""",
        (work_item_id,),
    ).fetchall()

    if not rows:
        # Not "no ticket exists" — "we could not establish one". Reported
        # under its own reason because the fix is an integration fix
        # (branch names, commit messages, an API link at 6.9), not a
        # detection-logic fix, and the two must not be counted together.
        return GateResult(False, "no_ticket_link",
                          "no Jira/Linear ticket could be linked to this item")

    keys = [r[0] for r in rows]
    rejected: list[str] = []
    for key, category, source_status, sprint_name, sprint_state, link_conf in rows:
        if category in PARKED_STATUS_CATEGORIES:
            rejected.append(f"{key} is '{source_status}' ({category})")
            continue
        if sprint_name is None:
            rejected.append(f"{key} is in no sprint")
            continue
        if sprint_state != "active":
            rejected.append(f"{key} is in {sprint_name} (state={sprint_state})")
            continue
        return GateResult(
            True, "active_sprint",
            f"{key} is '{source_status}' in {sprint_name} (active)",
            ticket_keys=keys, passing_ticket_key=key, ticket_status=source_status,
            sprint_name=sprint_name, sprint_state=sprint_state, link_confidence=link_conf,
        )

    return GateResult(False, "not_active_sprint_work",
                      "; ".join(rejected), ticket_keys=keys)


# ---------------------------------------------------------------------------
# 4. Small reads
# ---------------------------------------------------------------------------

def item_observed_at(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    """The observed_at of the snapshot THIS item belongs to.

    detectors.py reads `SELECT DISTINCT observed_at FROM snapshot` and
    takes the first row, which is safe in a single-source Part I database
    and is not safe here: a Part II database holds a GitHub snapshot, a
    Jira snapshot and a Linear snapshot, each with its own observed_at.
    Every clock in this module is anchored to the item's own snapshot
    (D-064's rule — a frozen observation time, never wall-clock now).
    """
    row = conn.execute(
        "SELECT s.observed_at FROM work_item w JOIN snapshot s ON s.id=w.snapshot_id WHERE w.id=?",
        (work_item_id,),
    ).fetchone()
    return row[0] if row else None


def item_key(conn: sqlite3.Connection, work_item_id: int) -> str:
    row = conn.execute(
        """SELECT p.source_key, w.source_number FROM work_item w
           JOIN project p ON p.id = w.project_id WHERE w.id=?""",
        (work_item_id,),
    ).fetchone()
    return f"{row[0]}#{row[1]}" if row else f"item:{work_item_id}"


def actor_login(conn: sqlite3.Connection, actor_id: Optional[int]) -> str:
    if actor_id is None:
        return "unknown"
    row = conn.execute("SELECT source_key FROM actor WHERE id=?", (actor_id,)).fetchone()
    return row[0] if row else f"actor:{actor_id}"


def item_confidence(conn: sqlite3.Connection, work_item_id: int) -> str:
    row = conn.execute(
        "SELECT confidence FROM v_item_confidence WHERE work_item_id=?", (work_item_id,)
    ).fetchone()
    return row[0] if row else "high"


def _last_human_activity(conn: sqlite3.Connection, work_item_id: int) -> tuple[Optional[str], bool]:
    """(timestamp, is_lower_bound) over human events with a real date.

    Read from `event` rather than v_item_clock for one reason only: the
    view's days_silent is an integer cast, and this module needs hours.
    The selection rule is identical to the view's."""
    row = conn.execute(
        """SELECT MAX(occurred_at),
                  MAX(CASE WHEN date_precision <> 'exact' THEN 1 ELSE 0 END)
           FROM event
           WHERE work_item_id=? AND counts_as_human=1 AND occurred_at IS NOT NULL""",
        (work_item_id,),
    ).fetchone()
    return (row[0], bool(row[1])) if row else (None, False)


def _reviewer_last_action(conn: sqlite3.Connection, work_item_id: int,
                          actor_id: int) -> tuple[Optional[str], bool]:
    row = conn.execute(
        """SELECT MAX(occurred_at),
                  MAX(CASE WHEN date_precision <> 'exact' THEN 1 ELSE 0 END)
           FROM event
           WHERE work_item_id=? AND actor_id=? AND counts_as_human=1
             AND occurred_at IS NOT NULL""",
        (work_item_id, actor_id),
    ).fetchone()
    return (row[0], bool(row[1])) if row else (None, False)


# ---------------------------------------------------------------------------
# 5. The result shape
# ---------------------------------------------------------------------------

@dataclass
class FilterResult:
    work_item_id: int
    item_key: str
    outcome: str                       # FIRE | SUPPRESSED | ABSTAIN
    pattern: Optional[str]             # the pattern this outcome is about
    reason: str                        # machine-readable, always set
    # The other pattern's verdict on the same item. Only ever set when both
    # patterns abstained: the item-level `reason` is then one of two true
    # statements, and hiding the other one would make the ABSTAIN breakdown
    # read as though a P2-shaped item failed a P1 test.
    alt_pattern: Optional[str] = None
    alt_reason: Optional[str] = None
    next_actor: Optional[str] = None
    hours_idle: Optional[float] = None
    evidence: str = ""
    ticket_keys: list[str] = field(default_factory=list)
    ticket_status: Optional[str] = None
    sprint_name: Optional[str] = None
    sprint_state: Optional[str] = None
    link_confidence: Optional[str] = None
    is_lower_bound: bool = False
    confidence: str = "high"           # v_item_confidence — evidence completeness

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["hours_idle"] = None if self.hours_idle is None else round(self.hours_idle, 1)
        return d


def _abstain(conn, wid, pattern, reason) -> FilterResult:
    return FilterResult(work_item_id=wid, item_key=item_key(conn, wid), outcome=ABSTAIN,
                        pattern=pattern, reason=reason, confidence=item_confidence(conn, wid))


def _apply_gate(conn: sqlite3.Connection, wid: int, pattern: str, next_actor: str,
                hours_idle: float, is_lower_bound: bool, evidence: str) -> FilterResult:
    """The pattern shape matched in full. The gate is the last word."""
    g = sprint_gate(conn, wid)
    return FilterResult(
        work_item_id=wid, item_key=item_key(conn, wid),
        outcome=FIRE if g.passed else SUPPRESSED,
        pattern=pattern, reason=g.reason, next_actor=next_actor,
        hours_idle=hours_idle,
        evidence=f"{evidence}; {g.detail}",
        ticket_keys=g.ticket_keys, ticket_status=g.ticket_status,
        sprint_name=g.sprint_name, sprint_state=g.sprint_state,
        link_confidence=g.link_confidence, is_lower_bound=is_lower_bound,
        confidence=item_confidence(conn, wid),
    )


# ---------------------------------------------------------------------------
# 6. Pattern 1 — approved, CI green, still unmerged, idle > 48h
# ---------------------------------------------------------------------------

def evaluate_p1(conn: sqlite3.Connection, work_item_id: int) -> FilterResult:
    wid = work_item_id
    row = conn.execute(
        "SELECT kind, state, is_draft FROM work_item WHERE id=?", (wid,)
    ).fetchone()
    if row is None:
        return _abstain(conn, wid, P1, "no_such_item")
    kind, state, is_draft = row
    if kind != "change_request":
        return _abstain(conn, wid, P1, "not_a_pull_request")
    if state != "open":
        return _abstain(conn, wid, P1, "not_open")
    if is_draft:
        return _abstain(conn, wid, P1, "draft")

    # The LATEST review must be the approval. An approval followed by a
    # later changes_requested is not an approved PR — S-01 already made
    # this call in Part I and it is inherited unchanged.
    latest = conn.execute(
        """SELECT state, actor_id, submitted_at FROM review
           WHERE work_item_id=? AND submitted_at IS NOT NULL
           ORDER BY submitted_at DESC LIMIT 1""",
        (wid,),
    ).fetchone()
    if latest is None:
        return _abstain(conn, wid, P1, "never_reviewed")
    if latest[0] != "approved":
        return _abstain(conn, wid, P1, f"latest_review_is_{latest[0]}")
    _, approver_id, approved_at = latest

    # CI green is a positive requirement: 'unknown' does not satisfy it.
    rd = conn.execute(
        "SELECT merge_state, checks_state FROM readiness WHERE work_item_id=?", (wid,)
    ).fetchone()
    merge_state, checks_state = (rd if rd else ("unknown", "unknown"))
    if checks_state != "clean":
        return _abstain(conn, wid, P1, f"ci_not_known_green ({checks_state})")
    # A merge conflict is a suppressor (H4): 'unknown' does not suppress.
    if merge_state == "blocked":
        return _abstain(conn, wid, P1, "merge_conflict")

    last_at, lower_bound = _last_human_activity(conn, wid)
    obs = item_observed_at(conn, wid)
    idle = hours_between(obs, last_at) if last_at else hours_between(obs, approved_at)
    if idle is None:
        return _abstain(conn, wid, P1, "no_readable_clock")
    if idle <= IDLE_HOURS:
        return _abstain(conn, wid, P1, f"idle_only_{idle:.1f}h")

    return _apply_gate(
        conn, wid, P1, actor_login(conn, approver_id), idle, lower_bound,
        f"approved by {actor_login(conn, approver_id)} on {approved_at}; CI green; "
        f"still open and unmerged; no human activity for {idle:.1f}h",
    )


# ---------------------------------------------------------------------------
# 7. Pattern 2 — review requested of a named person, no response in 48h
# ---------------------------------------------------------------------------

def evaluate_p2(conn: sqlite3.Connection, work_item_id: int) -> FilterResult:
    wid = work_item_id
    row = conn.execute(
        "SELECT kind, state, is_draft FROM work_item WHERE id=?", (wid,)
    ).fetchone()
    if row is None:
        return _abstain(conn, wid, P2, "no_such_item")
    kind, state, is_draft = row
    if kind != "change_request":
        return _abstain(conn, wid, P2, "not_a_pull_request")
    if state != "open":
        return _abstain(conn, wid, P2, "not_open")
    if is_draft:
        return _abstain(conn, wid, P2, "draft")

    obs = item_observed_at(conn, wid)

    # origin='codeowners' is excluded by D-043: an automatic request is
    # not a promise anybody made. A withdrawn request is not live evidence.
    reqs = conn.execute(
        """SELECT actor_id, MAX(requested_at) FROM review_request
           WHERE work_item_id=? AND actor_id IS NOT NULL AND origin='manual'
             AND removed_at IS NULL AND requested_at IS NOT NULL
           GROUP BY actor_id""",
        (wid,),
    ).fetchall()
    if not reqs:
        return _abstain(conn, wid, P2, "no_live_manual_review_request")

    # Part I's S-04 emitted one detection PER REVIEWER while every verdict
    # it was scored against was per item — a mismatch named in D-083 as a
    # real cause of inflated counts. Fixed here: one result per item,
    # about the reviewer who has been silent longest.
    ghosted: list[tuple[float, int, str, bool]] = []
    responded = 0
    for actor_id, requested_at in reqs:
        last_action, lower_bound = _reviewer_last_action(conn, wid, actor_id)
        if last_action is not None and last_action >= requested_at:
            responded += 1
            continue
        waited = hours_between(obs, requested_at)
        if waited is None:
            continue
        ghosted.append((waited, actor_id, requested_at, lower_bound))

    if not ghosted:
        return _abstain(conn, wid, P2,
                        "every_requested_reviewer_responded" if responded
                        else "no_readable_clock")

    ghosted.sort(reverse=True)
    waited, actor_id, requested_at, lower_bound = ghosted[0]
    if waited <= IDLE_HOURS:
        return _abstain(conn, wid, P2, f"waited_only_{waited:.1f}h")

    # H6, inherited from S-04: if somebody else has approved since the
    # request, the PR is not waiting on this reviewer to move — chasing
    # them would be a false alarm. Added deliberately; it is a condition
    # the 6.4 brief did not list, and it only ever makes the pipeline
    # quieter, never louder.
    other_approval = conn.execute(
        """SELECT COUNT(*) FROM review
           WHERE work_item_id=? AND state='approved' AND actor_id != ?
             AND submitted_at IS NOT NULL AND submitted_at > ?""",
        (wid, actor_id, requested_at),
    ).fetchone()[0]
    if other_approval > 0:
        return _abstain(conn, wid, P2, "another_reviewer_approved_since")

    return _apply_gate(
        conn, wid, P2, actor_login(conn, actor_id), waited, lower_bound,
        f"review requested from {actor_login(conn, actor_id)} on {requested_at} "
        f"(manual, not CODEOWNERS); no review or comment from them in {waited:.1f}h",
    )


# ---------------------------------------------------------------------------
# 8. The pipeline
# ---------------------------------------------------------------------------

def _better(a: FilterResult, b: FilterResult) -> FilterResult:
    """FIRE beats SUPPRESSED beats ABSTAIN; P1 wins an exact tie.

    P1 first because it is the more actionable of the two: 'this is
    approved, press merge' is a smaller ask than 'go review this'.
    """
    if a.outcome == ABSTAIN and b.outcome == ABSTAIN and a.reason != b.reason:
        a.alt_pattern, a.alt_reason = b.pattern, b.reason
        return a
    if _OUTCOME_RANK[a.outcome] >= _OUTCOME_RANK[b.outcome]:
        return a
    return b


def run_pipeline(conn: sqlite3.Connection,
                 work_item_ids: Optional[Iterable[int]] = None) -> list[FilterResult]:
    """One FilterResult per work item — never zero, never two.

    Items are not filtered down to "interesting" ones first. Every item
    considered is accounted for by name, including the ones that abstain,
    because a pipeline whose default is silence has to be able to show
    what it was silent about and why.
    """
    if work_item_ids is None:
        ids = [r[0] for r in conn.execute("SELECT id FROM work_item ORDER BY id")]
    else:
        ids = list(work_item_ids)

    results = []
    for wid in ids:
        results.append(_better(evaluate_p1(conn, wid), evaluate_p2(conn, wid)))
    return results


def summarise(results: list[FilterResult]) -> dict:
    """The counts Phase 6's kill criterion will eventually be read off.

    `suppressed_by_reason` is the number that matters most right now: it
    is a direct count of the alerts Part I would have sent and Part II
    does not, broken down by why.
    """
    summary = {
        "items": len(results),
        FIRE: 0, SUPPRESSED: 0, ABSTAIN: 0,
        "fired_by_pattern": {},
        "suppressed_by_reason": {},
        "abstained_by_reason": {},
    }
    for r in results:
        summary[r.outcome] += 1
        if r.outcome == FIRE:
            summary["fired_by_pattern"][r.pattern] = \
                summary["fired_by_pattern"].get(r.pattern, 0) + 1
        elif r.outcome == SUPPRESSED:
            summary["suppressed_by_reason"][r.reason] = \
                summary["suppressed_by_reason"].get(r.reason, 0) + 1
        else:
            # Both patterns' reasons, when they differ. Counting a
            # P2-shaped item under P1's reason alone would make this
            # breakdown quietly wrong about why the pipeline was silent,
            # and this breakdown is the only record of that.
            key = r.reason if not r.alt_reason else f"{r.reason} / {r.alt_reason}"
            summary["abstained_by_reason"][key] = \
                summary["abstained_by_reason"].get(key, 0) + 1
    return summary
