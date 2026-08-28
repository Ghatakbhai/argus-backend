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

# --- Phase 7.4X ------------------------------------------------------------
# P3 and P4 both use a 24-hour threshold rather than P1/P2's 48, from the
# execution plan's own wording. The shorter clock is defensible here and not
# in P1/P2 for a specific reason: P1/P2 are asking a busy human to do work,
# so two days of silence is the politeness floor. P3 is reporting a
# CONTRADICTION between two systems of record, and P4 is reporting a fact
# (someone is on holiday) that no amount of waiting will change. Neither
# improves by being left another day.
GHOST_IDLE_HOURS = 24.0

# P4's second trigger: a sprint/cycle boundary close enough that "we'll sort
# it when they're back" is no longer an option.
OOO_SPRINT_HOURS = 48.0

# Case A's "the ticket is still live work" vocabulary.
#
# `docs/PHASE7_4X_EXECUTION_PLAN.md` §1.2 also lists 'backlog' here; the
# kickoff message that authorised the build does not. The kickoff message is
# followed, and the plan is corrected rather than the code bent to fit it
# (this project's standing habit, D-169/D-172): 'backlog' is a PARKED
# category, so a backlog ticket can never pass the sprint gate — including it
# would only ever manufacture SUPPRESSED rows nobody sees, while implying a
# coverage this pattern does not have. Recorded as a correction, not a
# silent deviation.
GHOST_ACTIVE_CATEGORIES = frozenset({"in_progress", "in_review", "ready"})

P1 = "P1-approved-unmerged"
P2 = "P2-review-ghosted"
P3 = "P3-ghost-state"
P4 = "P4-reviewer-ooo-sprint-end"

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
    sprint_ends_at: Optional[str] = None            # Phase 7.4X — P4 reads this
    link_confidence: Optional[str] = None


def sprint_gate(conn: sqlite3.Connection, work_item_id: int,
                only_ticket_key: Optional[str] = None) -> GateResult:
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

    `only_ticket_key` (Phase 7.4X) narrows the gate to ONE named ticket.
    P1/P2 never pass it and are unaffected. P3/P4 do, because those patterns
    are *about* a specific ticket — the one whose state contradicts the pull
    request's. Letting the default "at least one linked ticket passes" rule
    stand for them would allow a second, unrelated ticket in an active sprint
    to wave through an alert about a ticket that is in no sprint at all, and
    the digest line would then name a sprint the drifting ticket is not in.
    """
    sql = """SELECT t.source_key, t.status_category, t.source_status,
                    s.name, s.state, tl.confidence, s.ends_at
             FROM ticket_link tl
             JOIN ticket t ON t.id = tl.ticket_id
             LEFT JOIN sprint s ON s.id = t.sprint_id
             WHERE tl.work_item_id = ?"""
    params: list = [work_item_id]
    if only_ticket_key is not None:
        sql += " AND UPPER(t.source_key) = ?"
        params.append(only_ticket_key.upper())
    rows = conn.execute(sql + " ORDER BY t.source_key", tuple(params)).fetchall()

    if not rows:
        # Not "no ticket exists" — "we could not establish one". Reported
        # under its own reason because the fix is an integration fix
        # (branch names, commit messages, an API link at 6.9), not a
        # detection-logic fix, and the two must not be counted together.
        return GateResult(False, "no_ticket_link",
                          "no Jira/Linear ticket could be linked to this item")

    keys = [r[0] for r in rows]
    rejected: list[str] = []
    for (key, category, source_status, sprint_name, sprint_state,
         link_conf, sprint_ends_at) in rows:
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
            sprint_name=sprint_name, sprint_state=sprint_state,
            sprint_ends_at=sprint_ends_at, link_confidence=link_conf,
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
    # Phase 7.4X: with four patterns, "the other one's reason" is no longer a
    # single fact. `alt_pattern`/`alt_reason` keep their original meaning (the
    # next-ranked pattern whose reason DIFFERS, which is what the ABSTAIN
    # breakdown is keyed on); `all_reasons` carries the complete per-pattern
    # picture for anyone reading one row in the audit drawer, so nothing is
    # lost to the summary's need for a short key.
    all_reasons: dict = field(default_factory=dict)
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
                hours_idle: float, is_lower_bound: bool, evidence: str,
                only_ticket_key: Optional[str] = None) -> FilterResult:
    """The pattern shape matched in full. The gate is the last word."""
    g = sprint_gate(conn, wid, only_ticket_key=only_ticket_key)
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
# 7b. Pattern 3 — Ghost State: GitHub and the ticket board disagree
#     (Phase 7.4X, Task 1. Deterministic. No LLM, no write-back.)
# ---------------------------------------------------------------------------
#
# WHAT THIS PATTERN IS FOR
# ------------------------
# P1 and P2 both answer "who owes a move on this pull request?". P3 answers a
# different question entirely: "do our two systems of record still agree with
# each other?" Nobody is being chased here — the work may well be finished.
# What is broken is the RECORD of it, and a wrong record is what makes a
# stand-up ask a question everyone already knows the answer to.
#
# Two shapes, and they are deliberately not symmetrical:
#
#   Case A — the PR is merged, the linked ticket is still live work.
#            The code shipped and nobody moved the card. This is the common
#            one, and the cheapest to fix.
#   Case B — the ticket says done, the PR is still open.
#            More alarming: somebody closed the ticket believing the change
#            was in, and it is not.
#
# WHY `closed_at` AND NOT `merged_at`
# -----------------------------------
# `docs/PHASE7_4X_EXECUTION_PLAN.md` §1.2 asks for `(now - merged_at) > 24h`.
# There is no `merged_at` column in this schema and never has been —
# `work_item` (schema.sql) carries `state` and `closed_at`, and GitHub sets
# the latter when a pull request is merged. `closed_at` on a row whose state
# is 'merged' IS the merge time. Corrected here rather than a column
# invented, same treatment D-169 gave the CI-status column and D-172 gave the
# ticket-description field the milestone document assumed existed.
#
# WHY AN UNREADABLE MERGE DATE ABSTAINS RATHER THAN FALLING BACK
# --------------------------------------------------------------
# A merged PR with no readable `closed_at` could have merged five minutes ago
# or five months ago. Falling back to another clock (created_at, the last
# event) would answer a question this row cannot answer, in the direction
# that produces an alert. Phase 2 made this project's whole three-valued
# readiness vocabulary to stop exactly that (D-031/D-037/D-042); the same
# rule applies to a clock. An unknown is never converted into a claim.


def _ghost_candidates(conn: sqlite3.Connection, work_item_id: int) -> list[tuple]:
    """(ticket_key, status_category, source_status, source_name) per linked
    ticket, ordered by key so the choice below is deterministic."""
    return conn.execute(
        """SELECT t.source_key, t.status_category, t.source_status, src.name
           FROM ticket_link tl
           JOIN ticket t ON t.id = tl.ticket_id
           JOIN source src ON src.id = t.source_id
           WHERE tl.work_item_id = ?
           ORDER BY t.source_key""",
        (work_item_id,),
    ).fetchall()


def evaluate_p3(conn: sqlite3.Connection, work_item_id: int,
                now: Optional[str] = None) -> FilterResult:
    """Phase 7.4X Task 1.1/1.2.

    `now` defaults to this item's own snapshot `observed_at`, never to
    wall-clock time — D-064's frozen-observation rule, the same anchor P1 and
    P2 use. The parameter exists because the execution plan's own signature
    names it and because a test needs to be able to move the clock without
    rewriting a snapshot row; it is not an invitation to pass `datetime.now()`.
    """
    wid = work_item_id
    row = conn.execute(
        "SELECT kind, state, is_draft, closed_at, created_at FROM work_item WHERE id=?", (wid,)
    ).fetchone()
    if row is None:
        return _abstain(conn, wid, P3, "no_such_item")
    kind, state, is_draft, closed_at, created_at = row
    if kind != "change_request":
        return _abstain(conn, wid, P3, "not_a_pull_request")

    obs = now or item_observed_at(conn, wid)
    if obs is None:
        return _abstain(conn, wid, P3, "no_readable_clock")

    links = _ghost_candidates(conn, wid)
    if not links:
        # Same distinction sprint_gate draws: this is "we could not establish
        # a ticket", an integration gap, not "the team's board is fine".
        return _abstain(conn, wid, P3, "no_ticket_link")

    # ---- Case A: merged on GitHub, still open work on the board -----------
    if state == "merged":
        if not closed_at:
            return _abstain(conn, wid, P3, "merged_without_a_readable_date")
        merged_ago = hours_between(obs, closed_at)
        if merged_ago is None:
            return _abstain(conn, wid, P3, "no_readable_clock")
        if merged_ago <= GHOST_IDLE_HOURS:
            return _abstain(conn, wid, P3, f"merged_only_{merged_ago:.1f}h_ago")
        drifting = [l for l in links if l[1] in GHOST_ACTIVE_CATEGORIES]
        if not drifting:
            return _abstain(conn, wid, P3, "no_linked_ticket_still_active")
        key, _category, source_status, source_name = drifting[0]
        return _apply_gate(
            conn, wid, P3, actor_login(conn, _item_author_id(conn, wid)),
            merged_ago, False,
            f"pull request was merged on GitHub {merged_ago:.1f}h ago, but "
            f"{key} is still '{source_status}' in {source_name}",
            only_ticket_key=key,
        )

    # ---- Case B: the board says done, the PR is still open ---------------
    if state == "open":
        if is_draft:
            return _abstain(conn, wid, P3, "draft")
        drifting = [l for l in links if l[1] == "done"]
        if not drifting:
            return _abstain(conn, wid, P3, "no_linked_ticket_marked_done")
        last_at, lower_bound = _last_human_activity(conn, wid)
        idle = hours_between(obs, last_at or created_at)
        if idle is None:
            return _abstain(conn, wid, P3, "no_readable_clock")
        if idle <= GHOST_IDLE_HOURS:
            return _abstain(conn, wid, P3, f"idle_only_{idle:.1f}h")
        key, _category, source_status, source_name = drifting[0]
        return _apply_gate(
            conn, wid, P3, actor_login(conn, _item_author_id(conn, wid)),
            idle, lower_bound,
            f"{key} is marked '{source_status}' (done) in {source_name}, but the "
            f"pull request is still open and has been idle for {idle:.1f}h",
            only_ticket_key=key,
        )

    return _abstain(conn, wid, P3, f"state_is_{state}")


# ---------------------------------------------------------------------------
# 7c. Pattern 4 — a requested reviewer is out of office and the cycle is
#     about to close (Phase 7.4X, Task 2. Deterministic.)
# ---------------------------------------------------------------------------
#
# HOW THIS DIFFERS FROM P2, AND WHY IT OUTRANKS IT
# ------------------------------------------------
# P2 says "this review has been sitting for two days." P4 says "this review
# has been sitting for two days, the person it is sitting with is on holiday
# until Thursday, and the cycle closes tomorrow morning." Both are true of
# the same pull request; only the second one tells a lead what to do about
# it. So P4 outranks P2 in the pipeline's precedence (see `_PATTERN_RANK`) —
# strictly more context about identically the same silence.
#
# WHY THE ALERT IS ADDRESSED TO THE AUTHOR, NOT THE ABSENT REVIEWER
# -----------------------------------------------------------------
# `next_actor` is who ARGUS would DM. Addressing this one to the reviewer
# would send a nudge to a person whose defining property in this pattern is
# that they are not reading it — and 6.7's presence check would (correctly)
# hold it until they are back, which is precisely the delay the pattern
# exists to warn about. The author is the person actually blocked and the one
# who can ask for a second reviewer, so the alert goes to them. Named here
# because the execution plan's §2.3 sample text ("Reviewer @sarah is OOO…")
# describes the message BODY and is silent on the recipient; this is a
# decision made, not a detail inherited.
#
# WHY PRESENCE IS QUERIED HERE INSTEAD OF CALLING `presence.presence_at()`
# -----------------------------------------------------------------------
# `presence.py` imports `slack_triage`, which imports this module. Importing
# `presence` here would close that loop into a circular import. The query
# below is `presence_at`'s own SQL, unchanged, with a comment on both sides
# saying so — a deliberate, documented duplication in preference to
# restructuring three signed-off modules for one detector.


def _item_author_id(conn: sqlite3.Connection, work_item_id: int) -> Optional[int]:
    row = conn.execute("SELECT author_id FROM work_item WHERE id=?", (work_item_id,)).fetchone()
    return row[0] if row else None


def _presence_status_at(conn: sqlite3.Connection, actor_id: int, at: str) -> tuple:
    """(status, effective_to). Byte-for-byte the interval selection
    `presence.presence_at()` performs — see this section's docstring for why
    it is duplicated rather than imported. 'unknown' when no interval covers
    the moment: never guessed, never carried forward from an expired one."""
    row = conn.execute(
        """SELECT status, effective_to FROM presence
           WHERE actor_id = ? AND effective_from <= ?
             AND (effective_to IS NULL OR effective_to > ?)
           ORDER BY effective_from DESC, id DESC LIMIT 1""",
        (actor_id, at, at)).fetchone()
    return (row[0], row[1]) if row else ("unknown", None)


def evaluate_p4(conn: sqlite3.Connection, work_item_id: int,
                now: Optional[str] = None) -> FilterResult:
    """Phase 7.4X Task 2.1/2.2/2.3.

    Fires when an open pull request has a live, manual review request
    outstanding against someone Slack says is out of office, AND either the
    linked sprint/cycle ends within 48 hours or the request has been idle
    more than 24. Same `now` rule as `evaluate_p3`.
    """
    wid = work_item_id
    row = conn.execute(
        "SELECT kind, state, is_draft FROM work_item WHERE id=?", (wid,)
    ).fetchone()
    if row is None:
        return _abstain(conn, wid, P4, "no_such_item")
    kind, state, is_draft = row
    if kind != "change_request":
        return _abstain(conn, wid, P4, "not_a_pull_request")
    if state != "open":
        return _abstain(conn, wid, P4, "not_open")
    if is_draft:
        return _abstain(conn, wid, P4, "draft")

    obs = now or item_observed_at(conn, wid)
    if obs is None:
        return _abstain(conn, wid, P4, "no_readable_clock")

    # Identical selection to P2's: automatic (CODEOWNERS) requests are not a
    # promise anybody made (D-043), and a withdrawn request is not live.
    reqs = conn.execute(
        """SELECT actor_id, MAX(requested_at) FROM review_request
           WHERE work_item_id=? AND actor_id IS NOT NULL AND origin='manual'
             AND removed_at IS NULL AND requested_at IS NOT NULL
           GROUP BY actor_id""",
        (wid,),
    ).fetchall()
    if not reqs:
        return _abstain(conn, wid, P4, "no_live_manual_review_request")

    away: list[tuple[float, int, str, Optional[str]]] = []
    responded = 0
    for actor_id, requested_at in reqs:
        last_action, _lb = _reviewer_last_action(conn, wid, actor_id)
        if last_action is not None and last_action >= requested_at:
            responded += 1
            continue
        status, effective_to = _presence_status_at(conn, actor_id, obs)
        if status != "out_of_office":
            continue
        waited = hours_between(obs, requested_at)
        if waited is None:
            continue
        away.append((waited, actor_id, requested_at, effective_to))

    if not away:
        if responded == len(reqs):
            return _abstain(conn, wid, P4, "every_requested_reviewer_responded")
        return _abstain(conn, wid, P4, "no_pending_reviewer_is_out_of_office")

    # One result per item, about the reviewer who has been waited on longest
    # — the same per-item (not per-reviewer) discipline D-083 forced on P2.
    away.sort(reverse=True)
    waited, actor_id, requested_at, effective_to = away[0]

    # H6, inherited from P2/S-04: somebody else approving since the request
    # means the PR is not waiting on the absent reviewer at all.
    other_approval = conn.execute(
        """SELECT COUNT(*) FROM review
           WHERE work_item_id=? AND state='approved' AND actor_id != ?
             AND submitted_at IS NOT NULL AND submitted_at > ?""",
        (wid, actor_id, requested_at),
    ).fetchone()[0]
    if other_approval > 0:
        return _abstain(conn, wid, P4, "another_reviewer_approved_since")

    g = sprint_gate(conn, wid)
    hours_remaining = hours_between(g.sprint_ends_at, obs) if g.sprint_ends_at else None
    sprint_closing = hours_remaining is not None and 0 <= hours_remaining <= OOO_SPRINT_HOURS
    request_idle = waited > GHOST_IDLE_HOURS
    if not (sprint_closing or request_idle):
        # Neither leg of the OR is met: they are away, but there is still
        # room in the cycle and the request is fresh. Deliberately silent.
        return _abstain(
            conn, wid, P4,
            f"not_urgent (waited_{waited:.1f}h, "
            + (f"sprint_ends_in_{hours_remaining:.1f}h)" if hours_remaining is not None
               else "no_sprint_end_date)"))

    reviewer = actor_login(conn, actor_id)
    until = f" until {effective_to}" if effective_to else " (return date unknown)"
    if hours_remaining is not None:
        cycle = (f"{g.sprint_name} ends in {hours_remaining:.0f}h"
                 if g.sprint_name else f"the cycle ends in {hours_remaining:.0f}h")
    else:
        cycle = "no cycle end date is recorded"
    evidence = (f"review requested from {reviewer} on {requested_at} (manual, not "
                f"CODEOWNERS) and unanswered for {waited:.1f}h; {reviewer} is marked "
                f"out of office on Slack{until}; {cycle}. Suggest assigning a backup "
                f"reviewer.")

    # The alert is addressed to the author, not the absent reviewer — see this
    # section's docstring. `actor_login(None)` answers 'unknown', which is the
    # honest value when GitHub gave us no author, and `_unreachable_rows` in
    # digest.py already knows how to report an alert with nobody to send to.
    return _apply_gate(
        conn, wid, P4, actor_login(conn, _item_author_id(conn, wid)),
        waited, False, evidence,
    )


# ---------------------------------------------------------------------------
# 8. The pipeline
# ---------------------------------------------------------------------------

# Which pattern speaks for an item when more than one reaches the same
# outcome. Ordered by how small and concrete the ask is:
#
#   P1  'this is approved — press merge'          smallest possible ask
#   P3  'the code shipped — move the card'        a bookkeeping fix
#   P4  'your reviewer is away and the cycle      an ask WITH the context
#        closes tomorrow — find a backup'          needed to act on it
#   P2  'go review this'                          the same silence as P4,
#                                                  with less to go on
#
# P4 above P2 is the load-bearing one: they can fire on the identical pull
# request for the identical reason, and P4's line is P2's line plus the two
# facts (they are away; the cycle is closing) that decide what to do. Letting
# P2 win would throw away the only part a lead could act on.
_PATTERN_RANK = {P1: 4, P3: 3, P4: 2, P2: 1}


def _pick(candidates: list[FilterResult]) -> FilterResult:
    """One result per item, chosen by outcome first and pattern rank second.

    FIRE beats SUPPRESSED beats ABSTAIN, always — the gate's verdict outranks
    any preference between patterns. `_PATTERN_RANK` only ever breaks a tie
    between two patterns that reached the SAME outcome.
    """
    ranked = sorted(candidates,
                    key=lambda r: (_OUTCOME_RANK[r.outcome], _PATTERN_RANK[r.pattern]),
                    reverse=True)
    best = ranked[0]
    best.all_reasons = {c.pattern: c.reason for c in candidates}
    if best.outcome == ABSTAIN:
        for other in ranked[1:]:
            if other.reason != best.reason:
                best.alt_pattern, best.alt_reason = other.pattern, other.reason
                break
    return best


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
        results.append(_pick([
            evaluate_p1(conn, wid),
            evaluate_p3(conn, wid),      # Phase 7.4X, Task 1
            evaluate_p4(conn, wid),      # Phase 7.4X, Task 2
            evaluate_p2(conn, wid),
        ]))
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
        # The glanceable companion to `abstained_by_reason`, added at Phase
        # 7.4X for one reason: the full key is now up to four reasons long
        # and, on a small or deliberately varied item set, nearly unique per
        # item — complete, but not something a person can read down. This
        # counts only the WINNING pattern's reason, so "why was ARGUS quiet
        # this morning" has a short answer as well as an exact one. Neither
        # replaces the other; the exact one is still the record.
        "abstained_by_primary_reason": {},
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
            # EVERY distinct reason on the row, in pattern-rank order.
            #
            # Through Phase 6 this was two reasons (P1's and P2's), because
            # there were two patterns. Phase 7.4X tried keeping it at two —
            # the winner's plus the next-ranked different one — and that
            # quietly made this breakdown WORSE than it had been: P3 ranks
            # above P2, so three items that used to be distinguishable
            # ("never_reviewed / no_live_manual_review_request",
            # ".../waited_only_12.0h") all collapsed into one
            # "never_reviewed / no_linked_ticket_marked_done" bucket, and
            # the specific fact about each of them stopped being counted
            # anywhere. This breakdown is the only record of what the
            # pipeline was silent about; a shorter key is not worth a less
            # true one. Cardinality is bounded by the combinations that
            # actually occur, not by the number of items.
            key = " / ".join(dict.fromkeys(
                r.all_reasons[p] for p in sorted(r.all_reasons,
                                                 key=lambda x: -_PATTERN_RANK[x])
            )) if r.all_reasons else r.reason
            summary["abstained_by_reason"][key] = \
                summary["abstained_by_reason"].get(key, 0) + 1
            summary["abstained_by_primary_reason"][r.reason] = \
                summary["abstained_by_primary_reason"].get(r.reason, 0) + 1
    return summary
