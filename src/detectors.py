"""
ARGUS -- Stall pattern detectors (Phase 3.2)

One function per active stall pattern from the Phase 1 catalogue
(docs/PHASE1_STALL_PATTERN_CATALOGUE.md), built directly on the Phase 2
snapshot and the Phase 3.1 entity graph (src/entity_graph.py). S-07 is
not implemented -- it was dropped from the active catalogue at step 1.3
(D-040) and is not one of the nine patterns Phase 3 measures.

Every detector follows the same shape, mirroring the labelling rubric's
own gates (docs/PHASE1_LABELLING_RUBRIC.md SS3) so a detector's "why did
this fire / not fire" is auditable against the same procedure a human
labeller followed:

    1. Find candidates that carry the pattern's declared EVIDENCE
       (docs/PHASE2_1_DATA_MODEL.md SS6.1). No evidence -> not a
       candidate at all, nothing is reported (mirrors Gate 1/2).
    2. Check the declared SUPPRESSORS for that pattern
       (SS6.2, and the catalogue's own per-pattern "Suppressors" row).
       A suppressor present -> the candidate is recorded but not fired.
    3. Check the THRESHOLD on the correct clock -- the item's clock for
       an anyone's-activity pattern, or the named person's own clock for
       a per-person pattern (D-020) -- read from the Phase 2.1 views
       (v_item_clock / v_actor_item_clock), never recomputed by hand,
       so "how many days" always means what D-064 says it means.
    4. FIRED = evidence present, over threshold, no suppressor present.

Every candidate (fired or not) is returned as a Detection, not just the
fired ones -- so the near-misses and the suppressed ones stay visible
for the write-up and for later precision/recall work (Phase 3.3), rather
than disappearing silently.

Two structural facts about this snapshot, discovered while writing this
module, limit two suppressors -- named here, not silently routed around:

* `reference.relation` is hardcoded to `'mentions'` for every
  cross-reference the adapter records (src/ingest.py, the
  `cross-referenced` handler) -- `'blocked_by'` / `'closes'` /
  `'linked_pr'` are never distinguished. S-02's "or an open linked
  blocking item" evidence path and H3 ("an open linked blocker")
  therefore have zero rows to match against in this snapshot. Both
  detectors below only ever see the label-vocabulary evidence path.
  Not a bug to fix here -- Phase 2 is frozen and verified; noted so
  nobody reads "H3 never suppressed anything" as "no item ever had an
  open blocker."
* Reactions are never ingested despite being named in
  `docs/PHASE2_1_DATA_MODEL.md` SS6.3 as "cheap to record." No detector
  below can see a reaction-only response from an owed person.

Two patterns are known going in to be weak, per D-007 (rules-only,
no language model in Phase 3) and the data model's own SS8: **S-10**
reads prose to find a stated pending decision, and **S-09**'s only
declared evidence in this snapshot (team review requests, team
mentions) matched zero rows during Phase 3.1's graph build -- expected,
not a bug, and both are called out again below at their own detectors.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from entity_graph import EntityGraph, item_clock, actor_item_clock, item_confidence

ISO = "%Y-%m-%dT%H:%M:%SZ"


def parse_dt(s: str) -> datetime:
    return datetime.strptime(s, ISO)


def days_between(later: str, earlier: str) -> float:
    return (parse_dt(later) - parse_dt(earlier)).total_seconds() / 86400.0


# ---------------------------------------------------------------------------
# The result shape every detector returns
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    pattern: str
    work_item_id: int
    item_key: str
    severity: str
    next_actor: str
    evidence: str
    days_silent: Optional[float]
    is_lower_bound: bool
    confidence: str          # 'high' | 'low', from v_item_confidence
    fired: bool
    suppressed_by: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["days_silent"] = None if self.days_silent is None else round(self.days_silent, 1)
        return d


THRESHOLDS = {
    "S-01": 14, "S-02": 30, "S-03": 30, "S-04": 14, "S-05": 60,
    "S-06": 21, "S-08": (180, 90), "S-09": 30, "S-10": 30,
}
SEVERITY = {
    "S-01": "High", "S-02": "High", "S-03": "Medium", "S-04": "Medium",
    "S-05": "Low", "S-06": "Medium", "S-08": "Low", "S-09": "Medium", "S-10": "Medium",
}


# ---------------------------------------------------------------------------
# Small shared helpers -- thin reads, no new judgement calls
# ---------------------------------------------------------------------------

def observed_at(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT DISTINCT observed_at FROM snapshot").fetchone()
    return row[0]


def item_key(conn: sqlite3.Connection, work_item_id: int) -> str:
    row = conn.execute(
        """SELECT p.source_key, wi.source_number FROM work_item wi
           JOIN project p ON p.id = wi.project_id WHERE wi.id=?""",
        (work_item_id,),
    ).fetchone()
    return f"{row[0]}#{row[1]}" if row else f"item:{work_item_id}"


def actor_login(graph: EntityGraph, actor_id: Optional[int]) -> str:
    if actor_id is None:
        return "unknown"
    a = graph.actors.get(actor_id)
    return a.login if a else f"actor:{actor_id}"


def confidence_of(conn: sqlite3.Connection, work_item_id: int) -> str:
    c = item_confidence(conn, work_item_id)
    return c["confidence"] if c else "high"


def human_activity_after(conn: sqlite3.Connection, work_item_id: int, ts: str) -> int:
    """Count of counts_as_human=1 events strictly after ts -- the generic
    'has anyone acted since X' check the catalogue uses as evidence for
    several patterns (S-01, S-02, S-09)."""
    return conn.execute(
        """SELECT COUNT(*) FROM event
           WHERE work_item_id=? AND counts_as_human=1 AND occurred_at IS NOT NULL AND occurred_at > ?""",
        (work_item_id, ts),
    ).fetchone()[0]


# H1 -- a no-stale / pinned / keep-open style label, read from the
# Dirgh-confirmed per-project vocabulary (Q11, D-077..D-079). Only
# classification_status='confirmed' rows are trusted -- an unreviewed
# 'proposed' guess is not the "human explicitly declared this parked"
# signal H1 is supposed to be.
def h1_no_stale_label(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    row = conn.execute(
        """SELECT l.name FROM work_item_label wil JOIN label l ON l.id = wil.label_id
           WHERE wil.work_item_id=? AND wil.removed_at IS NULL
             AND l.classification='healthy_slowness' AND l.classification_status='confirmed'
           LIMIT 1""",
        (work_item_id,),
    ).fetchone()
    return row[0] if row else None


# H2 -- an open milestone. If it's still open the release hasn't
# shipped yet (an already-shipped milestone would have been closed) --
# that is the "expiry is a comparison, not a guess" rule from SS6.2.
def h2_open_milestone(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    row = conn.execute(
        """SELECT m.title FROM work_item w JOIN milestone m ON m.id = w.milestone_id
           WHERE w.id=? AND m.state='open'""",
        (work_item_id,),
    ).fetchone()
    return row[0] if row else None


# H4 -- readiness is three-valued on purpose (D-031/D-037/D-042):
# 'unknown' must never suppress, only an explicit 'blocked' does.
def h4_blocked_readiness(conn: sqlite3.Connection, work_item_id: int) -> list[str]:
    row = conn.execute(
        "SELECT merge_state, checks_state, cla_state FROM readiness WHERE work_item_id=?",
        (work_item_id,),
    ).fetchone()
    if not row:
        return []
    names = ["merge_conflict", "failing_check", "unsigned_cla"]
    return [n for n, v in zip(names, row) if v == "blocked"]


# -- Linked-item suppressors (D-081, deferred at D-092, built at D-103's
# repair). Both were named in this file's own comments as blocked on
# reference.relation always being 'mentions'; repair_references_2_5.py
# fixes that upstream of this file. Nothing here fires on a snapshot
# where every reference row is still 'mentions' (e.g. 2_3) -- these are
# strictly additive and inert on the un-repaired data.

def h_link_closed_recently(conn: sqlite3.Connection, work_item_id: int, obs: str,
                            window_days: float = 7.0) -> Optional[str]:
    """S-02's own named suppressor: 'the linked blocker closed recently
    (<7 days)'. relation='closed_by' means the linked PR's body contained
    a closing keyword for this item AND it merged -- i.e. the blocking
    work is actually done, just not yet reflected in the label."""
    rows = conn.execute(
        """SELECT r.to_work_item_id, r.to_number FROM reference r
           WHERE r.from_work_item_id=? AND r.relation='closed_by'""",
        (work_item_id,),
    ).fetchall()
    for to_wid, to_number in rows:
        closed_at = None
        if to_wid is not None:
            row = conn.execute("SELECT closed_at FROM work_item WHERE id=?", (to_wid,)).fetchone()
            closed_at = row[0] if row else None
        if closed_at is None:
            continue
        age = days_between(obs, closed_at)
        if age is not None and age < window_days:
            return f"#{to_number} closed {age:.1f}d ago"
    return None


def h_link_open_blocker(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    """H3, 'an open linked blocker': relation='blocked_by' means the
    linked PR's body contained a closing keyword for this item and that
    PR was still open at observed_at -- this item is legitimately
    waiting on it, not abandoned."""
    row = conn.execute(
        """SELECT to_number FROM reference
           WHERE from_work_item_id=? AND relation='blocked_by' LIMIT 1""",
        (work_item_id,),
    ).fetchone()
    return f"#{row[0]}" if row else None


# The blocker-vocabulary label evidence S-02 needs (SS6.1: label.classification='blocker').
def blocker_label(conn: sqlite3.Connection, work_item_id: int):
    return conn.execute(
        """SELECT l.name, wil.applied_at, wil.applied_by
           FROM work_item_label wil JOIN label l ON l.id = wil.label_id
           WHERE wil.work_item_id=? AND wil.removed_at IS NULL
             AND l.classification='blocker' AND l.classification_status='confirmed'
           ORDER BY wil.applied_at ASC LIMIT 1""",
        (work_item_id,),
    ).fetchone()


def make(pattern, wid, conn, graph, next_actor, evidence, days_silent, is_lower_bound,
         fired, suppressed_by) -> Detection:
    return Detection(
        pattern=pattern, work_item_id=wid, item_key=item_key(conn, wid),
        severity=SEVERITY[pattern], next_actor=next_actor, evidence=evidence,
        days_silent=days_silent, is_lower_bound=bool(is_lower_bound),
        confidence=confidence_of(conn, wid), fired=fired, suppressed_by=suppressed_by,
    )


# ---------------------------------------------------------------------------
# S-01 -- Approved but not merged
# ---------------------------------------------------------------------------

def detect_s01(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        "SELECT id FROM work_item WHERE kind='change_request' AND state='open' AND is_draft=0"
    ).fetchall()
    for (wid,) in rows:
        latest_review = conn.execute(
            """SELECT state, actor_id, submitted_at FROM review
               WHERE work_item_id=? AND submitted_at IS NOT NULL
               ORDER BY submitted_at DESC LIMIT 1""",
            (wid,),
        ).fetchone()
        if not latest_review or latest_review[0] != "approved":
            continue  # never approved, or a later review superseded the approval
        _, approver_id, approved_at = latest_review

        # Per the labelling rubric's own Example A (pola-rs/polars#12597):
        # periodic comments asking "what's blocking this?" do not un-stick
        # an approved-but-unmerged PR -- only merging would, and
        # state='open' already rules that out. So this is NOT "zero
        # activity ever since the approval" -- it is the item's ordinary
        # clock (time since the *most recent* human activity, whatever
        # that was), which can never predate the approval itself.
        clk = item_clock(conn, wid)
        days_silent = clk["days_silent"] if clk else days_between(obs, approved_at)

        suppressed_by = []
        stale = h1_no_stale_label(conn, wid)
        if stale:
            suppressed_by.append(f"H1: no-stale label '{stale}'")
        blocked = h4_blocked_readiness(conn, wid)
        if blocked:
            suppressed_by.append(f"H4: {', '.join(blocked)}")

        matched = days_silent is not None and days_silent >= THRESHOLDS["S-01"]
        if not matched and not suppressed_by:
            continue
        last_at = clk["last_human_at"] if clk else approved_at
        out.append(make(
            "S-01", wid, conn, graph, actor_login(graph, approver_id),
            f"approved by {actor_login(graph, approver_id)} on {approved_at}; "
            f"still open, unmerged; last human activity {last_at}",
            days_silent, clk and clk["is_lower_bound"], matched and not suppressed_by, suppressed_by,
        ))
    return out


# ---------------------------------------------------------------------------
# S-02 -- Blocked by a declared dependency
# ---------------------------------------------------------------------------

def detect_s02(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute("SELECT id FROM work_item WHERE state='open' AND is_draft=0").fetchall()
    for (wid,) in rows:
        blk = blocker_label(conn, wid)
        if not blk or blk[1] is None:
            continue
        name, applied_at, applied_by = blk

        # Same reasoning as S-01 (Example A): a comment about the blocker
        # doesn't resolve it -- only the label being removed would, and
        # `blocker_label()` already requires removed_at IS NULL. So this
        # is the item's ordinary clock, not a "zero activity ever" gate.
        clk = item_clock(conn, wid)
        days_silent = clk["days_silent"] if clk else days_between(obs, applied_at)

        suppressed_by = []
        stale = h1_no_stale_label(conn, wid)
        if stale:
            suppressed_by.append(f"H1: no-stale label '{stale}'")
        # The catalogue's other suppressor -- "the linked blocker closed
        # recently (<7 days)" -- built at D-103's repair (was previously
        # unreachable: reference.relation was never 'blocked_by'/'closed_by'
        # in this snapshot, see module docstring history).
        closed_link = h_link_closed_recently(conn, wid, obs)
        if closed_link:
            suppressed_by.append(f"H-link: linked blocker {closed_link}")

        matched = days_silent is not None and days_silent >= THRESHOLDS["S-02"]
        if not matched and not suppressed_by:
            continue
        applier = actor_login(graph, applied_by) if applied_by else "unknown"
        last_at = clk["last_human_at"] if clk else applied_at
        out.append(make(
            "S-02", wid, conn, graph, applier,
            f"labeled '{name}' (blocker vocabulary, Dirgh-confirmed) by {applier} on {applied_at}; "
            f"still applied; last human activity {last_at}",
            days_silent, clk and clk["is_lower_bound"], matched and not suppressed_by, suppressed_by,
        ))
    return out


# ---------------------------------------------------------------------------
# S-03 -- Changes requested, author never returned
# ---------------------------------------------------------------------------

def detect_s03(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        "SELECT id, author_id FROM work_item WHERE kind='change_request' AND state='open' AND is_draft=0"
    ).fetchall()
    for wid, author_id in rows:
        if author_id is None:
            continue
        latest = conn.execute(
            """SELECT state, submitted_at FROM review
               WHERE work_item_id=? AND submitted_at IS NOT NULL
               ORDER BY submitted_at DESC LIMIT 1""",
            (wid,),
        ).fetchone()
        if not latest or latest[0] != "changes_requested":
            continue
        cr_at = latest[1]

        aclk = actor_item_clock(conn, wid, author_id)
        if aclk and aclk["last_action_at"] and aclk["last_action_at"] > cr_at:
            continue  # H5: the author engaged since -- not a candidate

        days_silent = aclk["days_silent"] if aclk else days_between(obs, cr_at)
        matched = days_silent is not None and days_silent >= THRESHOLDS["S-03"]
        if not matched:
            continue
        # "Author account deleted or marked inactive" is a declared
        # suppressor this model cannot check -- account deletion isn't
        # a field anywhere in the Phase 2 schema. Named, not guessed at.
        out.append(make(
            "S-03", wid, conn, graph, actor_login(graph, author_id),
            f"latest review is changes_requested (at {cr_at}); no activity by the author since",
            days_silent, aclk and aclk["is_lower_bound"], True, [],
        ))
    return out


# ---------------------------------------------------------------------------
# S-04 -- Review requested from a named person who never responded
# ---------------------------------------------------------------------------

def detect_s04(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        """SELECT rr.work_item_id, rr.actor_id, rr.requested_at, rr.removed_at
           FROM review_request rr JOIN work_item wi ON wi.id = rr.work_item_id
           WHERE rr.actor_id IS NOT NULL AND rr.origin='manual'
             AND wi.state='open' AND wi.is_draft=0"""
    ).fetchall()
    latest: dict[tuple, tuple] = {}
    for wid, actor_id, requested_at, removed_at in rows:
        if removed_at is not None or requested_at is None:
            continue  # H4-shaped: the request itself was withdrawn -- not live evidence
        key = (wid, actor_id)
        if key not in latest or requested_at > latest[key][0]:
            latest[key] = (requested_at,)

    for (wid, actor_id), (requested_at,) in latest.items():
        rclk = actor_item_clock(conn, wid, actor_id)
        if rclk and rclk["last_action_at"] and rclk["last_action_at"] >= requested_at:
            continue  # the reviewer has responded since

        other_approval = conn.execute(
            """SELECT COUNT(*) FROM review
               WHERE work_item_id=? AND state='approved' AND actor_id != ? AND submitted_at > ?""",
            (wid, actor_id, requested_at),
        ).fetchone()[0]

        days_silent = rclk["days_silent"] if rclk else days_between(obs, requested_at)
        suppressed_by = []
        if other_approval > 0:
            suppressed_by.append("H6: another reviewer already approved")

        matched = days_silent is not None and days_silent >= THRESHOLDS["S-04"]
        if not matched and not suppressed_by:
            continue
        out.append(make(
            "S-04", wid, conn, graph, actor_login(graph, actor_id),
            f"review requested from {actor_login(graph, actor_id)} on {requested_at} "
            f"(origin=manual, not CODEOWNERS); no response from them since",
            days_silent, rclk and rclk["is_lower_bound"], matched and not suppressed_by, suppressed_by,
        ))
    return out


# ---------------------------------------------------------------------------
# S-05 -- Assigned but silent
# ---------------------------------------------------------------------------

def detect_s05(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        """SELECT a.work_item_id, a.actor_id, a.assigned_at, a.is_automatic
           FROM assignment a JOIN work_item wi ON wi.id = a.work_item_id
           WHERE wi.kind='issue' AND wi.state='open' AND a.unassigned_at IS NULL"""
    ).fetchall()
    for wid, actor_id, assigned_at, is_auto in rows:
        if assigned_at is None:
            continue
        aclk = actor_item_clock(conn, wid, actor_id)
        if aclk and aclk["last_action_at"] and aclk["last_action_at"] > assigned_at:
            continue

        days_silent = aclk["days_silent"] if aclk else days_between(obs, assigned_at)
        suppressed_by = []
        if is_auto:
            suppressed_by.append("H9: automatic assignment")
        stale = h1_no_stale_label(conn, wid)
        if stale:
            suppressed_by.append(f"H1: no-stale label '{stale}'")
        # H3 ("a linked open PR exists") -- built at D-103's repair, same
        # data gap as S-02 (previously unreachable, see module docstring
        # history).
        open_link = h_link_open_blocker(conn, wid)
        if open_link:
            suppressed_by.append(f"H3: open linked blocker {open_link}")

        matched = days_silent is not None and days_silent >= THRESHOLDS["S-05"]
        if not matched and not suppressed_by:
            continue
        out.append(make(
            "S-05", wid, conn, graph, actor_login(graph, actor_id),
            f"assigned to {actor_login(graph, actor_id)} on {assigned_at}; no activity from them since",
            days_silent, aclk and aclk["is_lower_bound"], matched and not suppressed_by, suppressed_by,
        ))
    return out


# ---------------------------------------------------------------------------
# S-06 -- A direct question to a person, unanswered
# ---------------------------------------------------------------------------

def detect_s06(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        """SELECT m.work_item_id, m.mentioned_actor_id, c.created_at, m.in_code_or_quote,
                  c.has_question_mark, c.authorship
           FROM mention m JOIN comment c ON c.id = m.comment_id
           JOIN work_item wi ON wi.id = m.work_item_id
           WHERE m.mentioned_actor_id IS NOT NULL AND wi.state='open' AND wi.is_draft=0"""
    ).fetchall()
    candidates: dict[tuple, str] = {}
    for wid, actor_id, created_at, in_code, has_q, authorship in rows:
        if in_code or not has_q or created_at is None:
            continue  # both are declared S-06 false positives (SS3.5)
        if authorship != "human":
            continue  # D-057: an AI-drafted or bot comment isn't someone asking
        key = (wid, actor_id)
        if key not in candidates or created_at > candidates[key]:
            candidates[key] = created_at

    for (wid, actor_id), created_at in candidates.items():
        mclk = actor_item_clock(conn, wid, actor_id)
        if mclk and mclk["last_action_at"] and mclk["last_action_at"] > created_at:
            continue

        days_silent = mclk["days_silent"] if mclk else days_between(obs, created_at)
        matched = days_silent is not None and days_silent >= THRESHOLDS["S-06"]
        if not matched:
            continue
        # "Question answered by someone else" is a declared suppressor
        # this module deliberately does not attempt: telling a real
        # answer apart from an unrelated later comment is a prose
        # judgement, and a keyword guess here would likely either
        # suppress almost every real hit (any later comment at all) or
        # none of them -- named as an honest gap rather than shipped as
        # a guess, the same call D-007 makes for S-10/H7.
        out.append(make(
            "S-06", wid, conn, graph, actor_login(graph, actor_id),
            f"@-mentioned with a question on {created_at}; no reply from them since",
            days_silent, mclk and mclk["is_lower_bound"], True, [],
        ))
    return out


# ---------------------------------------------------------------------------
# S-08 -- Open far longer than this repository's own norm, unexplained
# ---------------------------------------------------------------------------

def load_closed_age_p95(closed_sample_path: str) -> dict[str, dict]:
    """Reads the Phase 2.3 stratified closed-item sample (D-073) and
    computes, per repository, the age-at-close (days) at the 95th
    percentile -- the "top 5% of this repository's closed items" test
    SS6.1 and the catalogue both call for. This is a plain read of an
    already-verified data file, not a new sampling decision."""
    with open(closed_sample_path) as f:
        d = json.load(f)
    ages: dict[str, list[float]] = {}
    for b in d["buckets"]:
        repo = b["repo"]
        for it in b["items"]:
            c, cl = it.get("created_at"), it.get("closed_at")
            if not c or not cl:
                continue
            ages.setdefault(repo, []).append(days_between(cl, c))
    out = {}
    for repo, lst in ages.items():
        lst = sorted(lst)
        idx = min(len(lst) - 1, max(0, int(round(len(lst) * 0.95)) - 1))
        out[repo] = {"p95_days": lst[idx], "n": len(lst)}
    return out


def detect_s08(conn: sqlite3.Connection, graph: EntityGraph,
               p95_by_repo: dict[str, dict], other_fired_ids: set[int]) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    rows = conn.execute(
        """SELECT wi.id, wi.created_at, p.source_key
           FROM work_item wi JOIN project p ON p.id = wi.project_id
           WHERE wi.state='open' AND wi.is_draft=0"""
    ).fetchall()
    for wid, created_at, repo_key in rows:
        p95 = p95_by_repo.get(repo_key)
        if not p95 or created_at is None:
            continue
        age_days = days_between(obs, created_at)
        clk = item_clock(conn, wid)
        silent_days = clk["days_silent"] if clk else age_days

        suppressed_by = []
        if wid in other_fired_ids:
            suppressed_by.append("another pattern already explains this item")
        # "No explanation" means no *classified* label (blocker or
        # healthy_slowness) -- an ordinary categorisation label like
        # 'kind:bug' or 'area:API' is not an explanation for silence,
        # and treating any label at all as one would gut this pattern
        # (nearly every item on GitHub carries some label).
        n_explanatory = conn.execute(
            """SELECT COUNT(*) FROM work_item_label wil JOIN label l ON l.id = wil.label_id
               WHERE wil.work_item_id=? AND wil.removed_at IS NULL
                 AND l.classification IN ('blocker','healthy_slowness')
                 AND l.classification_status='confirmed'""",
            (wid,),
        ).fetchone()[0]
        if n_explanatory:
            suppressed_by.append(f"{n_explanatory} blocker/healthy-slowness label(s) offer an explanation")
        milestone = h2_open_milestone(conn, wid)  # H2: expiry is a comparison -- closed milestones don't suppress
        if milestone:
            suppressed_by.append(f"H2: open milestone '{milestone}'")

        matched = (
            age_days >= max(p95["p95_days"], THRESHOLDS["S-08"][0])
            and silent_days is not None and silent_days >= THRESHOLDS["S-08"][1]
        )
        if not matched and not suppressed_by:
            continue

        last_human = conn.execute(
            """SELECT actor_id FROM event WHERE work_item_id=? AND counts_as_human=1
               ORDER BY occurred_at DESC LIMIT 1""",
            (wid,),
        ).fetchone()
        next_actor = actor_login(graph, last_human[0]) if last_human and last_human[0] else \
            "unknown (no clear owner)"

        out.append(make(
            "S-08", wid, conn, graph, next_actor,
            f"open {age_days:.0f}d (repo p95 of {p95['n']} closed items = {p95['p95_days']:.0f}d); "
            f"silent {silent_days:.0f}d; no other pattern or label explains it",
            silent_days, clk and clk["is_lower_bound"], matched and not suppressed_by, suppressed_by,
        ))
    return out


# ---------------------------------------------------------------------------
# S-09 -- Handed to a group, owned by nobody
# ---------------------------------------------------------------------------

def detect_s09(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    """Evidence: a review request or an @mention naming a *team*
    (SS6.1). Phase 3.1's graph build already found zero
    review_requested_team / mentions_team edges anywhere in this
    148-item snapshot (docs/PHASE3_1_ENTITY_GRAPH.md) -- so this
    detector is expected to return nothing on the frozen ground truth.
    That is a fact about this sample, not a bug in the detector; it is
    implemented in full so it is ready the moment ARGUS points at a
    repository where team hand-offs do occur."""
    out = []
    obs = observed_at(conn)
    team_reqs = conn.execute(
        """SELECT rr.work_item_id, rr.team, rr.requested_at, rr.removed_at
           FROM review_request rr JOIN work_item wi ON wi.id = rr.work_item_id
           WHERE rr.team IS NOT NULL AND wi.state='open' AND wi.is_draft=0"""
    ).fetchall()
    team_mentions = conn.execute(
        """SELECT m.work_item_id, m.mentioned_team, c.created_at
           FROM mention m JOIN comment c ON c.id = m.comment_id
           JOIN work_item wi ON wi.id = m.work_item_id
           WHERE m.mentioned_team IS NOT NULL AND wi.state='open' AND wi.is_draft=0"""
    ).fetchall()

    candidates: dict[int, tuple] = {}
    for wid, team, requested_at, removed_at in team_reqs:
        if removed_at is not None or requested_at is None:
            continue
        if wid not in candidates or requested_at > candidates[wid][1]:
            candidates[wid] = (f"review requested from team '{team}'", requested_at)
    for wid, team, created_at in team_mentions:
        if created_at is None:
            continue
        if wid not in candidates or created_at > candidates[wid][1]:
            candidates[wid] = (f"team '{team}' mentioned in a comment", created_at)

    for wid, (desc, handoff_at) in candidates.items():
        if human_activity_after(conn, wid, handoff_at) > 0:
            continue  # an individual responded -- H6
        clk = item_clock(conn, wid)
        days_silent = clk["days_silent"] if clk else days_between(obs, handoff_at)
        matched = days_silent is not None and days_silent >= THRESHOLDS["S-09"]
        if not matched:
            continue
        out.append(make(
            "S-09", wid, conn, graph, "cannot be determined -- handed to a group, not a person",
            f"{desc} on {handoff_at}; no individual response since",
            days_silent, clk and clk["is_lower_bound"], True, [],
        ))
    return out


# ---------------------------------------------------------------------------
# S-10 -- A decision was promised, and nobody is tracking it
# ---------------------------------------------------------------------------

# Deliberately narrow, and deliberately not generalised beyond what the
# catalogue's own two known examples justify (D-058 named exactly two:
# pytest-dev/pytest#14091, pola-rs/polars#25735). Reading intent from
# prose with keyword rules is the honest weakness §8 of the data model
# names for this pattern -- widening the list to catch more would trade
# a documented weak-recall detector for an undocumented low-precision
# one, the wrong direction under "precision over coverage."
SELF_OWED_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bi'?ll decide\b", r"\bi will decide\b", r"\blet me decide\b",
        r"\bi need to decide\b", r"\bi have to decide\b",
        r"\bi'?ll think (about|it over)\b", r"\bi'?ll get back to you\b",
        r"\bgive me (some time|a (few )?days?) to decide\b",
        r"\bi'?d like to decide\b", r"\bi would like to decide\b",
    ]
]
OWNERLESS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bneeds? a decision\b", r"\bpending (a )?decision\b",
        r"\bsomeone (should|needs to) decide\b", r"\bwe need to decide\b",
        r"\bstill (undecided|deciding)\b", r"\bnot yet decided\b",
    ]
]


def detect_s10(conn: sqlite3.Connection, graph: EntityGraph) -> list[Detection]:
    out = []
    obs = observed_at(conn)
    comments = conn.execute(
        """SELECT c.work_item_id, c.actor_id, c.created_at, c.body
           FROM comment c JOIN work_item wi ON wi.id = c.work_item_id
           WHERE c.authorship='human' AND wi.state='open' AND wi.is_draft=0
             AND c.created_at IS NOT NULL"""
    ).fetchall()

    self_owed: dict[tuple, str] = {}   # (wid, actor_id) -> latest matching comment time
    ownerless: dict[int, str] = {}     # wid -> latest matching comment time
    for wid, actor_id, created_at, body in comments:
        if not body:
            continue
        if actor_id is not None and any(p.search(body) for p in SELF_OWED_PATTERNS):
            key = (wid, actor_id)
            if key not in self_owed or created_at > self_owed[key]:
                self_owed[key] = created_at
        elif any(p.search(body) for p in OWNERLESS_PATTERNS):
            if wid not in ownerless or created_at > ownerless[wid]:
                ownerless[wid] = created_at

    for (wid, actor_id), spoken_at in self_owed.items():
        aclk = actor_item_clock(conn, wid, actor_id)
        if aclk and aclk["last_action_at"] and aclk["last_action_at"] > spoken_at:
            continue  # they delivered the decision, or otherwise acted since
        days_silent = aclk["days_silent"] if aclk else days_between(obs, spoken_at)
        matched = days_silent is not None and days_silent >= THRESHOLDS["S-10"]
        if not matched:
            continue
        out.append(make(
            "S-10", wid, conn, graph, actor_login(graph, actor_id),
            f"{actor_login(graph, actor_id)} said (self-owed) a decision was pending, on {spoken_at}; "
            f"no activity from them since -- keyword match, prose judgement, low confidence by design",
            days_silent, aclk and aclk["is_lower_bound"], True, [],
        ))

    for wid, spoken_at in ownerless.items():
        if human_activity_after(conn, wid, spoken_at) > 0:
            continue
        clk = item_clock(conn, wid)
        days_silent = clk["days_silent"] if clk else days_between(obs, spoken_at)
        matched = days_silent is not None and days_silent >= THRESHOLDS["S-10"]
        if not matched:
            continue
        out.append(make(
            "S-10", wid, conn, graph, "cannot be determined -- decision named as pending, nobody owns it",
            f"a comment named a pending decision nobody was asked to make, on {spoken_at}; "
            f"no activity since -- keyword match, prose judgement, low confidence by design",
            days_silent, clk and clk["is_lower_bound"], True, [],
        ))
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

DETECTOR_FUNCS = {
    "S-01": detect_s01, "S-02": detect_s02, "S-03": detect_s03, "S-04": detect_s04,
    "S-05": detect_s05, "S-06": detect_s06, "S-09": detect_s09, "S-10": detect_s10,
}


def run_all(conn: sqlite3.Connection, graph: EntityGraph, closed_sample_path: str) -> dict[str, list[Detection]]:
    """Runs all nine active detectors. S-08 runs last because its own
    evidence rule ("no other pattern explains it") needs to know what
    the other eight already fired on."""
    results: dict[str, list[Detection]] = {}
    for pattern, fn in DETECTOR_FUNCS.items():
        results[pattern] = fn(conn, graph)

    fired_ids: set[int] = set()
    for dets in results.values():
        fired_ids.update(d.work_item_id for d in dets if d.fired)

    p95 = load_closed_age_p95(closed_sample_path)
    results["S-08"] = detect_s08(conn, graph, p95, fired_ids)
    return results
