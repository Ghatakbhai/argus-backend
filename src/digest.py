"""
ARGUS — Phase 6, step 6.8: the Unified Standup Digest.

Everything the previous seven steps built has, until now, been true but
scattered. The filter knows what it suppressed and why (6.4). The triage DM
knows what it asked and what it was told (6.6). Presence knows who is away
and which alerts are sitting behind an absence (6.7). None of it is
anywhere a human can read in one go, and a coordination tool whose findings
are only legible to its own author has not actually coordinated anything.

This module is the one place all of it becomes one readable thing, rendered
twice from a single assembled structure:

  * a Slack Block Kit message — the tech lead's morning DM, names included;
  * a self-contained HTML report — the "Radar" old Phase 4 was going to
    build and never did (folded here per D-107).

Both renderers read the SAME `Digest`. That is deliberate and is the whole
architectural claim of this step: a report and a message that disagree
about what is stuck are worse than either alone, and the only way to
guarantee they cannot disagree is to give them nothing to disagree about.

Design calls Dirgh made this session (session 34), recorded at D-118:

  1. **Named human blockers lead the digest.** Where somebody clicked
     [Blocked on…] and typed a reason, ARGUS knows the actual cause rather
     than merely the symptom, and the lead is usually the only person who
     can act across a team boundary. Escalations second, everything else
     under those.
  2. **A quiet morning still gets a short all-clear.** One line, with the
     counts. Silence that means "nothing is wrong" and silence that means
     "ARGUS died on Tuesday" look identical from the outside, and this
     project has spent five phases refusing to ship that ambiguity.
  3. **Two audiences, two renderings.** The lead's DM carries names; the
     channel post carries counts and no identifiers at all. The team sees
     the temperature without anybody being named in public.
  4. **An item nobody ever answers is asked three times, then handed to the
     digest** — never dropped, never asked forever. This closes the open
     question D-116 left behind.

## What this module does NOT do

It does not send anything. `collect()` reads, the renderers format, and the
caller decides where the bytes go. That is not fastidiousness: the sending
path is the part that cannot be tested offline (D-115 — nothing in this
project has ever spoken to real Slack), so keeping every decision on this
side of that line is what makes 6.8 verifiable at all before 6.9.

It also does not invent a tech lead. Schema section 12 has no concept of
one, and guessing at a team's structure is exactly the kind of confident
wrongness ARGUS exists to argue against. The caller passes a recipient in;
6.9 is the first step with a real team to ask.
"""

from __future__ import annotations

import html as _html
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Iterable, Optional

import presence as P
import slack_triage as ST
import sprint_filter as SF

# ---------------------------------------------------------------------------
# 1. Constants — every tunable in one readable place
# ---------------------------------------------------------------------------

# How many unanswered asks about one item before ARGUS stops DMing about it
# and hands it to the lead's digest instead. Dirgh's call, session 34,
# closing the question D-116 left open.
#
# Three, because two is inside the range of a normal holiday and four is
# past the point where a reasonable person would conclude they are being
# nagged by a robot. The item does not go quiet when this trips — it moves
# from "we are asking a developer" to "we are telling the lead nobody
# answered", which is a change of audience, not a disappearance.
MAX_UNANSWERED_ASKS = 3

# When a reported blocker stops being presented as current fact.
#
# "Blocked on the infra team" was true when it was typed. Fourteen days
# later it may have been resolved by somebody who never told ARGUS. The row
# does NOT disappear at this point — a vanishing blocker is precisely the
# failure this project keeps finding in its own code — it is relabelled, so
# the lead reads "reported 23 days ago" and treats it as a question rather
# than an answer.
BLOCKER_STALE_DAYS = 14

# Slack caps a message at 50 blocks. A digest that silently loses its tail
# at row 40 would be the same class of bug as everything else this project
# has hunted, so sections are truncated explicitly, the truncation is
# stated in the message, and the HTML report is never truncated at all.
MAX_ROWS_PER_SLACK_SECTION = 5
SLACK_BLOCK_LIMIT = 50

# The sections, in the order Dirgh chose. The order is data, not code, so
# that changing a team's mind about it later is a one-line change.
SECTION_BLOCKED = "blocked"
SECTION_ESCALATION = "escalation"
SECTION_UNANSWERED = "unanswered"
SECTION_AWAITING = "awaiting"
SECTION_HELD = "held"
SECTION_UNREACHABLE = "unreachable"

SECTION_ORDER = [
    SECTION_BLOCKED,
    SECTION_ESCALATION,
    SECTION_UNANSWERED,
    SECTION_AWAITING,
    SECTION_HELD,
    SECTION_UNREACHABLE,
]

SECTION_TITLE = {
    SECTION_BLOCKED: "Blocked — someone told us why",
    SECTION_ESCALATION: "Stuck behind someone who is away",
    SECTION_UNANSWERED: "Asked and never answered",
    SECTION_AWAITING: "Waiting on a reply",
    SECTION_HELD: "Held — recipient out of office",
    SECTION_UNREACHABLE: "We could not reach anyone",
}

# One line under each heading saying what the lead is expected to DO with
# it. A report that lists facts without implying an action is a report
# people skim once and then stop opening.
SECTION_BLURB = {
    SECTION_BLOCKED: "A developer named the blocker. These usually need someone with cross-team reach.",
    SECTION_ESCALATION: "Held more than 5 days behind an absence. Reassignment is a human decision.",
    SECTION_UNANSWERED: "Asked 3 times, no reply. ARGUS has stopped asking; it has not stopped counting.",
    SECTION_AWAITING: "A triage DM is open. No action needed yet — shown so the silence is visible.",
    SECTION_HELD: "Deliberately not sent. Will go out when they are back, two a day.",
    SECTION_UNREACHABLE: "An alert with nobody to send it to. This is an integration gap, not a stall.",
}

# Severity, for the HTML report's colour and for anyone sorting the rows.
SECTION_TONE = {
    SECTION_BLOCKED: "urgent",
    SECTION_ESCALATION: "urgent",
    SECTION_UNANSWERED: "warn",
    SECTION_AWAITING: "info",
    SECTION_HELD: "info",
    SECTION_UNREACHABLE: "warn",
}


# ---------------------------------------------------------------------------
# 2. Small shared helpers
# ---------------------------------------------------------------------------

def _hours_since(now_dt, iso: Optional[str]) -> Optional[float]:
    dt = ST._parse(iso) if iso else None
    if dt is None:
        return None
    return (now_dt - dt).total_seconds() / 3600.0


def age_phrase(hours: Optional[float], is_lower_bound: bool = False) -> str:
    """A duration a human reads without doing arithmetic.

    Deliberately coarse. "4 days" is what somebody acts on; "96.0 hours" is
    what a machine emits and a person has to convert. The lower-bound
    qualifier is carried through from the filter rather than dropped,
    because 6.4 is careful to distinguish "idle for 4 days" from "idle for
    at least 4 days" and flattening that here would throw away a
    distinction an earlier step paid for.
    """
    if hours is None:
        return "unknown"
    prefix = "at least " if is_lower_bound else ""
    if hours < 48:
        return f"{prefix}{hours:.0f}h"
    days = hours / 24.0
    return f"{prefix}{days:.0f} days" if abs(days - round(days)) < 0.05 \
        else f"{prefix}{days:.1f} days"


def _item_state(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    row = conn.execute("SELECT state FROM work_item WHERE id = ?",
                       (work_item_id,)).fetchone()
    return row[0] if row else None


def _item_title(conn: sqlite3.Connection, work_item_id: int) -> str:
    row = conn.execute("SELECT title FROM work_item WHERE id = ?",
                       (work_item_id,)).fetchone()
    return row[0] if row else ""


def _item_url(conn: sqlite3.Connection, work_item_id: int) -> Optional[str]:
    row = conn.execute("SELECT url FROM work_item WHERE id = ?",
                       (work_item_id,)).fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# 3. "Asked three times and nobody answered"
# ---------------------------------------------------------------------------
#
# This is the one behavioural change 6.8 makes to the sending path, and it
# is added the way every capability since 6.6 has been added: as an OPTIONAL
# injected callable, so `slack_triage` and `presence` are not touched and
# their verifiers prove it. `chain_limiters` is what lets 6.7's release
# throttle and this live in the same slot without either knowing about the
# other.

def unanswered_ask_count(conn: sqlite3.Connection, work_item_id: int,
                        now: Optional[str] = None) -> int:
    """How many times we have asked about this item and been ignored.

    Counted from expired messages — a DM that sat unanswered for a week and
    was written off by 6.6's `expire_stale_messages`. A message still open
    is not yet an unanswered ask; it is an ask in flight.

    `now` is an upper bound on what counts, and passing it is not optional
    in spirit even though the signature allows it. A digest is a statement
    about one morning; a morning's digest that counts a DM sent the
    following week is not merely inaccurate, it makes the whole record
    un-replayable — and being able to ask "what did ARGUS believe on the
    day it stayed quiet" is the property Phase 7's satisfaction scoring
    depends on. Found by the six-week simulation printing two
    never-answered items on day zero, before either had been asked once.

    **The count is reset by any human activity on the item since the last
    ask.** This is the guard against this project's characteristic defect,
    which has now appeared in three consecutive steps: a temporary state
    quietly becoming a permanent one. Without the reset, an item ignored
    three times last quarter would be permanently ineligible for a DM, even
    after the PR was rebased, re-reviewed and actively worked on — ARGUS
    would have gone silent forever about a live piece of work, and the only
    trace would be a digest line nobody connects to the cause. With it,
    giving up is scoped to one continuous stretch of silence, which is the
    only thing three ignored messages actually evidence.
    """
    last_human, _ = SF._last_human_activity(conn, work_item_id)
    rows = conn.execute(
        """SELECT m.sent_at FROM triage_message m
           LEFT JOIN triage_response r ON r.triage_message_id = m.id
           WHERE m.work_item_id = ? AND m.status = 'expired' AND r.id IS NULL
             AND (? IS NULL OR m.sent_at <= ?)""",
        (work_item_id, now, now)).fetchall()
    if last_human is None:
        return len(rows)
    return sum(1 for (sent_at,) in rows if sent_at > last_human)


def give_up_limiter(conn: sqlite3.Connection,
                    max_asks: int = MAX_UNANSWERED_ASKS
                    ) -> Callable[[int, int, str], Optional[dict]]:
    """Stop DMing about an item that has been ignored `max_asks` times.

    Same signature as 6.7's `held_release_limiter` so the two compose. Note
    what it returns: a reason, not silence. The skip is recorded by the
    caller and surfaces in this digest's "Asked and never answered"
    section, so the item changes audience rather than disappearing.
    """

    def limit(actor_id: int, work_item_id: int, now: str) -> Optional[dict]:
        n = unanswered_ask_count(conn, work_item_id, now)
        if n < max_asks:
            return None
        return {"reason": "unanswered_ask_limit",
                "asks": n,
                "detail": f"asked {n} times with no answer; escalated to the digest"}

    return limit


def chain_limiters(*limiters: Optional[Callable[[int, int, str], Optional[dict]]]
                   ) -> Callable[[int, int, str], Optional[dict]]:
    """Run several `release_limiter`-shaped callables, first veto wins.

    Exists so that adding 6.8's limiter costs `slack_triage.py` no edit at
    all: 6.6 accepts exactly one `release_limiter`, and this makes one out
    of many. Order matters and is the caller's choice; the daily job puts
    the give-up check first, because "we have stopped asking this person"
    is a more informative reason to skip than "we are dripping their
    backlog out slowly".
    """
    active = [f for f in limiters if f is not None]

    def limit(actor_id: int, work_item_id: int, now: str) -> Optional[dict]:
        for f in active:
            out = f(actor_id, work_item_id, now)
            if out:
                return out
        return None

    return limit


# ---------------------------------------------------------------------------
# 4. The assembled shape
# ---------------------------------------------------------------------------

@dataclass
class DigestRow:
    """One line a human reads, in whichever medium.

    Every field here exists because some renderer needs it; nothing is
    carried "in case". `evidence` is the filter's own sentence, verbatim,
    for the same reason 6.6 put it in the DM: a wrong alert should be
    arguable rather than mysterious, and paraphrasing it here would break
    the chain of custody between what ARGUS concluded and what it showed.
    """
    section: str
    item_key: str
    title: str = ""
    person: Optional[str] = None          # the login this row is about
    headline: str = ""                    # the one-sentence why
    detail: str = ""                      # the supporting clause
    evidence: str = ""                    # the filter's own line, verbatim
    age_hours: Optional[float] = None     # what the row is ranked on
    age_label: str = ""
    pattern: Optional[str] = None
    url: Optional[str] = None
    confidence: str = "high"
    is_stale: bool = False                # a fact old enough to re-check
    work_item_id: Optional[int] = None

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["age_hours"] = None if self.age_hours is None else round(self.age_hours, 1)
        return d


@dataclass
class DigestCounts:
    """The numbers Phase 6's kill criterion is eventually read off.

    `suppressed_by_reason` is the one that matters most: by 6.4's
    construction every SUPPRESSED row is an alert Part I would have sent
    and Part II does not, so this is a direct count of noise removed, and
    it belongs in front of a human every single morning rather than in a
    log nobody opens.
    """
    items_checked: int = 0
    fired: int = 0
    suppressed: int = 0
    abstained: int = 0
    suppressed_by_reason: dict = field(default_factory=dict)
    abstained_by_reason: dict = field(default_factory=dict)
    dms_sent: int = 0
    dms_skipped: int = 0
    dms_failed: int = 0
    dm_skips_by_reason: dict = field(default_factory=dict)
    dm_failures_by_reason: dict = field(default_factory=dict)
    people_out: int = 0
    responses_all_time: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Digest:
    generated_at: str
    team_label: str
    rows: list[DigestRow] = field(default_factory=list)
    counts: DigestCounts = field(default_factory=DigestCounts)
    truncated_sections: dict = field(default_factory=dict)

    @property
    def all_clear(self) -> bool:
        """Nothing needing a human. NOT the same as nothing to report.

        An all-clear digest still carries its counts, because "we checked
        23 items and suppressed 6 as backlog" is the evidence that the
        quiet is real rather than a crash.
        """
        return not self.rows

    def section(self, name: str) -> list[DigestRow]:
        return [r for r in self.rows if r.section == name]

    def sections(self) -> list[tuple[str, list[DigestRow]]]:
        return [(s, self.section(s)) for s in SECTION_ORDER if self.section(s)]

    def as_dict(self) -> dict:
        return {"generated_at": self.generated_at, "team_label": self.team_label,
                "all_clear": self.all_clear,
                "rows": [r.as_dict() for r in self.rows],
                "counts": self.counts.as_dict(),
                "truncated_sections": self.truncated_sections}


# ---------------------------------------------------------------------------
# 5. Collecting — one pass over everything the earlier steps recorded
# ---------------------------------------------------------------------------

def latest_blocker(conn: sqlite3.Connection, work_item_id: int,
                   now: Optional[str] = None) -> Optional[tuple]:
    """(login, text, responded_at) of the most recent [Blocked on…], if any."""
    return conn.execute(
        """SELECT a.source_key, r.blocked_on_text, r.responded_at
           FROM triage_response r
           JOIN triage_message m ON m.id = r.triage_message_id
           JOIN actor a ON a.id = m.sent_to_actor_id
           WHERE r.response_type = 'blocked_on' AND m.work_item_id = ?
             AND (? IS NULL OR r.responded_at <= ?)
           ORDER BY r.responded_at DESC LIMIT 1""",
        (work_item_id, now, now)).fetchone()


def _last_unanswered_ask(conn: sqlite3.Connection, work_item_id: int,
                        now: Optional[str] = None) -> Optional[str]:
    return conn.execute(
        """SELECT MAX(m.sent_at) FROM triage_message m
           LEFT JOIN triage_response r ON r.triage_message_id = m.id
           WHERE m.work_item_id = ? AND m.status = 'expired' AND r.id IS NULL
             AND (? IS NULL OR m.sent_at <= ?)""",
        (work_item_id, now, now)).fetchone()[0]


def _blocked_rows(conn, now_dt, now: str, live: dict) -> list[DigestRow]:
    """Items a developer told us the blocker for. Dirgh's top section.

    Only the LATEST blocked_on per item is shown. Somebody who answered
    twice has changed their mind, and showing both would present a
    superseded blocker as a current one.

    A closed or merged item is dropped: the blocker was real and is now
    irrelevant, and a digest that keeps reporting solved problems is a
    digest that gets muted.

    **A blocker that has since been asked about and ignored is dropped
    too.** Found by simulating six weeks rather than one morning: after the
    7-day cooldown lapses ARGUS re-asks, and if nobody answers three times
    the item is both "somebody told us why" (five weeks ago) and "nobody
    will answer" (now). Both are true, but only the second is current, and
    leading the digest with the stale one would let the more useful fact
    sit four sections lower. The old blocker text is not lost — it is
    carried into the unanswered row.
    """
    rows = conn.execute(
        """SELECT DISTINCT m.work_item_id FROM triage_response r
           JOIN triage_message m ON m.id = r.triage_message_id
           WHERE r.response_type = 'blocked_on' AND m.work_item_id IS NOT NULL
             AND r.responded_at <= ?""", (now,)).fetchall()

    out = []
    for (wid,) in rows:
        if wid not in live:
            continue                       # see `collect`: rows follow the alert
        login, text, at = latest_blocker(conn, wid, now)
        ignored_since = _last_unanswered_ask(conn, wid, now)
        if ignored_since and ignored_since > at:
            continue                       # superseded by silence; see docstring
        hours = _hours_since(now_dt, at)
        stale = hours is not None and hours > BLOCKER_STALE_DAYS * 24
        out.append(DigestRow(
            section=SECTION_BLOCKED, work_item_id=wid,
            item_key=ST.item_key_of(conn, wid), title=_item_title(conn, wid),
            person=login,
            headline=(text or "blocked, no reason given").strip(),
            detail=(f"{login} reported this {age_phrase(hours)} ago"
                    + (" — old enough to be worth re-checking" if stale else "")),
            age_hours=hours, age_label=age_phrase(hours),
            url=_item_url(conn, wid), is_stale=stale))
    return out


def _escalation_rows(conn, now: str, live: dict) -> list[DigestRow]:
    """6.7's 5-day escalations, rendered. The facts are entirely its own.

    `presence.Escalation.held_alerts` used to count every hold ever
    recorded for the pair, across every separate absence, which read wrong
    in a sentence that also names the current absence's start date (D-118:
    "3 alerts held since <yesterday>" after three separate holidays). 6.8
    worked around this locally rather than edit a signed-off file mid-step;
    6.9 makes the source fix in `presence.py` itself (`escalations_due` now
    scopes `held_alerts` to the current unbroken absence), so this just
    reads the field directly.
    """
    out = []
    for e in P.escalations_due(conn, now):
        if e.work_item_id not in live:
            continue                       # see `collect`: rows follow the alert
        out.append(DigestRow(
            section=SECTION_ESCALATION, work_item_id=e.work_item_id,
            item_key=e.item_key, title=_item_title(conn, e.work_item_id),
            person=e.blocked_on_login,
            headline=f"{e.blocked_on_login} has been away {age_phrase(e.days_out * 24)}",
            detail=(f"{e.held_alerts} alert(s) held during this absence, "
                    f"since {e.out_since}. Nobody else has been asked."),
            age_hours=e.days_out * 24.0, age_label=age_phrase(e.days_out * 24),
            url=_item_url(conn, e.work_item_id)))
    return out


def _unanswered_rows(conn, now_dt, now: str, live: dict[int, SF.FilterResult],
                     max_asks: int) -> list[DigestRow]:
    """Items ARGUS has stopped asking about, because nobody ever replied.

    Scoped to items the filter is STILL firing on today. That coupling is
    the point: the row exists because the problem is live, not because a
    flag was set once. When the PR is finally merged the filter stops
    firing and the row leaves on its own, with no state to clean up and
    nothing to go stale.
    """
    out = []
    for wid, res in live.items():
        n = unanswered_ask_count(conn, wid, now)
        if n < max_asks:
            continue
        hours = _hours_since(now_dt, _last_unanswered_ask(conn, wid, now))
        detail = f"Last asked {age_phrase(hours)} ago. ARGUS has stopped asking."
        # An old blocker report that silence has superseded is carried here
        # rather than dropped. It is no longer current, but "they did once
        # say it was waiting on Legal" is the most useful thing the lead has.
        prior = latest_blocker(conn, wid, now)
        if prior:
            detail += (f" Last thing they told us, {age_phrase(_hours_since(now_dt, prior[2]))}"
                       f" ago: “{(prior[1] or '').strip()}”")
        out.append(DigestRow(
            section=SECTION_UNANSWERED, work_item_id=wid,
            item_key=res.item_key, title=_item_title(conn, wid),
            person=res.next_actor,
            headline=f"{res.next_actor} was asked {n} times and has not replied",
            detail=detail,
            evidence=res.evidence, pattern=res.pattern,
            age_hours=hours, age_label=age_phrase(hours),
            url=_item_url(conn, wid), confidence=res.confidence))
    return out


def _awaiting_rows(conn, now_dt, now: str, live: dict) -> list[DigestRow]:
    """DMs sitting unanswered in somebody's Slack right now.

    Shown even though no action is wanted, because this is the queue that
    6.6's expiry mechanism drains, and a lead who can see it can tell the
    difference between "ARGUS is quiet because nothing is wrong" and
    "ARGUS is quiet because four people are ignoring it".
    """
    rows = conn.execute(
        """SELECT m.work_item_id, a.source_key, m.sent_at
           FROM triage_message m JOIN actor a ON a.id = m.sent_to_actor_id
           WHERE m.status = 'sent' AND m.work_item_id IS NOT NULL
             AND m.sent_at <= ?
           ORDER BY m.sent_at""", (now,)).fetchall()
    out = []
    for wid, login, sent_at in rows:
        if wid not in live:
            continue                       # see `collect`: rows follow the alert
        hours = _hours_since(now_dt, sent_at)
        out.append(DigestRow(
            section=SECTION_AWAITING, work_item_id=wid,
            item_key=ST.item_key_of(conn, wid), title=_item_title(conn, wid),
            person=login,
            headline=f"Waiting on {login}",
            detail=f"Asked {age_phrase(hours)} ago.",
            age_hours=hours, age_label=age_phrase(hours),
            url=_item_url(conn, wid)))
    return out


def _held_rows(conn, now_dt, now: str, escalated: set[int], live: dict) -> list[DigestRow]:
    """Alerts 6.7 held because their recipient is away.

    Anything already escalated is excluded rather than printed twice: the
    same item under two headings reads as two problems, and inflating the
    apparent size of the board is its own kind of dishonesty.
    """
    rows = conn.execute(
        """SELECT DISTINCT m.work_item_id, m.sent_to_actor_id, a.source_key
           FROM triage_message m JOIN actor a ON a.id = m.sent_to_actor_id
           WHERE m.status = 'suppressed_presence' AND m.work_item_id IS NOT NULL
             AND m.sent_at <= ?""", (now,)).fetchall()
    out = []
    for wid, actor_id, login in rows:
        if wid in escalated or wid not in live:
            continue                      # see `collect`: rows follow the alert
        since = P.out_of_office_since(conn, actor_id, now)
        if since is None:
            continue                      # they are back; 6.7 will release it
        # The hold that belongs to THIS absence, not the earliest one ever
        # recorded. Somebody's third holiday must not be reported as "held
        # since" their first — the same class of error as everything else
        # the six-week simulation has found in this project.
        held_at = conn.execute(
            """SELECT MIN(sent_at) FROM triage_message
               WHERE work_item_id = ? AND sent_to_actor_id = ?
                 AND status = 'suppressed_presence'
                 AND sent_at >= ? AND sent_at <= ?""",
            (wid, actor_id, since, now)).fetchone()[0] or since
        hours = _hours_since(now_dt, since)
        out.append(DigestRow(
            section=SECTION_HELD, work_item_id=wid,
            item_key=ST.item_key_of(conn, wid), title=_item_title(conn, wid),
            person=login,
            headline=f"{login} is out of office",
            detail=f"Away {age_phrase(hours)}. Held since {held_at}; releases when they return.",
            age_hours=hours, age_label=age_phrase(hours),
            url=_item_url(conn, wid)))
    return out


def _unreachable_rows(conn, now_dt, live: dict[int, SF.FilterResult],
                      sends: Optional[list]) -> list[DigestRow]:
    """A real alert with nobody to send it to.

    Schema section 12 says an 'unresolved' identity row is written on
    purpose so the digest can report "we had an alert for @someone and
    could not find them in Slack" rather than staying silent. This is the
    function that honours that comment. It is a warning, not an urgency:
    the fix is an integration fix, not a stall to chase.
    """
    seen: dict[int, DigestRow] = {}

    def add(wid, login, why):
        res = live.get(wid)
        if wid in seen or res is None:
            return
        seen[wid] = DigestRow(
            section=SECTION_UNREACHABLE, work_item_id=wid,
            item_key=res.item_key, title=_item_title(conn, wid),
            person=login, headline=f"No Slack account found for {login}",
            detail=why, evidence=res.evidence, pattern=res.pattern,
            age_hours=res.hours_idle, age_label=age_phrase(res.hours_idle,
                                                           res.is_lower_bound),
            url=_item_url(conn, wid), confidence=res.confidence)

    # What actually happened on today's send, when the caller ran one.
    for s in sends or []:
        if s.outcome == ST.FAILED and s.reason == "recipient_unresolved":
            add(s.work_item_id, s.recipient_login, s.detail or "identity could not be resolved")

    # And the standing record, so this works with no send results at all.
    unresolved = {r[0] for r in conn.execute(
        "SELECT a.source_key FROM slack_identity si JOIN actor a ON a.id = si.actor_id "
        "WHERE si.resolved_via = 'unresolved'")}
    for wid, res in live.items():
        if res.next_actor in unresolved:
            add(wid, res.next_actor, "no Slack account matched this person")
    return list(seen.values())


def collect(conn: sqlite3.Connection,
            results: Iterable[SF.FilterResult],
            now: str,
            *,
            sends: Optional[list] = None,
            team_label: str = "your team",
            max_asks: int = MAX_UNANSWERED_ASKS) -> Digest:
    """Assemble one morning's digest from everything the pipeline knows.

    Reads only. Nothing here writes a row, sets a flag or sends a message,
    which is what makes running it twice on the same morning harmless and
    what makes the whole step testable without Slack.

    **Every section is scoped to the items the filter is firing on TODAY.**
    This is the single rule that keeps the digest from accumulating, and it
    was not in the first version of this module — it came from reading a
    rendered sample and noticing that a blocker reported on a pull request
    somebody later moved to the backlog would sit at the top of the board
    until the PR was closed, months later. That is this project's
    characteristic defect wearing a different hat: a fact that was true
    once, kept because nothing was watching for when it stopped being
    relevant.

    Scoping to the live alert set makes the board self-clearing with no
    state to expire. An item leaves the digest the moment the pipeline
    stops flagging it — merged, reviewed, re-linked, moved to the backlog,
    ticket closed — because the reason it was on the board was always the
    alert, never the annotation. Items suppressed by 6.4's gate are still
    reported, as the counts they always were (D-116's answer for
    unlinkable items), not as rows.
    """
    now_dt = ST._require_now(now)
    results = list(results)
    live = {r.work_item_id: r for r in results if r.outcome == SF.FIRE}

    esc = _escalation_rows(conn, now, live)
    escalated = {r.work_item_id for r in esc}

    rows: list[DigestRow] = []
    rows += _blocked_rows(conn, now_dt, now, live)
    rows += esc
    rows += _unanswered_rows(conn, now_dt, now, live, max_asks)
    rows += _awaiting_rows(conn, now_dt, now, live)
    rows += _held_rows(conn, now_dt, now, escalated, live)
    rows += _unreachable_rows(conn, now_dt, live, sends)

    # Within a section, oldest first. Across sections, Dirgh's order stands:
    # a two-day-old named blocker outranks a six-day-old unexplained stall,
    # because one of them tells the lead what to actually do.
    order = {s: i for i, s in enumerate(SECTION_ORDER)}
    rows.sort(key=lambda r: (order.get(r.section, 99), -(r.age_hours or 0), r.item_key))

    # One item, one row — enforced here rather than assumed. The same pull
    # request under two headings reads as two problems, and a digest that
    # inflates the size of the board is dishonest in the direction that
    # gets a tool muted. Precedence is SECTION_ORDER, which is why the
    # sections that would mask a more current fact drop it themselves
    # upstream (see `_blocked_rows`) instead of relying on this.
    deduped, claimed = [], set()
    for r in rows:
        if r.work_item_id is not None and r.work_item_id in claimed:
            continue
        claimed.add(r.work_item_id)
        deduped.append(r)
    rows = deduped

    summary = SF.summarise(results)
    counts = DigestCounts(
        items_checked=summary["items"],
        fired=summary[SF.FIRE], suppressed=summary[SF.SUPPRESSED],
        abstained=summary[SF.ABSTAIN],
        suppressed_by_reason=dict(summary["suppressed_by_reason"]),
        abstained_by_reason=dict(summary["abstained_by_reason"]),
    )
    if sends is not None:
        s = ST.summarise_sends(list(sends))
        counts.dms_sent = s[ST.SENT]
        counts.dms_skipped = s[ST.SKIPPED]
        counts.dms_failed = s[ST.FAILED]
        counts.dm_skips_by_reason = dict(s["skipped_by_reason"])
        counts.dm_failures_by_reason = dict(s["failed_by_reason"])

    counts.people_out = conn.execute(
        """SELECT COUNT(DISTINCT actor_id) FROM presence
           WHERE status = 'out_of_office' AND effective_from <= ?
             AND (effective_to IS NULL OR effective_to > ?)""", (now, now)).fetchone()[0]
    counts.responses_all_time = {
        t: n for t, n in conn.execute(
            "SELECT response_type, COUNT(*) FROM triage_response "
            "WHERE responded_at <= ? GROUP BY response_type", (now,))}

    return Digest(generated_at=now, team_label=team_label, rows=rows, counts=counts)


# ---------------------------------------------------------------------------
# 6. Rendering — Slack, the tech lead's DM
# ---------------------------------------------------------------------------

def _noise_line(c: DigestCounts) -> str:
    """The sentence that justifies the tool's existence, every morning.

    Part I's ceiling (D-106) was 65.5% precision and the reason was noise
    nobody could switch off. This line is the running count of noise
    switched off, and it is in the message rather than in a dashboard
    because a number a lead has to go and look for is a number they never
    look at.
    """
    bits = [f"{c.items_checked} items checked", f"{c.fired} flagged"]
    if c.suppressed:
        top = sorted(c.suppressed_by_reason.items(), key=lambda kv: -kv[1])
        why = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in top[:2])
        bits.append(f"{c.suppressed} suppressed ({why})")
    if c.abstained:
        bits.append(f"{c.abstained} not matching a pattern")
    return " · ".join(bits)


def _mrkdwn_link(row: DigestRow) -> str:
    return f"<{row.url}|{row.item_key}>" if row.url else f"`{row.item_key}`"


def render_slack_blocks(digest: Digest,
                        max_rows: int = MAX_ROWS_PER_SLACK_SECTION,
                        report_url: Optional[str] = None) -> list[dict]:
    """The lead's morning DM. Names included, per Dirgh's call.

    Written to survive being read on a phone at a bus stop: the heading
    says how many things need a human, each row is one line of what and one
    line of why, and the counts sit at the bottom where they inform without
    interrupting.
    """
    c = digest.counts
    blocks: list[dict] = []

    if digest.all_clear:
        # Dirgh's call: a quiet morning still gets a message. Short, and
        # carrying the evidence that the quiet was computed rather than
        # merely experienced.
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": "*ARGUS standup — nothing stuck this morning.*"}})
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": _noise_line(c)}]})
        if report_url:
            blocks.append({"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"<{report_url}|Full report>"}]})
        return blocks

    n = len(digest.rows)
    blocks.append({"type": "header", "text": {"type": "plain_text",
                   "text": f"ARGUS standup — {n} thing{'s' if n != 1 else ''} for you"}})
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": f"{digest.team_label} · {digest.generated_at}"}]})

    for name, rows in digest.sections():
        shown, hidden = rows[:max_rows], rows[max_rows:]
        if hidden:
            digest.truncated_sections[name] = len(hidden)
        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": f"*{SECTION_TITLE[name]}* ({len(rows)})"}})
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": SECTION_BLURB[name]}]})
        for r in shown:
            head = f"{_mrkdwn_link(r)} — {r.headline}"
            if r.is_stale:
                head += "  ⚠️"
            blocks.append({"type": "section",
                           "text": {"type": "mrkdwn", "text": head}})
            sub = r.detail
            if r.confidence != "high":
                sub += f"  ·  ARGUS confidence: {r.confidence}"
            if sub:
                blocks.append({"type": "context",
                               "elements": [{"type": "mrkdwn", "text": sub}]})
        if hidden:
            # Said out loud. A digest that quietly drops its tail is the
            # same bug as an alert that quietly stops firing.
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                           "text": f"_…and {len(hidden)} more — see the full report._"}]})

    blocks.append({"type": "divider"})
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": _noise_line(c)}]})
    if report_url:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"<{report_url}|Full report>"}]})

    # Slack refuses a message over its block limit outright, so trimming is
    # not a nicety. Trim from the end, and say so where the reader can see it.
    if len(blocks) > SLACK_BLOCK_LIMIT:
        blocks = blocks[:SLACK_BLOCK_LIMIT - 1]
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                       "text": "_Message truncated to fit Slack's limit — the full report has everything._"}]})
    return blocks


def render_slack_text(digest: Digest) -> str:
    """The fallback text, which is the push notification.

    Not decoration: this is the line that appears on a lock screen and
    decides whether the DM is opened at all.
    """
    if digest.all_clear:
        return "ARGUS standup: nothing stuck this morning."
    n = len(digest.rows)
    lead = digest.rows[0]
    return (f"ARGUS standup: {n} thing{'s' if n != 1 else ''} need attention — "
            f"top: {lead.item_key}, {lead.headline}")


# ---------------------------------------------------------------------------
# 7. Rendering — Slack, the channel post
# ---------------------------------------------------------------------------

def render_channel_blocks(digest: Digest) -> list[dict]:
    """The #dev-standup post: the temperature, and nobody's name.

    Dirgh's call, and the reasoning is worth keeping: a public board that
    names who is slow becomes a leaderboard, and a leaderboard changes what
    people do with their pull requests rather than what they do with their
    work. The team gets the shape of the morning; the lead's DM gets the
    detail. Deliberately carries no item keys either — a PR number names a
    person to anyone willing to click it.
    """
    c = digest.counts
    counts_by_section = {name: len(rows) for name, rows in digest.sections()}

    if digest.all_clear:
        return [
            {"type": "section", "text": {"type": "mrkdwn",
             "text": "*ARGUS — nothing stuck this morning.* :white_check_mark:"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": _noise_line(c)}]},
        ]

    bits = []
    for name in SECTION_ORDER:
        n = counts_by_section.get(name, 0)
        if n:
            bits.append(f"*{n}* {SECTION_TITLE[name].lower()}")
    if c.people_out:
        bits.append(f"*{c.people_out}* away")

    return [
        {"type": "section", "text": {"type": "mrkdwn",
         "text": "*ARGUS standup*\n" + "  ·  ".join(bits)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": _noise_line(c)}]},
        {"type": "context", "elements": [{"type": "mrkdwn",
         "text": "_Detail is in the tech lead's DM — this post names nobody on purpose._"}]},
    ]


def render_channel_text(digest: Digest) -> str:
    if digest.all_clear:
        return "ARGUS: nothing stuck this morning."
    return f"ARGUS standup: {len(digest.rows)} items need attention."


# ---------------------------------------------------------------------------
# 8. Rendering — the HTML report (old Phase 4's Radar, finally)
# ---------------------------------------------------------------------------

_CSS = """
:root{--bg:#fbfbfa;--card:#fff;--ink:#1f1e1c;--mut:#6b6862;--line:#e6e3dd;
--urgent:#b03a2e;--urgent-bg:#fdf1ef;--warn:#8a6116;--warn-bg:#fdf7ea;
--info:#2f5d8a;--info-bg:#eff5fb;--ok:#2e6b45;--ok-bg:#eef7f1;}
@media(prefers-color-scheme:dark){:root{--bg:#171614;--card:#201f1c;--ink:#eceae5;
--mut:#a09c94;--line:#33312d;--urgent:#f0857a;--urgent-bg:#2c1d1b;
--warn:#e5b95f;--warn-bg:#2b2418;--info:#8ab6e0;--info-bg:#1a222b;
--ok:#7dc79a;--ok-bg:#1a251e;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:23px;margin:0 0 4px;letter-spacing:-.01em}
.sub{color:var(--mut);font-size:13px;margin:0 0 28px}
.tiles{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 30px}
.tile{flex:1 1 130px;background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:25px;font-weight:600;letter-spacing:-.02em}
.tile span{color:var(--mut);font-size:12px}
h2{font-size:15px;margin:30px 0 2px;display:flex;align-items:center;gap:8px}
.pill{font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px}
.urgent .pill{background:var(--urgent-bg);color:var(--urgent)}
.warn .pill{background:var(--warn-bg);color:var(--warn)}
.info .pill{background:var(--info-bg);color:var(--info)}
.blurb{color:var(--mut);font-size:13px;margin:0 0 12px}
.row{background:var(--card);border:1px solid var(--line);border-left-width:3px;
border-radius:9px;padding:13px 15px;margin-bottom:9px}
.urgent .row{border-left-color:var(--urgent)}
.warn .row{border-left-color:var(--warn)}
.info .row{border-left-color:var(--info)}
.row .top{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
.row a,.row .key{font-weight:600;color:inherit;text-decoration:none;
border-bottom:1px solid var(--line)}
.row .age{margin-left:auto;color:var(--mut);font-size:12px;white-space:nowrap}
.row .head{margin:5px 0 0;font-size:15px}
.row .ttl{margin:3px 0 0;color:var(--mut);font-size:12.5px}
.row .det,.row .ev{color:var(--mut);font-size:13px;margin:4px 0 0}
.row .ev{font-style:italic;font-size:12px}
.tag{font-size:11px;color:var(--mut);border:1px solid var(--line);
border-radius:99px;padding:1px 7px}
.clear{background:var(--ok-bg);border:1px solid var(--line);border-left:3px solid var(--ok);
border-radius:9px;padding:18px}
.clear b{color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
td{padding:6px 8px;border-bottom:1px solid var(--line)}
td:last-child{text-align:right;color:var(--mut);white-space:nowrap}
.scroll{overflow-x:auto}
footer{margin-top:40px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);
padding-top:14px}
"""


def _e(s) -> str:
    return _html.escape("" if s is None else str(s))


def _counts_table(title: str, d: dict) -> str:
    if not d:
        return ""
    rows = "".join(
        f"<tr><td>{_e(k.replace('_', ' '))}</td><td>{v}</td></tr>"
        for k, v in sorted(d.items(), key=lambda kv: -kv[1]))
    return (f"<h2 class='info'><span>{_e(title)}</span></h2>"
            f"<div class='scroll'><table>{rows}</table></div>")


def render_html(digest: Digest) -> str:
    """A self-contained HTML report. No network, no assets, no build step.

    This is the artifact old Phase 4 described and never produced. It is
    the complete view — the Slack message truncates, this never does —
    which is why every truncation notice in the DM points here.
    """
    c = digest.counts
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>ARGUS standup — {_e(digest.team_label)}</title>",
        f"<style>{_CSS}</style></head><body><div class='wrap'>",
        "<h1>ARGUS standup digest</h1>",
        f"<p class='sub'>{_e(digest.team_label)} · generated {_e(digest.generated_at)}</p>",
    ]

    tiles = [
        (len(digest.rows), "need a human"),
        (c.items_checked, "items checked"),
        (c.suppressed, "suppressed as noise"),
        (c.people_out, "people away"),
    ]
    parts.append("<div class='tiles'>" + "".join(
        f"<div class='tile'><b>{v}</b><span>{_e(lab)}</span></div>" for v, lab in tiles)
        + "</div>")

    if digest.all_clear:
        parts.append(
            "<div class='clear'><b>Nothing stuck this morning.</b>"
            f"<p class='det' style='margin:6px 0 0'>{_e(_noise_line(c))}</p>"
            "<p class='blurb' style='margin:10px 0 0'>ARGUS ran and found nothing "
            "needing a person. This message exists so that a quiet morning and a "
            "broken tool do not look the same.</p></div>")

    for name, rows in digest.sections():
        tone = SECTION_TONE[name]
        parts.append(f"<section class='{tone}'>")
        parts.append(f"<h2><span>{_e(SECTION_TITLE[name])}</span>"
                     f"<span class='pill'>{len(rows)}</span></h2>")
        parts.append(f"<p class='blurb'>{_e(SECTION_BLURB[name])}</p>")
        for r in rows:
            key = (f"<a href='{_e(r.url)}'>{_e(r.item_key)}</a>" if r.url
                   else f"<span class='key'>{_e(r.item_key)}</span>")
            tags = ""
            if r.confidence != "high":
                tags += f"<span class='tag'>confidence: {_e(r.confidence)}</span>"
            if r.is_stale:
                tags += "<span class='tag'>worth re-checking</span>"
            parts.append(
                "<div class='row'>"
                f"<div class='top'>{key}{tags}"
                f"<span class='age'>{_e(r.age_label)}</span></div>"
                + (f"<p class='ttl'>{_e(r.title)}</p>" if r.title else "")
                + f"<p class='head'>{_e(r.headline)}</p>"
                + (f"<p class='det'>{_e(r.detail)}</p>" if r.detail else "")
                + (f"<p class='ev'>{_e(r.evidence)}</p>" if r.evidence else "")
                + "</div>")
        parts.append("</section>")

    parts.append(_counts_table("Suppressed, by reason", c.suppressed_by_reason))
    parts.append(_counts_table("No pattern matched, by reason", c.abstained_by_reason))
    if c.dm_skips_by_reason:
        parts.append(_counts_table("Triage DMs not sent, by reason", c.dm_skips_by_reason))
    if c.dm_failures_by_reason:
        parts.append(_counts_table("Triage DMs that failed, by reason", c.dm_failures_by_reason))
    if c.responses_all_time:
        parts.append(_counts_table("Developer answers, all time", c.responses_all_time))

    parts.append(
        "<footer>Every suppressed item above is an alert the GitHub-only version of "
        "ARGUS would have sent and this one did not. That count, not the flagged "
        "count, is what Phase 6 is judged on.<br>Generated offline from ARGUS's own "
        "records. Nothing here was inferred from a source that was not asked.</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# 9. Rendering — plain text, for a human reading a verification run
# ---------------------------------------------------------------------------

def render_text(digest: Digest) -> str:
    """The console rendering, and it is not an afterthought.

    Reading the run's own output table — not its pass line — has found the
    single real defect in each of the last three steps. This renderer
    exists so that the same method is available for this one.
    """
    out = [f"ARGUS standup — {digest.team_label} — {digest.generated_at}"]
    if digest.all_clear:
        out.append("  ALL CLEAR — nothing needing a human.")
    for name, rows in digest.sections():
        out.append(f"\n  [{SECTION_TITLE[name]}]  ({len(rows)})")
        for r in rows:
            out.append(f"    {r.item_key:<18} {r.age_label:>12}  {r.headline}")
            if r.detail:
                out.append(f"    {'':<18} {'':>12}  · {r.detail}")
    c = digest.counts
    out.append("\n  " + _noise_line(c))
    if c.dms_sent or c.dms_skipped or c.dms_failed:
        out.append(f"  DMs: {c.dms_sent} sent, {c.dms_skipped} skipped, {c.dms_failed} failed")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 10. The one call a daily job makes
# ---------------------------------------------------------------------------

@dataclass
class RenderedDigest:
    digest: Digest
    lead_blocks: list
    lead_text: str
    channel_blocks: list
    channel_text: str
    html: str

    def as_dict(self) -> dict:
        return {"digest": self.digest.as_dict(),
                "lead_blocks": self.lead_blocks, "lead_text": self.lead_text,
                "channel_blocks": self.channel_blocks,
                "channel_text": self.channel_text, "html_bytes": len(self.html)}


def build_digest(conn: sqlite3.Connection,
                 results: Iterable[SF.FilterResult],
                 now: str,
                 *,
                 sends: Optional[list] = None,
                 team_label: str = "your team",
                 report_url: Optional[str] = None) -> RenderedDigest:
    """Collect once, render three ways. The whole of 6.8 in one call."""
    d = collect(conn, results, now, sends=sends, team_label=team_label)
    return RenderedDigest(
        digest=d,
        lead_blocks=render_slack_blocks(d, report_url=report_url),
        lead_text=render_slack_text(d),
        channel_blocks=render_channel_blocks(d),
        channel_text=render_channel_text(d),
        html=render_html(d))


def send_digest(conn: sqlite3.Connection,
                transport: ST.SlackTransport,
                rendered: RenderedDigest,
                *,
                lead_slack_user_id: Optional[str] = None,
                channel_id: Optional[str] = None) -> dict:
    """Deliver a built digest. Separated from building on purpose.

    Every failure here is reported rather than raised: a channel post that
    fails because the bot was never invited must not cost the lead their
    DM, and neither failure should take down the daily job. 6.5 took
    DM-only scopes deliberately, so posting to a channel needs the bot
    invited to it — until 6.9 confirms that on a real workspace, a
    `not_in_channel` error is an expected outcome, not a crash.
    """
    out: dict = {"lead": None, "channel": None}

    if lead_slack_user_id:
        try:
            opened = transport.call("conversations.open", users=lead_slack_user_id)
            ch = (opened.get("channel") or {}).get("id")
            if not ch:
                out["lead"] = {"ok": False, "error": "dm_channel_not_opened"}
            else:
                posted = transport.call("chat.postMessage", channel=ch,
                                        text=rendered.lead_text,
                                        blocks=rendered.lead_blocks)
                out["lead"] = {"ok": True, "channel": ch, "ts": posted.get("ts")}
        except ST.SlackError as exc:
            out["lead"] = {"ok": False, "error": exc.error, "method": exc.method}

    if channel_id:
        try:
            posted = transport.call("chat.postMessage", channel=channel_id,
                                    text=rendered.channel_text,
                                    blocks=rendered.channel_blocks)
            out["channel"] = {"ok": True, "channel": channel_id, "ts": posted.get("ts")}
        except ST.SlackError as exc:
            out["channel"] = {"ok": False, "error": exc.error, "method": exc.method}

    return out


if __name__ == "__main__":                                  # pragma: no cover
    print(json.dumps({"module": "digest", "step": "6.8",
                      "sections": SECTION_ORDER,
                      "max_unanswered_asks": MAX_UNANSWERED_ASKS}, indent=2))
