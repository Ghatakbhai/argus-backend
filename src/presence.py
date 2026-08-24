"""
ARGUS — Phase 6, step 6.7: presence / out-of-office detection.

Stops ARGUS sending a triage DM to somebody who is on holiday.

The whole step turns on one distinction that is easy to get wrong and
expensive to get wrong:

    Slack's `users.getPresence` "away" is NOT out of office.

Slack's own reference says `away` is an idle signal — a client goes
`auto_away` after ten minutes of no activity. Wiring suppression to it
would silence alerts for anybody at lunch, in a long meeting, or typing in
a different app, and it would do so invisibly. Verified against Slack's
current documentation rather than assumed (D-112's rule); recorded here
because the wrong choice looks perfectly reasonable from the method name.

So presence is read from the **profile status** instead — the thing a
person deliberately sets to tell colleagues they are away — via
`users.profile.get`, which needs the `users.profile:read` scope that D-115
deliberately declined to request in advance.

Two further design rules, both inherited:

* **Positive evidence only** (D-114's gate discipline). A status is treated
  as out-of-office when it matches something that affirmatively says so.
  An unreadable, empty or unrecognised status is `'unknown'`, and unknown
  never suppresses. ARGUS not knowing where somebody is, is not a reason to
  go quiet about their work.

* **Suppression is a delay, never a deletion.** A held alert is recorded,
  is released when the person is back, and — once it has been held long
  enough that waiting is no longer sensible — is surfaced to the tech lead,
  because reassigning work is something only a human can do. Silence that
  looks like success is this project's characteristic bug, and presence
  detection is a very easy place to reintroduce it.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional

import slack_triage as ST

# ---------------------------------------------------------------------------
# 1. What counts as "away", and what emphatically does not
# ---------------------------------------------------------------------------

AVAILABLE = "available"
OUT_OF_OFFICE = "out_of_office"
UNKNOWN = "unknown"

# Checked FIRST. These are statuses of people who are working — somebody in
# a meeting or working from home is reachable, and an item that has already
# been idle for 48 hours is not disturbed by a 30-minute calendar block.
# Slack's calendar integrations set a meeting emoji routinely, so without
# this list a team that syncs its calendars would silence a large share of
# its alerts every afternoon, invisibly.
STILL_WORKING_PATTERNS = [
    r"\bin a (call|meeting|interview)\b",
    r"\bmeeting\b",
    r"\bfocus(ing|sed)?\b",
    r"\bdeep work\b",
    r"\bheads down\b",
    r"\bcommut(e|ing)\b",
    r"\blunch\b",
    r"\bcoffee\b",
    r"\bbrb\b",
    r"\bback in \d+ ?(m|min|mins|minutes)\b",
    r"\bwfh\b",
    r"\bwork(ing)? from home\b",
    r"\bremote\b",
    r"\bon ?site\b",
]

STILL_WORKING_EMOJI = {
    ":spiral_calendar_pad:",   # what Slack's calendar apps set for a meeting
    ":calendar:",
    ":date:",
    ":headphones:",
    ":coffee:",
    ":hamburger:",
    ":house_with_garden:",     # the conventional "working from home"
    ":house:",
    ":bust_in_silhouette:",
}

# Positive out-of-office evidence. Text patterns come first in importance,
# because text survives workspaces that use their own custom emoji.
OOO_TEXT_PATTERNS = [
    r"\booo\b",
    r"\bo\.o\.o\.?",
    r"\bout of (the )?office\b",
    r"\bon (leave|vacation|holidays?|sabbatical)\b",
    r"\bannual leave\b",
    r"\bparental leave\b|\bmaternity\b|\bpaternity\b",
    r"\bsick (leave|day|today)\b|\boff sick\b",
    r"\bpto\b",
    r"\bvacation\b",
    r"\bsabbatical\b",
    r"\bbereavement\b",
    r"\baway until\b|\bback on\b|\bback \w+day\b",
    r"\bpublic holiday\b|\bbank holiday\b",
]

# Slack's own built-in Out of Office feature displays the glyph ⛔ —
# confirmed at 6.9 against Slack's current help article ("the default ⛔
# out-of-office emoji will be displayed in your Slack status"). ⛔'s standard
# Slack/Unicode shortcode is `:no_entry:`, also confirmed at 6.9 against
# Slack's published emoji reference. What is STILL not documented anywhere
# (checked docs.slack.dev's presence-and-status page directly, 6.9) is
# whether the built-in feature's API payload literally writes the string
# `":no_entry:"` into `status_emoji`, or something else internally that
# renders to the same glyph — so `:no_entry:` remains the reasonable
# reading, one step more confirmed than before, not a proven API value. The
# text rules above still stand on their own for that reason. First real
# Slack account (6.9 live run) settles the API-payload question outright.
OOO_EMOJI = {
    ":no_entry:",               # glyph+shortcode confirmed 6.9; API payload still unproven, see above
    ":palm_tree:",
    ":desert_island:",
    ":beach_with_umbrella:",
    ":umbrella_on_ground:",
    ":face_with_thermometer:",
    ":sneezing_face:",
    ":thermometer:",
    ":hospital:",
    ":baby:",
    ":cradle:",
}

_STILL_WORKING_RE = [re.compile(p, re.I) for p in STILL_WORKING_PATTERNS]
_OOO_RE = [re.compile(p, re.I) for p in OOO_TEXT_PATTERNS]

# How long somebody must be continuously out before their held work is put in
# front of the tech lead. Below this, absences mostly resolve themselves and
# escalating would be noise; above it, a pull request can sit dead for a
# fortnight while ARGUS knows and says nothing — which is the exact problem
# ARGUS exists to solve. Dirgh's call, session 33.
LEAD_ESCALATION_DAYS = 5

# How many held alerts are released to one person per day once they return.
# A person's first morning back is when they are least able to absorb a wall
# of notifications and most likely to mute the app. Applies ONLY to alerts
# that were actually held for presence — a normal day's fresh alerts are
# unaffected. Dirgh's call, session 33.
MAX_HELD_RELEASES_PER_DAY = 2


@dataclass
class Classification:
    status: str                    # available | out_of_office | unknown
    reason: str                    # machine-readable
    matched: Optional[str] = None  # the emoji or phrase that decided it


def classify_status(status_text: Optional[str],
                    status_emoji: Optional[str]) -> Classification:
    """Read one Slack profile status. Positive evidence only.

    Order matters: "still working" is checked before "out of office", so a
    status like ":spiral_calendar_pad: In a meeting until Friday" reads as a
    working person with a long meeting rather than as a week off.
    """
    text = (status_text or "").strip()
    emoji = (status_emoji or "").strip().lower()

    if not text and not emoji:
        return Classification(UNKNOWN, "no_status_set")

    if emoji in STILL_WORKING_EMOJI:
        return Classification(AVAILABLE, "working_emoji", emoji)
    for rx in _STILL_WORKING_RE:
        m = rx.search(text)
        if m:
            return Classification(AVAILABLE, "working_text", m.group(0))

    if emoji in OOO_EMOJI:
        return Classification(OUT_OF_OFFICE, "ooo_emoji", emoji)
    for rx in _OOO_RE:
        m = rx.search(text)
        if m:
            return Classification(OUT_OF_OFFICE, "ooo_text", m.group(0))

    # A status we do not recognise. Deliberately NOT read as available and
    # deliberately NOT read as away: we simply do not know, and unknown
    # never suppresses.
    return Classification(UNKNOWN, "unrecognised_status", text or emoji)


# ---------------------------------------------------------------------------
# 2. Reading Slack, writing intervals
# ---------------------------------------------------------------------------

def _unix_to_iso(ts: Any) -> Optional[str]:
    """Slack's status_expiration is a Unix timestamp; 0 or absent means never."""
    try:
        n = int(ts)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return ST._iso(datetime.fromtimestamp(n, tz=timezone.utc))


@dataclass
class PresenceReading:
    actor_id: int
    login: str
    slack_user_id: Optional[str]
    status: str
    reason: str
    matched: Optional[str] = None
    effective_to: Optional[str] = None
    wrote_row: bool = False
    detail: str = ""


def ingest_presence(conn: sqlite3.Connection,
                    integration_id: int,
                    logins: Iterable[str],
                    transport: Optional[ST.SlackTransport],
                    now: str) -> list[PresenceReading]:
    """Read each person's Slack status and record it as an interval.

    Stored as an interval rather than a flag (schema section 12's own rule),
    so 6.8 and Phase 7 can ask "were they out when we decided not to message
    them" about any historical message, not only "are they out right now".

    **`effective_from` is a lower bound, not the truth.** Slack reports the
    current status; it does not say when it was set. So the interval starts
    when ARGUS first *observed* it — somebody who left on Friday and is first
    observed on Monday gets a presence row starting Monday. This is the same
    honesty Part I applied to `days_silent` with `is_lower_bound` (D-063):
    the real absence can only ever be longer than recorded, never shorter. It
    matters for LEAD_ESCALATION_DAYS, which will therefore fire late rather
    than early — the safe direction, since an early escalation would put a
    colleague's name in front of a manager on thin evidence.
    """
    ST._require_now(now)
    out: list[PresenceReading] = []

    for login in logins:
        actor_id = ST._actor_id_for_login(conn, login)
        if actor_id is None:
            out.append(PresenceReading(-1, login, None, UNKNOWN, "unknown_actor",
                                       detail=f"no github actor named {login!r}"))
            continue

        row = conn.execute(
            """SELECT slack_user_id FROM slack_identity
               WHERE integration_id = ? AND actor_id = ? AND slack_user_id IS NOT NULL""",
            (integration_id, actor_id)).fetchone()
        if not row:
            # Not an error: 6.6 already refuses to message people it cannot
            # identify, so there is nobody here whose presence would matter.
            out.append(PresenceReading(actor_id, login, None, UNKNOWN,
                                       "no_slack_identity",
                                       detail="not resolved to a Slack account"))
            continue
        slack_user_id = row[0]

        if transport is None:
            out.append(PresenceReading(actor_id, login, slack_user_id, UNKNOWN,
                                       "no_transport"))
            continue

        try:
            data = transport.call("users.profile.get", user=slack_user_id)
        except ST.SlackError as exc:
            # An API failure is not evidence of anything. Left unknown, and
            # unknown never suppresses — so a Slack outage makes ARGUS
            # noisier, never quieter. That is the correct direction to fail.
            out.append(PresenceReading(actor_id, login, slack_user_id, UNKNOWN,
                                       "lookup_failed", detail=exc.error))
            continue

        profile = data.get("profile") or {}
        cls = classify_status(profile.get("status_text"), profile.get("status_emoji"))
        expires = _unix_to_iso(profile.get("status_expiration"))

        wrote = _record_interval(conn, actor_id, cls.status, now, expires)
        out.append(PresenceReading(actor_id, login, slack_user_id, cls.status,
                                   cls.reason, cls.matched, expires, wrote,
                                   detail=(profile.get("status_text") or "").strip()))

    conn.commit()
    return out


def _record_interval(conn: sqlite3.Connection, actor_id: int, status: str,
                     now: str, effective_to: Optional[str]) -> bool:
    """Extend the open interval if unchanged; otherwise close it and open a new one.

    Returns True if a new row was written. Re-running on the same day must
    not pile up one row per run — the same idempotency discipline D-112's
    changelog-doubling bug taught.
    """
    open_row = conn.execute(
        """SELECT id, status, effective_to FROM presence
           WHERE actor_id = ? AND (effective_to IS NULL OR effective_to > ?)
           ORDER BY effective_from DESC, id DESC LIMIT 1""",
        (actor_id, now)).fetchone()

    if open_row and open_row[1] == status:
        # Same state as we already believe. Only the known end time can move.
        if effective_to != open_row[2]:
            conn.execute("UPDATE presence SET effective_to = ?, detected_at = ? WHERE id = ?",
                         (effective_to, now, open_row[0]))
        return False

    if open_row:
        conn.execute("UPDATE presence SET effective_to = ? WHERE id = ?", (now, open_row[0]))

    conn.execute(
        """INSERT INTO presence (actor_id, status, detected_via, effective_from,
                                  effective_to, detected_at)
           VALUES (?,?, 'slack_status', ?,?,?)""",
        (actor_id, status, now, effective_to, now))
    return True


# ---------------------------------------------------------------------------
# 3. Asking the historical question
# ---------------------------------------------------------------------------

@dataclass
class PresenceAt:
    status: str
    presence_id: Optional[int] = None
    effective_from: Optional[str] = None
    effective_to: Optional[str] = None

    @property
    def is_out(self) -> bool:
        return self.status == OUT_OF_OFFICE


def presence_at(conn: sqlite3.Connection, actor_id: int, at: str) -> PresenceAt:
    """What did we believe about this person at this moment?

    Unknown when no interval covers it — never guessed, never carried
    forward from an interval that has already expired.
    """
    ST._require_now(at)
    row = conn.execute(
        """SELECT id, status, effective_from, effective_to FROM presence
           WHERE actor_id = ? AND effective_from <= ?
             AND (effective_to IS NULL OR effective_to > ?)
           ORDER BY effective_from DESC, id DESC LIMIT 1""",
        (actor_id, at, at)).fetchone()
    if not row:
        return PresenceAt(UNKNOWN)
    return PresenceAt(row[1], row[0], row[2], row[3])


def out_of_office_since(conn: sqlite3.Connection, actor_id: int,
                        at: str) -> Optional[str]:
    """When the current unbroken absence began, or None if they are not out."""
    p = presence_at(conn, actor_id, at)
    return p.effective_from if p.is_out else None


# ---------------------------------------------------------------------------
# 4. The checks 6.6's send path calls
# ---------------------------------------------------------------------------

def make_presence_check(conn: sqlite3.Connection) -> Callable[[int, str], Optional[dict]]:
    """Build the callable `slack_triage.send_triage_dms` accepts.

    Returns None when the DM should go ahead, or a dict describing why it is
    being held. Written as an injected callable rather than an import inside
    slack_triage so that step 6.6 keeps working, and keeps being testable,
    with no presence data at all — a team that has not granted
    `users.profile:read` still gets triage DMs, just without this filter.
    """

    def check(actor_id: int, at: str) -> Optional[dict]:
        p = presence_at(conn, actor_id, at)
        if not p.is_out:
            return None
        return {"reason": "out_of_office",
                "presence_id": p.presence_id,
                "since": p.effective_from,
                "until": p.effective_to,
                "detail": f"out of office since {p.effective_from}"
                          + (f", expected back {p.effective_to}" if p.effective_to else "")}

    return check


def held_release_limiter(conn: sqlite3.Connection,
                         max_per_day: int = MAX_HELD_RELEASES_PER_DAY
                         ) -> Callable[[int, int, str], Optional[dict]]:
    """Drip previously-held alerts back out rather than dumping them at once.

    Applies ONLY to work items that were actually held for presence. A normal
    day's fresh alerts are untouched — the problem being solved is
    specifically the wall of notifications on somebody's first morning back,
    not the ordinary volume of a working week. Deliberately narrow, so this
    step cannot quietly change 6.6's behaviour for teams nobody is away on.
    """

    def limit(actor_id: int, work_item_id: int, at: str) -> Optional[dict]:
        # An item counts as "still in the backlog" only while it has a hold
        # that has not yet been followed by a real send.
        #
        # Written this way because of a defect found by simulating six weeks
        # of runs: the first version asked only "was this item ever held",
        # which is true forever once it has been true once. Five weeks after
        # everybody was back, with nobody away, an item was still being
        # throttled — a delay meant for one morning had silently become
        # permanent, visible only to somebody reading the reason strings.
        # Same shape as 6.6's expiry bug and 6.4's double-abstain: a
        # temporary state quietly becoming the permanent one.
        unreleased = conn.execute(
            """SELECT 1 FROM triage_message h
               WHERE h.work_item_id = ? AND h.status = 'suppressed_presence'
                 AND NOT EXISTS (
                     SELECT 1 FROM triage_message s
                     WHERE s.work_item_id = h.work_item_id
                       AND s.status <> 'suppressed_presence'
                       AND s.sent_at > h.sent_at)
               LIMIT 1""",
            (work_item_id,)).fetchone()
        if not unreleased:
            return None

        since = ST._iso(ST._require_now(at) - timedelta(days=1))
        released = conn.execute(
            """SELECT COUNT(*) FROM triage_message m
               WHERE m.sent_to_actor_id = ? AND m.status <> 'suppressed_presence'
                 AND m.sent_at > ?""",
            (actor_id, since)).fetchone()[0]
        if released >= max_per_day:
            return {"reason": "held_release_drip",
                    "detail": f"{released} alert(s) already went to this person in the "
                              f"last 24h (limit {max_per_day} while clearing a backlog)"}
        return None

    return limit


# ---------------------------------------------------------------------------
# 5. What the tech lead needs to be told
# ---------------------------------------------------------------------------

@dataclass
class Escalation:
    work_item_id: int
    item_key: str
    blocked_on_login: str
    out_since: str
    days_out: float
    held_alerts: int
    detail: str

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["days_out"] = round(self.days_out, 1)
        return d


def escalations_due(conn: sqlite3.Connection, now: str,
                    after_days: int = LEAD_ESCALATION_DAYS) -> list[Escalation]:
    """Items held so long that a human needs to consider reassigning them.

    Nobody but a person can reassign work, so this is the point where
    presence suppression stops being the right answer. Step 6.8's morning
    digest is what the tech lead reads, and that is where these belong —
    this function produces the facts, 6.8 renders them.

    Note what is deliberately NOT done here: ARGUS does not DM a lead
    directly, because "who is the tech lead" is not a concept this schema
    models, and inventing one here would be guessing at a team's structure.
    Naming that gap rather than papering over it leaves it for 6.9, which is
    the first step with a real team to ask.
    """
    now_dt = ST._require_now(now)
    cutoff = ST._iso(now_dt - timedelta(days=after_days))

    rows = conn.execute(
        """SELECT DISTINCT m.work_item_id, a.id, a.source_key
           FROM triage_message m
           JOIN actor a ON a.id = m.sent_to_actor_id
           WHERE m.status = 'suppressed_presence'
           ORDER BY m.work_item_id"""
    ).fetchall()

    out = []
    for work_item_id, actor_id, login in rows:
        since = out_of_office_since(conn, actor_id, now)
        if since is None or since > cutoff:
            continue  # back at work, or not away long enough yet
        answered = conn.execute(
            """SELECT 1 FROM triage_response r JOIN triage_message m
                      ON m.id = r.triage_message_id
               WHERE m.work_item_id = ? LIMIT 1""", (work_item_id,)).fetchone()
        if answered:
            continue  # somebody already dealt with it; not stuck on the absence
        # Scoped to the CURRENT unbroken absence, not a lifetime total across
        # every separate absence this person has ever had (D-118's wording
        # bug, fixed at source here per D-118's own note, carried to 6.9).
        held = conn.execute(
            """SELECT COUNT(*) FROM triage_message m
               WHERE m.work_item_id = ? AND m.sent_to_actor_id = ?
                 AND m.status = 'suppressed_presence' AND m.sent_at >= ?""",
            (work_item_id, actor_id, since)).fetchone()[0]
        days = (now_dt - ST._parse(since)).total_seconds() / 86400.0
        out.append(Escalation(
            work_item_id, ST.item_key_of(conn, work_item_id), login, since, days, held,
            detail=f"{login} has been out since {since} ({days:.1f}d); "
                   f"{held} alert(s) held during this absence. Nobody else has been asked."))
    return out


def summarise_presence(readings: list[PresenceReading]) -> dict:
    out = {"people": len(readings), "by_status": {}, "by_reason": {}, "rows_written": 0}
    for r in readings:
        out["by_status"][r.status] = out["by_status"].get(r.status, 0) + 1
        out["by_reason"][r.reason] = out["by_reason"].get(r.reason, 0) + 1
        out["rows_written"] += int(r.wrote_row)
    return out
