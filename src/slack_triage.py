"""
ARGUS — Phase 6, step 6.6: the 1-click interactive triage DM.

Takes the FIRE rows the sprint filter (6.4) produces, sends each one as a
direct message to the one person it is waiting on, and writes that person's
button click back into the entity model.

Three buttons, per the roadmap:

    [Handled Offline]   the developer already dealt with it somewhere ARGUS
                        cannot see — the "dark matter" Part I proved was the
                        ceiling. This click is ARGUS being TOLD the answer.
    [Blocked on X]      it is genuinely stuck, on something named. Opens a
                        small dialog asking what, so the standup digest (6.8)
                        can say what it is blocked on rather than just that
                        it is blocked.
    [Snooze 7d]         real, known, not now.

Design rules this module holds to, inherited from earlier steps:

* **Nothing is silent by omission** (D-114's rule). Every FIRE handed to
  `send_triage_dms` comes back with exactly one explicit outcome and a
  machine-readable reason — including the ones that were deliberately not
  sent. A pipeline whose default is silence must be able to show what it
  was silent about.

* **A well-formed identifier is not a resolved one** (D-114's rule, applied
  to people instead of ticket keys). A GitHub login that looks like a Slack
  handle is not a Slack account. If this module cannot positively identify
  the recipient it sends nothing, records `recipient_unresolved`, and says
  so. Sending a stranger somebody else's PR is a worse failure than silence.

* **No wall-clock now()** (D-064's rule). Every time comparison here runs
  against an explicitly passed `now`, so a run is reproducible and a test is
  deterministic.

* **Idempotency is assumed to be needed, not assumed to be absent**
  (D-112's changelog-doubling bug). Slack retries deliveries; a retried
  button click must not write a second response row.

* **The network is not available from the sandbox** (D-111/D-115). Every
  Slack call goes through a `SlackTransport` seam, so the whole send →
  click → write-back cycle is testable offline. `HttpSlackTransport` is the
  real one and is exercised for the first time at step 6.9.
"""

from __future__ import annotations

import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional

import sprint_filter as SF

# ---------------------------------------------------------------------------
# 1. Constants — every tunable in one readable place
# ---------------------------------------------------------------------------

SLACK_API_BASE = "https://slack.com/api/"

# How long after ANY answered triage DM this module stays quiet about the
# same work item.
#
# [Snooze 7d] says this explicitly, so 7 days is its literal meaning. The
# other two buttons get the same window for a different reason: ARGUS's
# view of the item will usually look identical tomorrow — "handled offline"
# and "blocked on the infra team" are both facts about the world that the
# GitHub API cannot see — so re-sending tomorrow would ask the same person
# the same question they already answered. That is the alert-fatigue
# failure mode Phase 7's kill criterion names, and it is the fastest way to
# get an app muted.
#
# One constant, one meaning, visible: the cooling-off period is computed at
# send time from the response rows, never written into
# `triage_message.snooze_until`, which schema section 12 defines as
# specifically the [Snooze 7d] field.
SNOOZE_DAYS = 7
RESPONSE_COOLDOWN_DAYS = 7

# How long an unanswered DM stays open before it is written off as ignored.
#
# This exists because of a failure found by reading a simulated month of runs
# rather than by a test: without it, a DM nobody ever clicks sits at status
# 'sent' forever, and because `should_send` refuses to send while one is open,
# ARGUS goes permanently silent about that item. Silence caused by a developer
# ignoring one message is indistinguishable, from the outside, from silence
# because everything is fine — the exact failure mode this project has spent
# five phases refusing to ship.
#
# Expiry converts it into a counted fact. A non-response is data: Phase 7 is
# scored on alert satisfaction, and "sent, never answered" is one of the most
# informative things a pilot can tell us.
EXPIRE_UNANSWERED_DAYS = 7

CALLBACK_BLOCKED_ON = "argus_blocked_on_modal"

ACTION_HANDLED_OFFLINE = "argus_handled_offline"
ACTION_BLOCKED_ON = "argus_blocked_on"
ACTION_SNOOZE_7D = "argus_snooze_7d"

# The modal's one input. Both ids are needed to read the typed text back:
# a view_submission payload nests it as state.values[block_id][action_id].value
# (confirmed against Slack's own reference, not from memory — D-112's rule).
BLOCKED_ON_BLOCK_ID = "argus_blocked_on_block"
BLOCKED_ON_ACTION_ID = "argus_blocked_on_input"

ACTION_TO_RESPONSE_TYPE = {
    ACTION_HANDLED_OFFLINE: "handled_offline",
    ACTION_BLOCKED_ON: "blocked_on",
    ACTION_SNOOZE_7D: "snooze_7d",
}

# Slack's own documented limit on a button's `value`.
BUTTON_VALUE_MAX = 2000

# Send outcomes. One of these per FIRE, always.
SENT = "SENT"
SKIPPED = "SKIPPED"
FAILED = "FAILED"


# ---------------------------------------------------------------------------
# 2. Time helpers — all anchored to an explicit `now`
# ---------------------------------------------------------------------------

def _parse(ts: Optional[str]) -> Optional[datetime]:
    return SF.parse_dt(ts)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_now(now: str) -> datetime:
    dt = _parse(now)
    if dt is None:
        raise ValueError(
            f"slack_triage needs an explicit, parseable reference time; got {now!r}. "
            "This module never reads wall-clock now() (D-064)."
        )
    return dt


# ---------------------------------------------------------------------------
# 3. The Slack transport seam
# ---------------------------------------------------------------------------

class SlackError(RuntimeError):
    """A Slack API call that returned ok:false, carrying Slack's own error."""

    def __init__(self, method: str, error: str, payload: Optional[dict] = None):
        super().__init__(f"slack {method} failed: {error}")
        self.method = method
        self.error = error
        self.payload = payload or {}


class SlackTransport:
    """One method, so the whole of Slack can be faked in a test.

    Implementations return Slack's parsed JSON response and raise
    SlackError on ok:false rather than returning it, so a caller cannot
    accidentally treat a failed post as a successful one.
    """

    def call(self, method: str, **args: Any) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class HttpSlackTransport(SlackTransport):
    """The real one.

    NOT exercised anywhere in this project yet: D-115 established that this
    sandbox cannot reach slack.com at all, the same finding D-111 made for
    Atlassian and Linear. Step 6.9, on Dirgh's own staging environment, is
    the first time this class runs against the real API. It is written
    against Slack's published request/response field names, checked at build
    time rather than recalled.
    """

    def __init__(self, bot_token: str, base: str = SLACK_API_BASE, timeout: float = 15.0):
        if not bot_token or not bot_token.startswith("xoxb-"):
            raise ValueError("expected a bot token beginning 'xoxb-'")
        self._token = bot_token
        self._base = base
        self._timeout = timeout

    def call(self, method: str, **args: Any) -> dict:
        # Slack accepts JSON bodies with a bearer token for these methods,
        # which avoids URL-encoding a blocks array by hand.
        body = json.dumps({k: v for k, v in args.items() if v is not None}).encode("utf-8")
        req = urllib.request.Request(
            self._base + method,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Authorization": f"Bearer {self._token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:  # network refused, DNS, timeout
            raise SlackError(method, f"transport_error: {exc}") from exc
        if not data.get("ok"):
            raise SlackError(method, data.get("error", "unknown_error"), data)
        return data


def load_bot_token(path: str) -> str:
    """Read the bot token from a file on disk.

    The credential lives in `secrets/` on Dirgh's own machine and is never
    written into the database or a tracked document — `integration`
    stores a POINTER to this path, per schema section 12 and D-087.
    """
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


# ---------------------------------------------------------------------------
# 4. Identity: which Slack account is this person?
# ---------------------------------------------------------------------------

@dataclass
class Identity:
    actor_id: int
    login: str
    slack_user_id: Optional[str]
    resolved_via: str            # manual_map | email_lookup | unresolved
    matched_email: Optional[str] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.slack_user_id is not None


def _actor_id_for_login(conn: sqlite3.Connection, login: str) -> Optional[int]:
    """The GitHub actor with this login.

    Scoped to the github source deliberately. A Jira user and a GitHub user
    can share a display name without being the same person, and this module
    resolves the person a GitHub-side alert is waiting on.
    """
    row = conn.execute(
        """SELECT a.id FROM actor a JOIN source s ON s.id = a.source_id
           WHERE s.name = 'github' AND a.source_key = ?""",
        (login,),
    ).fetchone()
    return row[0] if row else None


def resolve_identity(conn: sqlite3.Connection,
                     integration_id: int,
                     login: str,
                     transport: Optional[SlackTransport],
                     now: str,
                     email_for_login: Optional[Callable[[str], Optional[str]]] = None,
                     manual_map: Optional[dict[str, str]] = None) -> Identity:
    """Find the Slack account for a GitHub login, in order of trustworthiness.

    1. A `slack_identity` row already resolved in a previous run — cached,
       so a daily run does not re-query Slack for every developer.
    2. An explicit manual mapping supplied by the team. Most trustworthy:
       a human said so.
    3. An email lookup via `users.lookupByEmail` (the `users:read.email`
       scope D-115 deliberately requested for exactly this).

    Where the email comes from is ARGUS's own declared contract, not a
    field read from the frozen Phase 2 schema — `actor` has no email
    column and section 2 is frozen. `email_for_login` is that contract:
    step 6.9, which is the first step with a live GitHub org, supplies it.
    This is the same move D-113 and D-114 made when a needed shape could
    not be confirmed: name the gap, define the contract, put the burden on
    the step that first has real access.

    Anything unresolved is WRITTEN as unresolved rather than dropped, and
    the caller sends nothing.
    """
    actor_id = _actor_id_for_login(conn, login)
    if actor_id is None:
        return Identity(-1, login, None, "unresolved",
                        detail=f"no github actor named {login!r} in this database")

    cached = conn.execute(
        """SELECT slack_user_id, resolved_via, matched_email FROM slack_identity
           WHERE integration_id = ? AND actor_id = ?""",
        (integration_id, actor_id),
    ).fetchone()
    if cached and cached[0]:
        return Identity(actor_id, login, cached[0], cached[1], cached[2],
                        detail="from a previous run")

    def _store(slack_user_id: Optional[str], via: str, email: Optional[str]) -> None:
        conn.execute(
            """INSERT INTO slack_identity
                   (integration_id, actor_id, slack_user_id, matched_email,
                    resolved_via, resolved_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT (integration_id, actor_id) DO UPDATE SET
                   slack_user_id = excluded.slack_user_id,
                   matched_email = excluded.matched_email,
                   resolved_via  = excluded.resolved_via,
                   resolved_at   = excluded.resolved_at""",
            (integration_id, actor_id, slack_user_id, email, via, now),
        )

    if manual_map and login in manual_map:
        uid = manual_map[login]
        _store(uid, "manual_map", None)
        return Identity(actor_id, login, uid, "manual_map", detail="explicit team mapping")

    email = email_for_login(login) if email_for_login else None
    if email and transport is not None:
        try:
            data = transport.call("users.lookupByEmail", email=email)
            uid = (data.get("user") or {}).get("id")
            if uid:
                _store(uid, "email_lookup", email)
                return Identity(actor_id, login, uid, "email_lookup", email,
                                detail=f"matched on {email}")
            reason = "slack returned ok with no user id"
        except SlackError as exc:
            # users_not_found also covers a deactivated account. Either way
            # we do not have a person to message.
            reason = f"users.lookupByEmail: {exc.error}"
    elif email and transport is None:
        reason = "no Slack transport available to look the email up"
    else:
        reason = "no email known for this login (see email_for_login contract)"

    _store(None, "unresolved", email)
    return Identity(actor_id, login, None, "unresolved", email, detail=reason)


# ---------------------------------------------------------------------------
# 5. Composing the message
# ---------------------------------------------------------------------------

PATTERN_HEADLINE = {
    "P1-approved-unmerged": "This PR is approved and still unmerged",
    "P2-review-ghosted": "This PR is waiting on your review",
    "P3-ghost-state": "GitHub and the ticket board disagree about this",
    "P4-reviewer-ooo-sprint-end": "Your reviewer is away and the cycle is closing",
}

PATTERN_ASK = {
    "P1-approved-unmerged": "It has an approval and CI is green — is something holding the merge?",
    "P2-review-ghosted": "A review was requested and there has been no response yet.",
    "P3-ghost-state": "The pull request and the linked ticket are in states that "
                      "cannot both be current — worth a look at which one is stale.",
    "P4-reviewer-ooo-sprint-end": "The requested reviewer is out of office and nobody "
                                  "else has been asked to cover it yet.",
}


def _hours_phrase(hours: Optional[float], is_lower_bound: bool) -> str:
    if hours is None:
        return "for a while"
    if hours >= 48:
        n = hours / 24.0
        unit = f"{n:.1f} days".replace(".0 days", " days")
    else:
        unit = f"{hours:.0f} hours"
    return ("for at least " if is_lower_bound else "for ") + unit


def button_value(result: SF.FilterResult) -> str:
    """What travels on the button.

    Deliberately NOT the triage_message id: the row cannot exist until
    Slack has returned a message ts, and the ts is what the row is keyed
    on. The click is matched back to its row by (channel, message ts),
    which Slack always supplies in the interaction payload and which is
    unique. This value is carried for auditing and for a human reading a
    raw payload — never trusted as the lookup key, because a value on a
    button is client-supplied data.
    """
    v = json.dumps({"v": 1, "work_item_id": result.work_item_id,
                    "item": result.item_key, "pattern": result.pattern},
                   separators=(",", ":"))
    return v[:BUTTON_VALUE_MAX]


def compose_blocks(result: SF.FilterResult, item_url: Optional[str] = None) -> list[dict]:
    """The Block Kit body of one triage DM.

    Written to be readable by the developer receiving it in three seconds:
    what, how long, what the sprint board says, three buttons. The evidence
    line the filter produced is included verbatim rather than paraphrased,
    so a developer who disagrees can see precisely what ARGUS concluded and
    why — a wrong alert should be arguable, not mysterious.
    """
    headline = PATTERN_HEADLINE.get(result.pattern or "", "This item looks stuck")
    ask = PATTERN_ASK.get(result.pattern or "", "")
    title = f"*{headline}*\n<{item_url}|{result.item_key}>" if item_url \
        else f"*{headline}*\n`{result.item_key}`"

    ctx_bits = [f"Idle {_hours_phrase(result.hours_idle, result.is_lower_bound)}"]
    if result.sprint_name:
        ctx_bits.append(f"{result.ticket_keys[0] if result.ticket_keys else 'ticket'} "
                        f"· {result.ticket_status} in {result.sprint_name}")
    if result.confidence != "high":
        # Said out loud rather than hidden: ARGUS's own read of how complete
        # its evidence is belongs in front of the person being asked to act.
        ctx_bits.append(f"ARGUS confidence: {result.confidence}")

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {"type": "context",
         "elements": [{"type": "mrkdwn", "text": "  ·  ".join(ctx_bits)}]},
    ]
    if ask:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ask}})
    if result.evidence:
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": f"_{result.evidence}_"}]})

    val = button_value(result)
    blocks.append({
        "type": "actions",
        "block_id": "argus_triage_actions",
        "elements": [
            {"type": "button", "action_id": ACTION_HANDLED_OFFLINE,
             "text": {"type": "plain_text", "text": "Handled offline"},
             "value": val},
            {"type": "button", "action_id": ACTION_BLOCKED_ON,
             "text": {"type": "plain_text", "text": "Blocked on…"},
             "value": val},
            {"type": "button", "action_id": ACTION_SNOOZE_7D,
             "text": {"type": "plain_text", "text": "Snooze 7d"},
             "value": val},
        ],
    })
    return blocks


def compose_fallback_text(result: SF.FilterResult) -> str:
    """The `text` argument, which is not decoration.

    Slack uses it for the notification preview and for any client that
    cannot render blocks. A DM whose push notification reads "This content
    can't be displayed" is a DM nobody opens.
    """
    headline = PATTERN_HEADLINE.get(result.pattern or "", "This item looks stuck")
    return f"{result.item_key}: {headline.lower()}"


def blocked_on_modal(channel_id: str, message_ts: str, item_key: str) -> dict:
    """The dialog [Blocked on…] opens.

    One optional-looking but required field, deliberately: the whole value
    of this button over a flat "blocked" flag is that the digest can name
    what the blocker is. `private_metadata` carries the message coordinates
    through the modal round trip, because a view_submission payload does
    not otherwise say which message it came from.
    """
    return {
        "type": "modal",
        "callback_id": CALLBACK_BLOCKED_ON,
        "private_metadata": json.dumps({"channel": channel_id, "ts": message_ts},
                                       separators=(",", ":")),
        "title": {"type": "plain_text", "text": "What's it blocked on?"},
        "submit": {"type": "plain_text", "text": "Save"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {"type": "context",
             "elements": [{"type": "mrkdwn", "text": f"*{item_key}*"}]},
            {"type": "input",
             "block_id": BLOCKED_ON_BLOCK_ID,
             "label": {"type": "plain_text", "text": "Blocked on"},
             "element": {"type": "plain_text_input",
                         "action_id": BLOCKED_ON_ACTION_ID,
                         "max_length": 300,
                         "placeholder": {"type": "plain_text",
                                         "text": "e.g. waiting on the infra team for a staging DB"}},
             "hint": {"type": "plain_text",
                      "text": "One line. This is what your tech lead sees in the morning digest."}},
        ],
    }


def compose_answered_blocks(result_item_key: str, response_type: str,
                            blocked_on_text: Optional[str],
                            answered_at: str,
                            snooze_until: Optional[str]) -> list[dict]:
    """What the DM is rewritten to after a click.

    The buttons are REMOVED, not left in place looking clickable. A button
    that does nothing on a second press teaches people the app is broken.
    """
    if response_type == "handled_offline":
        line = f":white_check_mark: *{result_item_key}* — you said this is handled offline. " \
               "ARGUS will stay quiet about it."
    elif response_type == "blocked_on":
        line = f":construction: *{result_item_key}* — logged as blocked on: " \
               f"*{blocked_on_text}*. This goes into the morning digest."
    else:
        until = (snooze_until or "").replace("T", " ").replace("Z", " UTC")
        line = f":alarm_clock: *{result_item_key}* — snoozed until {until}."
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": line}},
        {"type": "context",
         "elements": [{"type": "mrkdwn", "text": f"Recorded {answered_at}"}]},
    ]


# ---------------------------------------------------------------------------
# 6. Should this DM be sent at all?
# ---------------------------------------------------------------------------

@dataclass
class SendDecision:
    send: bool
    reason: str
    detail: str = ""


def expire_stale_messages(conn: sqlite3.Connection, now: str,
                          after_days: int = EXPIRE_UNANSWERED_DAYS) -> list[int]:
    """Write off DMs nobody ever answered. Returns the ids expired.

    Run at the top of every send, so the daily job maintains itself rather
    than depending on somebody remembering to call this.

    An expired message releases its item: `should_send` only treats a
    message with status 'sent' as blocking, so once a DM is written off,
    ARGUS is free to raise the same item again. Asking a second time after
    a week of silence is right; going quiet forever after one ignored
    message is not.
    """
    cutoff = _iso(_require_now(now) - timedelta(days=after_days))
    rows = conn.execute(
        "SELECT id FROM triage_message WHERE status = 'sent' AND sent_at <= ?", (cutoff,)
    ).fetchall()
    ids = [r[0] for r in rows]
    if ids:
        conn.execute(
            "UPDATE triage_message SET status = 'expired', suppressed_reason = ? "
            f"WHERE id IN ({','.join('?' * len(ids))})",
            [f"unanswered for {after_days}d as of {now}", *ids],
        )
        conn.commit()
    return ids


def should_send(conn: sqlite3.Connection, work_item_id: int, now: str) -> SendDecision:
    """The quiet-period rules, in one readable place.

    Three reasons not to send, in the order they are checked:

    1. An unanswered DM about this item is already sitting in somebody's
       Slack. Sending a second one is nagging, and it also creates two rows
       that a single click could ambiguously answer.
    2. The item was snoozed and the snooze has not expired.
    3. The item was answered recently in any way. See RESPONSE_COOLDOWN_DAYS
       for why "handled offline" earns quiet too.
    """
    now_dt = _require_now(now)

    open_msg = conn.execute(
        """SELECT id, sent_at FROM triage_message
           WHERE work_item_id = ? AND status = 'sent'
           ORDER BY id DESC LIMIT 1""",
        (work_item_id,),
    ).fetchone()
    if open_msg:
        return SendDecision(False, "open_dm_awaiting_response",
                            f"triage_message {open_msg[0]} sent {open_msg[1]} is unanswered")

    snoozed = conn.execute(
        """SELECT id, snooze_until FROM triage_message
           WHERE work_item_id = ? AND snooze_until IS NOT NULL
           ORDER BY snooze_until DESC LIMIT 1""",
        (work_item_id,),
    ).fetchone()
    if snoozed:
        until = _parse(snoozed[1])
        if until and until > now_dt:
            return SendDecision(False, "snoozed", f"snoozed until {snoozed[1]}")

    answered = conn.execute(
        """SELECT r.response_type, r.responded_at
           FROM triage_response r JOIN triage_message m ON m.id = r.triage_message_id
           WHERE m.work_item_id = ?
           ORDER BY r.responded_at DESC LIMIT 1""",
        (work_item_id,),
    ).fetchone()
    if answered:
        at = _parse(answered[1])
        if at and (now_dt - at) < timedelta(days=RESPONSE_COOLDOWN_DAYS):
            return SendDecision(False, "recently_answered",
                                f"answered '{answered[0]}' at {answered[1]}")

    return SendDecision(True, "ok")


# ---------------------------------------------------------------------------
# 7. Sending
# ---------------------------------------------------------------------------

@dataclass
class TriageSendResult:
    work_item_id: int
    item_key: str
    outcome: str                      # SENT | SKIPPED | FAILED
    reason: str                       # machine-readable, always set
    recipient_login: Optional[str] = None
    slack_user_id: Optional[str] = None
    channel_id: Optional[str] = None
    message_ts: Optional[str] = None
    triage_message_id: Optional[int] = None
    detail: str = ""

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _integration_row(conn: sqlite3.Connection, integration_id: int) -> tuple:
    row = conn.execute(
        "SELECT id, external_account_id, display_name FROM integration WHERE id = ? AND revoked_at IS NULL",
        (integration_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"no live integration with id {integration_id}")
    return row


def get_or_create_slack_integration(conn: sqlite3.Connection, team_id: str,
                                    credential_ref: str, scopes: str,
                                    installed_at: str,
                                    display_name: Optional[str] = None) -> int:
    """The `integration` row D-115 said step 6.6 would write.

    `credential_ref` is a path, never the token itself.
    """
    if credential_ref.startswith("xoxb-") or credential_ref.startswith("xapp-"):
        raise ValueError(
            "credential_ref must be a POINTER to where the secret lives "
            "(e.g. 'secrets/slack_bot_token.txt'), never the secret itself"
        )
    src = conn.execute("SELECT id FROM source WHERE name = 'slack'").fetchone()
    if src is None:
        cur = conn.execute(
            "INSERT INTO source (name, base_url) VALUES ('slack', ?)", (SLACK_API_BASE,)
        )
        source_id = cur.lastrowid
    else:
        source_id = src[0]

    row = conn.execute(
        "SELECT id FROM integration WHERE source_id = ? AND external_account_id = ?",
        (source_id, team_id),
    ).fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        """INSERT INTO integration (source_id, project_id, external_account_id,
                                     display_name, scope, credential_ref, installed_at)
           VALUES (?, NULL, ?, ?, ?, ?, ?)""",
        (source_id, team_id, display_name, scopes, credential_ref, installed_at),
    )
    return cur.lastrowid


def send_one(conn: sqlite3.Connection,
             transport: SlackTransport,
             integration_id: int,
             result: SF.FilterResult,
             now: str,
             email_for_login: Optional[Callable[[str], Optional[str]]] = None,
             manual_map: Optional[dict[str, str]] = None,
             item_url_for: Optional[Callable[[SF.FilterResult], Optional[str]]] = None,
             presence_check: Optional[Callable[[int, str], Optional[dict]]] = None,
             release_limiter: Optional[Callable[[int, int, str], Optional[dict]]] = None,
             ) -> TriageSendResult:
    """One FIRE → at most one DM → exactly one explicit outcome."""
    base = dict(work_item_id=result.work_item_id, item_key=result.item_key)

    if result.outcome != SF.FIRE:
        return TriageSendResult(**base, outcome=SKIPPED, reason="not_a_fire",
                                detail=f"outcome was {result.outcome}")

    if not result.next_actor or result.next_actor == "unknown":
        return TriageSendResult(**base, outcome=SKIPPED, reason="no_next_actor",
                                detail="the filter did not name a person to ask")

    decision = should_send(conn, result.work_item_id, now)
    if not decision.send:
        return TriageSendResult(**base, outcome=SKIPPED, reason=decision.reason,
                                recipient_login=result.next_actor, detail=decision.detail)

    ident = resolve_identity(conn, integration_id, result.next_actor, transport, now,
                             email_for_login=email_for_login, manual_map=manual_map)
    if not ident.ok:
        return TriageSendResult(**base, outcome=FAILED, reason="recipient_unresolved",
                                recipient_login=result.next_actor, detail=ident.detail)

    # ---- step 6.7: is this person actually here? -----------------------
    # Checked AFTER identity, because knowing who they are is what makes the
    # question askable at all, and BEFORE any Slack write, so a held alert
    # costs nothing and disturbs nobody.
    if presence_check is not None:
        held = presence_check(ident.actor_id, now)
        if held:
            mid = _record_presence_hold(conn, integration_id, result, ident, now, held)
            return TriageSendResult(**base, outcome=SKIPPED, reason="out_of_office",
                                    recipient_login=result.next_actor,
                                    slack_user_id=ident.slack_user_id,
                                    triage_message_id=mid, detail=held.get("detail", ""))

    if release_limiter is not None:
        capped = release_limiter(ident.actor_id, result.work_item_id, now)
        if capped:
            return TriageSendResult(**base, outcome=SKIPPED, reason=capped["reason"],
                                    recipient_login=result.next_actor,
                                    slack_user_id=ident.slack_user_id,
                                    detail=capped.get("detail", ""))

    try:
        opened = transport.call("conversations.open", users=ident.slack_user_id)
        channel_id = (opened.get("channel") or {}).get("id")
        if not channel_id:
            return TriageSendResult(**base, outcome=FAILED, reason="dm_channel_not_opened",
                                    recipient_login=result.next_actor,
                                    slack_user_id=ident.slack_user_id,
                                    detail="conversations.open returned no channel id")

        url = item_url_for(result) if item_url_for else None
        posted = transport.call(
            "chat.postMessage",
            channel=channel_id,
            text=compose_fallback_text(result),
            blocks=compose_blocks(result, url),
        )
        message_ts = posted.get("ts")
        if not message_ts:
            return TriageSendResult(**base, outcome=FAILED, reason="no_message_ts",
                                    recipient_login=result.next_actor,
                                    slack_user_id=ident.slack_user_id, channel_id=channel_id,
                                    detail="chat.postMessage returned no ts; cannot track this DM")
    except SlackError as exc:
        return TriageSendResult(**base, outcome=FAILED, reason="slack_error",
                                recipient_login=result.next_actor,
                                slack_user_id=ident.slack_user_id,
                                detail=f"{exc.method}: {exc.error}")

    cur = conn.execute(
        """INSERT INTO triage_message
               (integration_id, work_item_id, ticket_id, sent_to_actor_id,
                external_channel_id, external_message_ts, sent_at, status)
           VALUES (?,?,NULL,?,?,?,?, 'sent')""",
        (integration_id, result.work_item_id, ident.actor_id,
         channel_id, message_ts, now),
    )
    return TriageSendResult(**base, outcome=SENT, reason="sent",
                            recipient_login=result.next_actor,
                            slack_user_id=ident.slack_user_id, channel_id=channel_id,
                            message_ts=message_ts, triage_message_id=cur.lastrowid,
                            detail=f"identity via {ident.resolved_via}")


def _record_presence_hold(conn: sqlite3.Connection, integration_id: int,
                          result: SF.FilterResult, ident: Identity,
                          now: str, held: dict) -> Optional[int]:
    """Write down that an alert was held because its recipient is away.

    Recorded rather than merely skipped, for the reason this project keeps
    coming back to: an alert that vanishes silently is indistinguishable from
    an alert that was never warranted. `triage_message.status` has had a
    `'suppressed_presence'` value reserved since step 6.1 and nothing had ever
    written one; this is it.

    One row per item per absence, not one per daily run — the same idempotency
    discipline as everywhere else. `external_message_ts` is NULL here because
    no message exists, which is why schema section 12 was widened at this step.
    """
    tag = f"presence:{held.get('presence_id')}"
    existing = conn.execute(
        """SELECT id FROM triage_message
           WHERE work_item_id = ? AND status = 'suppressed_presence'
             AND suppressed_reason LIKE ? LIMIT 1""",
        (result.work_item_id, tag + "%")).fetchone()
    if existing:
        return existing[0]

    cur = conn.execute(
        """INSERT INTO triage_message
               (integration_id, work_item_id, ticket_id, sent_to_actor_id,
                external_channel_id, external_message_ts, sent_at,
                status, suppressed_reason)
           VALUES (?,?,NULL,?, NULL, NULL, ?, 'suppressed_presence', ?)""",
        (integration_id, result.work_item_id, ident.actor_id, now,
         f"{tag}: {held.get('detail', 'recipient out of office')}"))
    return cur.lastrowid


def send_triage_dms(conn: sqlite3.Connection,
                    transport: SlackTransport,
                    integration_id: int,
                    results: Iterable[SF.FilterResult],
                    now: str,
                    only_fires: bool = True,
                    **kwargs) -> list[TriageSendResult]:
    """The daily send.

    By default only FIRE rows are considered, but every one of them comes
    back accounted for. Pass only_fires=False to get an explicit
    `not_a_fire` row for the suppressed and abstained items too — which is
    what step 6.8's digest will want, since D-114's whole point is that the
    SUPPRESSED count is the number Phase 6 is judged on.
    """
    _require_now(now)
    expire_stale_messages(conn, now)
    out = []
    for r in results:
        if only_fires and r.outcome != SF.FIRE:
            continue
        out.append(send_one(conn, transport, integration_id, r, now, **kwargs))
    conn.commit()
    return out


# ---------------------------------------------------------------------------
# 8. Handling the click
# ---------------------------------------------------------------------------

@dataclass
class InteractionResult:
    handled: bool
    action: str                       # what this module did
    reason: str = ""
    triage_message_id: Optional[int] = None
    response_type: Optional[str] = None
    blocked_on_text: Optional[str] = None
    response_body: Optional[dict] = None   # what to return to Slack over HTTP

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _message_by_coords(conn: sqlite3.Connection, channel_id: str,
                       message_ts: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        """SELECT id, work_item_id, status, sent_to_actor_id
           FROM triage_message
           WHERE external_channel_id = ? AND external_message_ts = ?""",
        (channel_id, message_ts),
    ).fetchone()


def item_key_of(conn: sqlite3.Connection, work_item_id: Optional[int]) -> str:
    """The human-readable key for an item, e.g. 'acme/web#401'."""
    if work_item_id is None:
        return "this item"
    return SF.item_key(conn, work_item_id)


# Kept as the historical internal name; step 6.7 needs a public one.
_item_key_for_message = item_key_of


def _record_response(conn: sqlite3.Connection,
                     transport: Optional[SlackTransport],
                     msg_id: int, work_item_id: Optional[int],
                     channel_id: str, message_ts: str,
                     response_type: str, blocked_on_text: Optional[str],
                     now: str, raw_payload: Optional[dict]) -> InteractionResult:
    """Write the click into the model, then rewrite the DM to match.

    Order matters. The database row is written first and committed; the
    Slack redraw is best-effort. If Slack is briefly unreachable the answer
    is still recorded — losing a developer's answer because a redraw failed
    would be the worst possible trade, since the answer is the whole point
    of this step and the redraw is cosmetic.
    """
    snooze_until = None
    if response_type == "snooze_7d":
        snooze_until = _iso(_require_now(now) + timedelta(days=SNOOZE_DAYS))

    conn.execute(
        """INSERT INTO triage_response
               (triage_message_id, response_type, blocked_on_text, responded_at, raw_payload)
           VALUES (?,?,?,?,?)""",
        (msg_id, response_type, blocked_on_text, now,
         json.dumps(raw_payload, separators=(",", ":")) if raw_payload else None),
    )
    conn.execute(
        "UPDATE triage_message SET status = 'responded', snooze_until = ? WHERE id = ?",
        (snooze_until, msg_id),
    )
    conn.commit()

    redraw = "message_updated"
    if transport is not None:
        try:
            transport.call(
                "chat.update",
                channel=channel_id,
                ts=message_ts,
                text=f"Recorded: {response_type.replace('_', ' ')}",
                blocks=compose_answered_blocks(
                    _item_key_for_message(conn, work_item_id),
                    response_type, blocked_on_text, now, snooze_until),
            )
        except SlackError as exc:
            redraw = f"message_update_failed: {exc.error}"

    return InteractionResult(True, "response_recorded", redraw,
                             triage_message_id=msg_id, response_type=response_type,
                             blocked_on_text=blocked_on_text)


def handle_interaction(conn: sqlite3.Connection,
                       payload: dict,
                       transport: Optional[SlackTransport],
                       now: str) -> InteractionResult:
    """Handle one Slack interaction payload.

    Covers both halves of the [Blocked on…] round trip:
      * `block_actions` — a button was pressed. Two of the three buttons
        record immediately; [Blocked on…] opens a modal and records nothing
        yet.
      * `view_submission` — the modal was submitted. This is where a
        blocked_on response is actually written.

    Every path is idempotent on the (channel, ts) key. Slack retries
    deliveries it thinks failed, and a retried click must not produce a
    second `triage_response` row — the same class of bug D-112 found in the
    Jira changelog ingest, checked for here rather than assumed absent.
    """
    ptype = payload.get("type")

    # ---- the modal came back ------------------------------------------
    if ptype == "view_submission":
        view = payload.get("view") or {}
        if view.get("callback_id") != CALLBACK_BLOCKED_ON:
            return InteractionResult(False, "ignored", f"unknown callback_id "
                                                       f"{view.get('callback_id')!r}")
        try:
            meta = json.loads(view.get("private_metadata") or "{}")
        except json.JSONDecodeError:
            return InteractionResult(False, "ignored", "unparseable private_metadata")
        channel_id, message_ts = meta.get("channel"), meta.get("ts")
        if not channel_id or not message_ts:
            return InteractionResult(False, "ignored", "private_metadata lost the message coords")

        # state.values[block_id][action_id].value — confirmed against
        # Slack's own reference, not recalled.
        values = ((view.get("state") or {}).get("values") or {})
        text = (((values.get(BLOCKED_ON_BLOCK_ID) or {}).get(BLOCKED_ON_ACTION_ID) or {})
                .get("value"))
        text = (text or "").strip()

        row = _message_by_coords(conn, channel_id, message_ts)
        if row is None:
            return InteractionResult(False, "ignored", "no triage_message for those coords")
        msg_id, work_item_id, status, _actor = row
        if status == "responded":
            return InteractionResult(True, "already_responded",
                                     "a response for this message is already recorded",
                                     triage_message_id=msg_id)
        if not text:
            # An input block is required by Slack, so this should not
            # happen — handled anyway rather than writing an empty
            # "blocked on nothing", which would be worse than useless in
            # the digest.
            return InteractionResult(
                False, "validation_error", "blocked_on text was empty",
                triage_message_id=msg_id,
                response_body={"response_action": "errors",
                               "errors": {BLOCKED_ON_BLOCK_ID:
                                          "Please say what it's blocked on."}})
        return _record_response(conn, transport, msg_id, work_item_id, channel_id,
                                message_ts, "blocked_on", text, now, payload)

    # ---- a button was pressed -----------------------------------------
    if ptype != "block_actions":
        return InteractionResult(False, "ignored", f"unhandled payload type {ptype!r}")

    actions = payload.get("actions") or []
    if not actions:
        return InteractionResult(False, "ignored", "block_actions payload with no actions")
    action_id = actions[0].get("action_id")
    if action_id not in ACTION_TO_RESPONSE_TYPE:
        return InteractionResult(False, "ignored", f"not an ARGUS action: {action_id!r}")

    # The clicked message's ts lives on payload.message.ts; container.message_ts
    # carries the same value and is the fallback when `message` is absent.
    channel_id = (payload.get("channel") or {}).get("id") \
        or (payload.get("container") or {}).get("channel_id")
    message_ts = (payload.get("message") or {}).get("ts") \
        or (payload.get("container") or {}).get("message_ts")
    if not channel_id or not message_ts:
        return InteractionResult(False, "ignored", "payload carried no message coordinates")

    row = _message_by_coords(conn, channel_id, message_ts)
    if row is None:
        return InteractionResult(False, "ignored",
                                 "no triage_message for those coords — not an ARGUS DM, "
                                 "or sent by a different install")
    msg_id, work_item_id, status, _actor = row
    if status == "responded":
        return InteractionResult(True, "already_responded",
                                 "a response for this message is already recorded",
                                 triage_message_id=msg_id)

    if action_id == ACTION_BLOCKED_ON:
        trigger_id = payload.get("trigger_id")
        if not trigger_id:
            return InteractionResult(False, "modal_not_opened",
                                     "no trigger_id in payload", triage_message_id=msg_id)
        if transport is None:
            return InteractionResult(False, "modal_not_opened",
                                     "no Slack transport available", triage_message_id=msg_id)
        try:
            transport.call("views.open", trigger_id=trigger_id,
                           view=blocked_on_modal(channel_id, message_ts,
                                                 _item_key_for_message(conn, work_item_id)))
        except SlackError as exc:
            return InteractionResult(False, "modal_not_opened",
                                     f"views.open: {exc.error}", triage_message_id=msg_id)
        # Nothing is recorded yet, deliberately: opening a dialog is not an
        # answer, and a user who cancels it has said nothing.
        return InteractionResult(True, "modal_opened", "awaiting the blocked-on text",
                                 triage_message_id=msg_id)

    return _record_response(conn, transport, msg_id, work_item_id, channel_id, message_ts,
                            ACTION_TO_RESPONSE_TYPE[action_id], None, now, payload)


# ---------------------------------------------------------------------------
# 9. Reporting
# ---------------------------------------------------------------------------

def summarise_sends(results: list[TriageSendResult]) -> dict:
    """The counts step 6.8's digest reads.

    `failed_by_reason` is deliberately its own bucket rather than being
    folded into "skipped": a DM we chose not to send and a DM we could not
    send are different facts, and only one of them is a bug.
    """
    out = {"fires": len(results), SENT: 0, SKIPPED: 0, FAILED: 0,
           "skipped_by_reason": {}, "failed_by_reason": {}}
    for r in results:
        out[r.outcome] += 1
        if r.outcome == SKIPPED:
            out["skipped_by_reason"][r.reason] = out["skipped_by_reason"].get(r.reason, 0) + 1
        elif r.outcome == FAILED:
            out["failed_by_reason"][r.reason] = out["failed_by_reason"].get(r.reason, 0) + 1
    return out


def triage_ledger(conn: sqlite3.Connection) -> list[dict]:
    """Every DM ever sent, with its answer if it has one.

    This is the raw material for 6.8 and, more importantly, for Phase 6's
    exit criterion: a `handled_offline` count is a direct measurement of
    how often ARGUS was wrong in a way only a human could have told it.
    """
    rows = conn.execute(
        """SELECT m.id, m.work_item_id, m.sent_at, m.status, m.snooze_until,
                  a.source_key, r.response_type, r.blocked_on_text, r.responded_at
           FROM triage_message m
           JOIN actor a ON a.id = m.sent_to_actor_id
           LEFT JOIN triage_response r ON r.triage_message_id = m.id
           ORDER BY m.id"""
    ).fetchall()
    out = []
    for (mid, wid, sent_at, status, snooze_until, login,
         rtype, btext, rat) in rows:
        out.append({
            "triage_message_id": mid,
            "item": SF.item_key(conn, wid) if wid else None,
            "sent_to": login, "sent_at": sent_at, "status": status,
            "snooze_until": snooze_until,
            "response_type": rtype, "blocked_on_text": btext, "responded_at": rat,
        })
    return out
