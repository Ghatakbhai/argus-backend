"""ARGUS Phase 7 — Milestone 1, Task 2 (D-167): the live Slack DM dispatcher.

WHAT THIS CLOSES.

Every other piece of the pipeline that ends in a Slack DM already exists and
is already proven: `sprint_filter`/`digest` decide FIRE/SUPPRESSED (Phase 3-6,
frozen), `ingest_worker.run_one()` writes the resulting `alert` rows into
Postgres every time it runs (7.4c), and `slack_app.py` can already open a
per-tenant Slack client from an encrypted, tenant-bound bot token
(`transport_for()`) and already knows how to handle a button click on a DM it
sent (`handle_interaction()`). What has never existed, in either Phase 6 or
Phase 7, is the piece that actually SENDS one: reads a tenant's `FIRE` alerts,
finds the Slack person to ask, and posts the message. That is this module.

It is a deliberately thin layer over code that already works. Identity
resolution, message composition, and the "record before you talk to Slack"
ordering are all near-line-for-line ports of `src/slack_triage.py`'s
Phase-6-proven `resolve_identity`/`send_one` (D-115 through D-121) — this
module does not re-derive any of that judgement, it re-homes it against
Postgres and `slack_app.TenantSlackTransport` instead of SQLite and Phase 6's
`HttpSlackTransport`. The interactive buttons it posts use `slack_app.py`'s
own action ids and are recognised by `slack_app.handle_interaction()`
unchanged — a click on a DM this module sends is handled by code that already
exists and is already tested (`test_slack_app.py`), because `_message_by_coords()`
matches purely on `(external_channel_id, external_message_ts)`, which this
module writes into the same `triage_message` table Phase 6 always used.

ONE HARD INVARIANT, CHECKED HERE AND NOWHERE ELSE ON THIS PATH: a tenant whose
`tenant.status` is not `'live'` gets NO Slack traffic from this module, ever.
`ingest_worker.run_one()` already runs detection for every tenant regardless
of status (7.4c's Shadow Mode design, §3.1.2 step 7) — Shadow Mode's entire
meaning is that detection keeps running silently while delivery does not, and
this is the one place in the whole system a live Slack DM could actually leave
the building. If this check were only enforced by a caller remembering to
check first, a caller that forgets sends real DMs to a pilot team still in
its 2-week silent calibration window — exactly the failure Phase 7.6 exists
to prevent.

TWO THINGS THE MILESTONE 1 PLANNING DOC (`docs/MILESTONE_1_CORE_INFRASTRUCTURE_GAPS.md`)
GOT WRONG, FOUND WHILE BUILDING THIS, AND WORTH RECORDING (see D-167's
follow-up note in `context/DECISIONS.md`) RATHER THAN SILENTLY WORKING AROUND:

  1. It says to resolve a developer's email via `actor.email`. There is no
     such column — `schema_pg.sql`'s `actor` table has never had one, for the
     same reason Phase 6 never added one: a GitHub login is not an email
     address, and Phase 1's frozen data model doesn't carry one either. Phase
     6 solved this by making email resolution an explicit external contract
     (`email_for_login`, see `slack_triage.resolve_identity`'s docstring) — a
     callable the caller supplies once it has real access to a source of
     truth for emails (a GitHub org's member list, an HRIS, a manually
     maintained map). This module keeps that exact contract rather than
     inventing a schema column the rest of the codebase doesn't have.
  2. It says to log the delivery into `digest_delivery`. That table is a
     once-per-`ingest_run` record of what was rendered and to which channel as
     a whole (`schema_pg.sql`'s own comment: "'shadow' records a digest that
     was rendered ... deliberately not delivered") — it has no row-per-
     recipient shape and its `status` CHECK does not even include a value for
     "one DM sent OK". `triage_message` is the table Phase 6 and `slack_app.py`
     both already use for exactly this — one row per (item, recipient) DM,
     with `status IN ('sent','responded','expired','suppressed_presence','failed')`
     and the coordinates `handle_interaction()` looks click-backs up by. Using
     `digest_delivery` instead would have meant either violating its CHECK
     constraint or breaking the one-row-per-run invariant everything else
     that reads it relies on. This module writes `triage_message`, not
     `digest_delivery`.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from . import db, slack_app
from .slack_app import (
    ACTION_BLOCKED_ON,
    ACTION_HANDLED_OFFLINE,
    ACTION_SNOOZE_7D,
    SlackError,
    SlackTransport,
    TenantSlackTransport,
)

logger = logging.getLogger("argus.slack_dispatcher")

PATTERN_HEADLINE = {
    "P1-approved-unmerged": "This PR is approved and still unmerged",
    "P2-review-ghosted": "This PR is waiting on your review",
}
PATTERN_ASK = {
    "P1-approved-unmerged": "It has an approval — is something holding the merge?",
    "P2-review-ghosted": "A review was requested and there has been no response yet.",
}


class TenantNotLive(RuntimeError):
    """Raised (never silently swallowed) when something asks this module to
    send a real Slack DM for a tenant whose status is not 'live'. Shadow Mode
    is the one thing this module must never quietly get wrong."""


# ===========================================================================
# 1. Result types — every alert gets an explicit outcome, never a silent skip.
# ===========================================================================

SENT = "sent"
SKIPPED = "skipped"
FAILED = "failed"


@dataclass
class DispatchResult:
    alert_id: int
    work_item_id: Optional[int]
    outcome: str                       # SENT | SKIPPED | FAILED
    reason: str
    recipient_login: Optional[str] = None
    slack_user_id: Optional[str] = None
    triage_message_id: Optional[int] = None
    detail: str = ""

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class DispatchSummary:
    tenant_id: str
    results: list[DispatchResult] = field(default_factory=list)

    @property
    def sent(self) -> int:
        return sum(1 for r in self.results if r.outcome == SENT)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.outcome == SKIPPED)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.outcome == FAILED)

    def as_dict(self) -> dict:
        return {"tenant_id": self.tenant_id, "sent": self.sent,
                "skipped": self.skipped, "failed": self.failed,
                "results": [r.as_dict() for r in self.results]}


# ===========================================================================
# 2. Identity resolution — the Postgres port of slack_triage.resolve_identity.
# ===========================================================================

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


def resolve_identity(conn, tenant_id: str, integration_id: int, actor_id: int,
                     login: str, transport: Optional[SlackTransport], now: str,
                     email_for_login: Optional[Callable[[str], Optional[str]]] = None,
                     manual_map: Optional[dict[str, str]] = None) -> Identity:
    """Find the Slack account for one already-known actor, in order of
    trustworthiness — identical policy to `slack_triage.resolve_identity`:

    1. A `slack_identity` row already resolved on a previous dispatch for this
       (integration, actor) — cached, so a daily run does not re-query Slack
       for every developer every day.
    2. An explicit manual mapping, if the caller supplies one. Most
       trustworthy: a human said so.
    3. `users.lookupByEmail`, given an email from `email_for_login` — see this
       module's docstring for why that stays a caller-supplied contract
       rather than a schema column.

    Unresolved is WRITTEN as unresolved, not left silent: the next dispatch
    should not repeat a Slack call that is going to fail the same way again
    for the same reason, and a human reading `slack_identity` later should be
    able to see why nobody got a DM about a real FIRE alert.
    """
    cached = conn.execute(
        "SELECT slack_user_id, resolved_via, matched_email FROM slack_identity"
        " WHERE integration_id = %s AND actor_id = %s",
        (integration_id, actor_id)).fetchone()
    if cached and cached["slack_user_id"]:
        return Identity(actor_id, login, cached["slack_user_id"], cached["resolved_via"],
                        cached["matched_email"], detail="from a previous dispatch")

    def _store(slack_user_id: Optional[str], via: str, email: Optional[str]) -> None:
        conn.execute(
            "INSERT INTO slack_identity"
            "   (tenant_id, integration_id, actor_id, slack_user_id, matched_email,"
            "    resolved_via, resolved_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (tenant_id, integration_id, actor_id) DO UPDATE SET"
            "   slack_user_id = EXCLUDED.slack_user_id,"
            "   matched_email = EXCLUDED.matched_email,"
            "   resolved_via  = EXCLUDED.resolved_via,"
            "   resolved_at   = EXCLUDED.resolved_at",
            (tenant_id, integration_id, actor_id, slack_user_id, email, via, now))

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
            reason = f"users.lookupByEmail: {exc.error}"
    elif email and transport is None:
        reason = "no Slack transport available to look the email up"
    else:
        reason = "no email known for this login (see email_for_login contract)"

    _store(None, "unresolved", email)
    return Identity(actor_id, login, None, "unresolved", email, detail=reason)


# ===========================================================================
# 3. Composing the message.
# ===========================================================================

def _item_url(conn, work_item_id: Optional[int]) -> Optional[str]:
    if work_item_id is None:
        return None
    row = conn.execute("SELECT url FROM work_item WHERE id = %s", (work_item_id,)).fetchone()
    return row["url"] if row else None


def _button_value(alert_row: dict) -> str:
    """Carried on the button for auditing / a human reading a raw payload.
    Never trusted as a lookup key — `handle_interaction` matches purely on
    (channel, message ts), which is server-known, not client-supplied. Same
    contract `slack_triage.button_value` documents."""
    return json.dumps({"v": 1, "alert_id": alert_row["id"],
                       "work_item_id": alert_row["work_item_id"],
                       "pattern": alert_row["pattern"]}, separators=(",", ":"))[:2000]


def compose_blocks(alert_row: dict, item_key: str, item_url: Optional[str]) -> list[dict]:
    """The Block Kit body of one triage DM. Same three-second-read shape as
    `slack_triage.compose_blocks`: what, why, three buttons — using the
    action ids `slack_app.handle_interaction` already recognises."""
    headline = PATTERN_HEADLINE.get(alert_row["pattern"] or "", "This item looks stuck")
    ask = PATTERN_ASK.get(alert_row["pattern"] or "", "")
    title = f"*{headline}*\n<{item_url}|{item_key}>" if item_url else f"*{headline}*\n`{item_key}`"

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
    ]
    if ask:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": ask}})
    if alert_row.get("reason"):
        # sprint_filter's own evidence string, shown verbatim — same rule
        # slack_triage.compose_blocks follows: a wrong alert should be
        # arguable by the person reading it, not mysterious.
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": f"_{alert_row['reason']}_"}]})

    val = _button_value(alert_row)
    blocks.append({
        "type": "actions",
        "block_id": "argus_triage_actions",
        "elements": [
            {"type": "button", "action_id": ACTION_HANDLED_OFFLINE,
             "text": {"type": "plain_text", "text": "Handled offline"}, "value": val},
            {"type": "button", "action_id": ACTION_BLOCKED_ON,
             "text": {"type": "plain_text", "text": "Blocked on…"}, "value": val},
            {"type": "button", "action_id": ACTION_SNOOZE_7D,
             "text": {"type": "plain_text", "text": "Snooze 7d"}, "value": val},
        ],
    })
    return blocks


def compose_fallback_text(alert_row: dict, item_key: str) -> str:
    """The `text` argument — Slack's push-notification preview, not
    decoration. See `slack_triage.compose_fallback_text`'s identical rule."""
    headline = PATTERN_HEADLINE.get(alert_row["pattern"] or "", "This item looks stuck")
    return f"{item_key}: {headline.lower()}"


# ===========================================================================
# 4. Sending one alert.
# ===========================================================================

def _already_dispatched(conn, work_item_id: Optional[int], ticket_id: Optional[int]) -> bool:
    """True if a live (non-suppressed, non-failed) triage_message already
    exists for this item. Keeps a re-run of the same ingest_run — or a second
    call against alerts already handled — from DMing the same person twice
    about the same stuck item, the same idempotency discipline
    `slack_triage.should_send` enforces in Phase 6."""
    row = conn.execute(
        "SELECT id FROM triage_message"
        " WHERE status IN ('sent','responded')"
        "   AND ((%(wi)s::bigint IS NOT NULL AND work_item_id = %(wi)s::bigint)"
        "     OR (%(tk)s::bigint IS NOT NULL AND ticket_id = %(tk)s::bigint))"
        " LIMIT 1",
        {"wi": work_item_id, "tk": ticket_id}).fetchone()
    return row is not None


def dispatch_one(conn, tenant_id: str, integration_id: int, alert_row: dict, now: str,
                 transport: Optional[SlackTransport],
                 email_for_login: Optional[Callable[[str], Optional[str]]] = None,
                 manual_map: Optional[dict[str, str]] = None) -> DispatchResult:
    """One FIRE alert -> at most one DM -> exactly one explicit outcome.
    Never raises for an ordinary Slack or identity failure — those are
    outcomes, not exceptions. Only a caller error (see `TenantNotLive`, and a
    missing transport is treated as one below) escapes as an exception."""
    base = dict(alert_id=alert_row["id"], work_item_id=alert_row.get("work_item_id"))

    if alert_row["outcome"] != "FIRE":
        return DispatchResult(**base, outcome=SKIPPED, reason="not_a_fire",
                              detail=f"outcome was {alert_row['outcome']}")

    if alert_row.get("subject_actor_id") is None:
        return DispatchResult(**base, outcome=SKIPPED, reason="no_subject_actor",
                              detail="alert names nobody to ask")

    if _already_dispatched(conn, alert_row.get("work_item_id"), alert_row.get("ticket_id")):
        return DispatchResult(**base, outcome=SKIPPED, reason="already_dispatched",
                              detail="a live triage_message already exists for this item")

    actor = conn.execute("SELECT source_key, kind FROM actor WHERE id = %s",
                         (alert_row["subject_actor_id"],)).fetchone()
    if actor is None:
        return DispatchResult(**base, outcome=FAILED, reason="subject_actor_missing",
                              detail="alert.subject_actor_id does not resolve to a real actor")
    if actor["kind"] != "human":
        return DispatchResult(**base, outcome=SKIPPED, reason="subject_not_human",
                              recipient_login=actor["source_key"],
                              detail=f"actor.kind = {actor['kind']!r}")
    login = actor["source_key"]

    if transport is None:
        return DispatchResult(**base, outcome=FAILED, reason="no_slack_transport",
                              recipient_login=login,
                              detail="tenant has no live Slack workspace token")

    ident = resolve_identity(conn, tenant_id, integration_id, alert_row["subject_actor_id"],
                             login, transport, now, email_for_login, manual_map)
    if not ident.ok:
        return DispatchResult(**base, outcome=FAILED, reason="recipient_unresolved",
                              recipient_login=login, detail=ident.detail)

    item_key = slack_app.item_key_of(conn, alert_row.get("work_item_id"))
    item_url = _item_url(conn, alert_row.get("work_item_id"))

    try:
        opened = transport.call("conversations.open", users=ident.slack_user_id)
        channel_id = (opened.get("channel") or {}).get("id")
        if not channel_id:
            return DispatchResult(**base, outcome=FAILED, reason="dm_channel_not_opened",
                                  recipient_login=login, slack_user_id=ident.slack_user_id,
                                  detail="conversations.open returned no channel id")

        posted = transport.call(
            "chat.postMessage", channel=channel_id,
            text=compose_fallback_text(alert_row, item_key),
            blocks=compose_blocks(alert_row, item_key, item_url))
        message_ts = posted.get("ts")
        if not message_ts:
            return DispatchResult(**base, outcome=FAILED, reason="no_message_ts",
                                  recipient_login=login, slack_user_id=ident.slack_user_id,
                                  detail="chat.postMessage returned no ts; cannot track this DM")
    except SlackError as exc:
        return DispatchResult(**base, outcome=FAILED, reason="slack_error",
                              recipient_login=login, slack_user_id=ident.slack_user_id,
                              detail=f"{exc.method}: {exc.error}")

    row = conn.execute(
        "INSERT INTO triage_message"
        "   (tenant_id, integration_id, work_item_id, ticket_id, sent_to_actor_id,"
        "    external_channel_id, external_message_ts, sent_at, status)"
        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'sent') RETURNING id",
        (tenant_id, integration_id, alert_row.get("work_item_id"), alert_row.get("ticket_id"),
         alert_row["subject_actor_id"], channel_id, message_ts, now)).fetchone()

    return DispatchResult(**base, outcome=SENT, reason="sent", recipient_login=login,
                          slack_user_id=ident.slack_user_id, triage_message_id=row["id"],
                          detail=f"identity via {ident.resolved_via}")


# ===========================================================================
# 5. The entry point.
# ===========================================================================

def dispatch_tenant_triage_dms(
        conn, tenant_id: str, ingest_run_id: int, now: str,
        alert_ids: Optional[Sequence[int]] = None,
        transport: Optional[SlackTransport] = None,
        email_for_login: Optional[Callable[[str], Optional[str]]] = None,
        manual_map: Optional[dict[str, str]] = None) -> DispatchSummary:
    """Dispatch live Slack triage DMs for one tenant's ingest run.

    MUST be called inside `db.tenant_tx(tenant_id)` — every query in this
    module is RLS-scoped and assumes it.

    Refuses outright (raises `TenantNotLive`, never just skips quietly) if
    the tenant is not `status = 'live'`. This is deliberate and non-optional:
    detection (`ingest_worker.run_one`) runs for shadow tenants too, by
    design (7.4c-c/D-162, §3.1.2 step 7) — this function is the one place
    Shadow Mode's silence promise is actually enforced on the Slack side, and
    a caller forgetting to check tenant status first must not be able to
    leak a real DM to a pilot team still in its 2-week silent calibration
    window.

    `alert_ids`, if given, restricts dispatch to those specific alerts
    (matching the milestone doc's literal `dispatch_tenant_triage_dms(tenant_id,
    alerts)` shape, adapted to IDs already in this tenant's own database
    rather than caller-assembled dicts — the row this module needs for each
    alert, `subject_actor_id` included, only exists in Postgres). Omitted, it
    dispatches every `FIRE` alert from `ingest_run_id` that has not already
    been sent.

    `transport`, if not given, is built from this tenant's own stored Slack
    workspace token via `slack_app.transport_for()` — the exact
    retrieve-then-decrypt path (`slack_workspace_token` -> `slack_crypto.
    decrypt_token`) Milestone 1's brief calls for. Passed explicitly in tests,
    the same way every other call site in this codebase injects a transport
    rather than letting a function reach for the network itself.
    """
    tenant_row = conn.execute("SELECT status FROM tenant WHERE id = %s",
                              (tenant_id,)).fetchone()
    if tenant_row is None:
        raise TenantNotLive(f"no such tenant: {tenant_id}")
    if tenant_row["status"] != "live":
        raise TenantNotLive(
            f"tenant {tenant_id} has status {tenant_row['status']!r}, not 'live' — "
            "refusing to send any Slack DM (Shadow Mode invariant, see module docstring)")

    integration_row = conn.execute(
        "SELECT i.id FROM integration i JOIN source s"
        "   ON s.id = i.source_id AND s.tenant_id = i.tenant_id"
        " WHERE i.tenant_id = %s AND s.name = 'slack' AND i.revoked_at IS NULL"
        " ORDER BY i.installed_at DESC LIMIT 1",
        (tenant_id,)).fetchone()
    if integration_row is None:
        raise TenantNotLive(  # not a Shadow Mode question, but the same "refuse loudly"
            f"tenant {tenant_id} has no live Slack integration — cannot dispatch")
    integration_id = integration_row["id"]

    if transport is None:
        transport = slack_app.transport_for(conn, tenant_id, integration_id)

    if alert_ids is not None:
        rows = conn.execute(
            "SELECT * FROM alert WHERE tenant_id = %s AND id = ANY(%s)",
            (tenant_id, list(alert_ids))).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alert WHERE tenant_id = %s AND ingest_run_id = %s"
            "   AND outcome = 'FIRE'",
            (tenant_id, ingest_run_id)).fetchall()

    summary = DispatchSummary(tenant_id=tenant_id)
    for alert_row in rows:
        result = dispatch_one(conn, tenant_id, integration_id, dict(alert_row), now,
                              transport, email_for_login, manual_map)
        summary.results.append(result)
        if result.outcome == FAILED:
            logger.warning("slack_dispatcher: alert %s failed to dispatch for tenant %s: %s",
                           result.alert_id, tenant_id, result.detail)
    return summary
