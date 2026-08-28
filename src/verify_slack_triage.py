"""
ARGUS — Phase 6.6 verification: the 1-click triage DM, end to end, offline.

Same discipline as the three verifiers before it (D-112/D-113/D-114): every
assertion fails loudly, nothing passes silently, and the fixtures are
realistic rather than convenient.

What is different here is that the thing being tested talks to a third
party. D-115 established that this sandbox cannot reach slack.com at all,
so the whole send → click → write-back cycle runs against `FakeSlack`, a
recording stand-in built to Slack's own published request and response
field names. That is a real limitation and it is stated plainly rather
than implied away: this file proves ARGUS's half of the conversation is
correct — the right person, the right blocks, the right database rows, the
right behaviour on a retry — and it cannot prove Slack accepts them. Step
6.9, on Dirgh's own staging workspace, is the first time the real
`HttpSlackTransport` runs.

The item side is NOT hand-built: the same fixture database step 6.4 was
verified on is rebuilt through the real Jira and Linear adapters and the
real sprint filter, so every DM tested here is one the verified pipeline
actually produced.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(__file__))
import slack_triage as ST
import sprint_filter as SF
import verify_sprint_filter as VSF

NOW = "2026-08-21T12:00:00Z"
TEAM_ID = "T0ARGUS01"


def plus_days(base: str, days: float) -> str:
    return ST._iso(ST._parse(base) + timedelta(days=days))


# ---------------------------------------------------------------------------
# The stand-in for Slack
# ---------------------------------------------------------------------------

class FakeSlack(ST.SlackTransport):
    """Records every call; answers in Slack's documented response shape.

    Deliberately strict about arguments — it raises on a missing `channel`
    or `ts` rather than shrugging — because the point of this stand-in is
    to catch ARGUS sending a malformed request, which is exactly what a
    permissive fake would hide.
    """

    def __init__(self, emails: dict[str, str] | None = None,
                 fail: dict[str, str] | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.emails = emails or {}          # email -> slack user id
        self.fail = fail or {}              # method -> slack error string
        self._ts = 1000

    def call(self, method: str, **args):
        self.calls.append((method, args))
        if method in self.fail:
            raise ST.SlackError(method, self.fail[method])

        if method == "users.lookupByEmail":
            uid = self.emails.get(args["email"])
            if not uid:
                raise ST.SlackError(method, "users_not_found")
            return {"ok": True, "user": {"id": uid, "profile": {"email": args["email"]}}}

        if method == "conversations.open":
            uid = args["users"]
            assert uid.startswith("U"), f"conversations.open got {uid!r}, not a user id"
            return {"ok": True, "channel": {"id": "D" + uid[1:]}}

        if method == "chat.postMessage":
            assert args["channel"].startswith("D"), "a triage DM must go to a DM channel"
            assert args.get("text"), "chat.postMessage sent with no fallback text"
            assert isinstance(args.get("blocks"), list) and args["blocks"], "no blocks"
            self._ts += 1
            return {"ok": True, "channel": args["channel"], "ts": f"{self._ts}.000100"}

        if method == "chat.update":
            assert args["channel"].startswith("D") and args.get("ts"), "chat.update coords"
            assert isinstance(args.get("blocks"), list), "chat.update without blocks"
            return {"ok": True, "channel": args["channel"], "ts": args["ts"]}

        if method == "views.open":
            assert args.get("trigger_id"), "views.open without a trigger_id"
            v = args["view"]
            assert v["type"] == "modal" and v.get("callback_id"), "malformed view"
            return {"ok": True, "view": {"id": "V1", "callback_id": v["callback_id"]}}

        raise AssertionError(f"unexpected Slack method: {method}")

    def of(self, method: str) -> list[dict]:
        return [a for m, a in self.calls if m == method]

    def reset(self):
        self.calls.clear()


# ---------------------------------------------------------------------------
# Payload builders — Slack's documented interaction shapes
# ---------------------------------------------------------------------------

def block_actions(action_id: str, channel: str, ts: str, user: str = "U_MARCO",
                  trigger_id: str = "TRIG.1", value: str = "{}") -> dict:
    return {
        "type": "block_actions",
        "user": {"id": user},
        "channel": {"id": channel},
        "container": {"type": "message", "channel_id": channel, "message_ts": ts},
        "message": {"type": "message", "ts": ts},
        "trigger_id": trigger_id,
        "response_url": "https://hooks.slack.example/x",
        "actions": [{"type": "button", "action_id": action_id,
                     "block_id": "argus_triage_actions", "value": value,
                     "action_ts": "1755000000.000"}],
    }


def view_submission(channel: str, ts: str, text: str | None,
                    callback_id: str = ST.CALLBACK_BLOCKED_ON) -> dict:
    element = {"type": "plain_text_input"}
    if text is not None:
        element["value"] = text
    return {
        "type": "view_submission",
        "user": {"id": "U_MARCO"},
        "view": {
            "id": "V1", "type": "modal", "callback_id": callback_id,
            "private_metadata": json.dumps({"channel": channel, "ts": ts},
                                           separators=(",", ":")),
            "state": {"values": {ST.BLOCKED_ON_BLOCK_ID: {ST.BLOCKED_ON_ACTION_ID: element}}},
        },
    }


# ---------------------------------------------------------------------------
# Build the world: the 6.4 database, linked, filtered
# ---------------------------------------------------------------------------

def build_world():
    conn, spec, gh = VSF.build_db()
    ids = gh["ids"]
    srcs = [SF.link_sources_from_db(conn, i) for i in ids.values()]
    SF.ingest_ticket_links(conn, srcs, NOW)
    conn.commit()
    results = SF.run_pipeline(conn)
    return conn, ids, results


EMAILS = {
    "marco": "marco@acme.example",
    "dana": "dana@acme.example",
    # alice deliberately absent: an unresolvable recipient is a case this
    # step has to handle without sending a stranger somebody's pull request.
}
SLACK_USERS = {
    "marco@acme.example": "U_MARCO",
    "dana@acme.example": "U_DANA",
}


def email_for_login(login: str):
    return EMAILS.get(login)


def run():
    checks = 0
    conn, ids, results = build_world()
    fires = [r for r in results if r.outcome == SF.FIRE]

    # =====================================================================
    # A. The integration row, and the credential discipline
    # =====================================================================
    try:
        ST.get_or_create_slack_integration(conn, TEAM_ID, "xoxb-real-looking-token",
                                           "chat:write", NOW)
        raise AssertionError("a raw token was accepted as a credential_ref")
    except ValueError as exc:
        assert "POINTER" in str(exc)
    checks += 1

    integ = ST.get_or_create_slack_integration(
        conn, TEAM_ID, "secrets/slack_bot_token.txt",
        "chat:write,im:write,users:read,users:read.email", NOW, "ARGUS staging")
    again = ST.get_or_create_slack_integration(
        conn, TEAM_ID, "secrets/slack_bot_token.txt", "chat:write", NOW)
    assert integ == again, "a second install created a duplicate integration row"
    stored = conn.execute("SELECT credential_ref FROM integration WHERE id=?", (integ,)).fetchone()[0]
    assert not stored.startswith("xoxb-"), "a secret reached the database"
    checks += 1

    # =====================================================================
    # B. Identity resolution — the three routes and the honest failure
    # =====================================================================
    slack = FakeSlack(emails=SLACK_USERS)

    i_manual = ST.resolve_identity(conn, integ, "dana", slack, NOW,
                                   manual_map={"dana": "U_DANA_MANUAL"})
    assert i_manual.ok and i_manual.resolved_via == "manual_map"
    assert not slack.of("users.lookupByEmail"), "an explicit mapping still hit the API"
    checks += 1

    i_email = ST.resolve_identity(conn, integ, "marco", slack, NOW,
                                  email_for_login=email_for_login)
    assert i_email.ok and i_email.slack_user_id == "U_MARCO"
    assert i_email.resolved_via == "email_lookup" and i_email.matched_email == "marco@acme.example"
    checks += 1

    slack.reset()
    i_cached = ST.resolve_identity(conn, integ, "marco", slack, NOW,
                                   email_for_login=email_for_login)
    assert i_cached.ok and i_cached.slack_user_id == "U_MARCO"
    assert not slack.calls, "a cached identity still called Slack"
    checks += 1

    i_none = ST.resolve_identity(conn, integ, "alice", slack, NOW,
                                 email_for_login=email_for_login)
    assert not i_none.ok and i_none.resolved_via == "unresolved"
    assert "no email known" in i_none.detail
    row = conn.execute(
        "SELECT slack_user_id, resolved_via FROM slack_identity WHERE actor_id=?",
        (i_none.actor_id,)).fetchone()
    assert row == (None, "unresolved"), "an unresolved person was not recorded as unresolved"
    checks += 1

    # An email that Slack itself does not know: a different failure, same silence.
    i_missing = ST.resolve_identity(conn, integ, "priya", slack, NOW,
                                    email_for_login=lambda l: "priya@acme.example")
    assert not i_missing.ok and "users_not_found" in i_missing.detail
    checks += 1

    i_ghost = ST.resolve_identity(conn, integ, "nobody-by-that-name", slack, NOW)
    assert not i_ghost.ok and "no github actor" in i_ghost.detail
    checks += 1

    # =====================================================================
    # C. The composed message
    # =====================================================================
    fire = next(r for r in fires if r.next_actor == "marco")
    blocks = ST.compose_blocks(fire, item_url="https://github.com/acme/web/pull/401")
    actions = [b for b in blocks if b["type"] == "actions"]
    assert len(actions) == 1, "expected exactly one actions block"
    action_ids = [e["action_id"] for e in actions[0]["elements"]]
    assert action_ids == [ST.ACTION_HANDLED_OFFLINE, ST.ACTION_BLOCKED_ON, ST.ACTION_SNOOZE_7D], \
        f"the three buttons are wrong or reordered: {action_ids}"
    for e in actions[0]["elements"]:
        assert e["type"] == "button" and e["text"]["type"] == "plain_text"
        assert len(e["text"]["text"]) <= 75, "button label over Slack's 75-char limit"
        assert len(e["value"]) <= ST.BUTTON_VALUE_MAX, "button value over Slack's 2000-char limit"
        assert json.loads(e["value"])["work_item_id"] == fire.work_item_id
    checks += 1

    flat = json.dumps(blocks)
    assert fire.item_key in flat, "the DM does not name the item"
    assert "96" in flat or "4 days" in flat, "the DM does not say how long it has been idle"
    assert fire.evidence.split(";")[0][:20] in flat, "the DM omits the filter's own evidence"
    assert ST.compose_fallback_text(fire), "no fallback text — the push notification would be blank"
    checks += 1

    # A low-confidence item says so on the face of the message.
    import copy
    shaky = copy.deepcopy(fire)
    shaky.confidence = "low"
    assert "confidence: low" in json.dumps(ST.compose_blocks(shaky)), \
        "an incomplete-evidence alert did not disclose that"
    checks += 1

    # =====================================================================
    # D. The send
    # =====================================================================
    slack.reset()
    sends = ST.send_triage_dms(conn, slack, integ, results, NOW,
                               email_for_login=email_for_login)
    # 5 -> 6 at Phase 7.4X: P3 (Ghost State) fires on #417, a merged PR
    # whose ENG-101 is still 'In Progress' in an active sprint. The 6.4
    # fixtures were not edited to produce this — see
    # verify_sprint_filter.py's own note on #417.
    assert len(sends) == len(fires) == 6, f"expected one outcome per FIRE, got {len(sends)}"
    summary = ST.summarise_sends(sends)
    assert summary[ST.SENT] == 4, f"expected 4 DMs sent, got {summary[ST.SENT]}"
    # 1 -> 2 at Phase 7.4X. The sixth FIRE (P3 on #417) is addressed to
    # priya, the PR author, who has no resolvable Slack identity in these
    # fixtures either. Reported as a second FAILED/recipient_unresolved —
    # an integration gap named out loud, not an alert quietly dropped,
    # which is the whole reason this outcome exists.
    assert summary[ST.FAILED] == 2, "an unresolvable DM was not reported as failed"
    assert summary["failed_by_reason"] == {"recipient_unresolved": 2}
    checks += 1

    posts = slack.of("chat.postMessage")
    assert len(posts) == 4, f"{len(posts)} messages posted for 4 sendable fires"
    assert all(p["channel"].startswith("D") for p in posts), "a triage alert left a DM"
    assert conn.execute("SELECT COUNT(*) FROM triage_message").fetchone()[0] == 4
    # Nothing was written for the person we could not identify.
    alice_actor = ST._actor_id_for_login(conn, "alice")
    assert conn.execute("SELECT COUNT(*) FROM triage_message WHERE sent_to_actor_id=?",
                        (alice_actor,)).fetchone()[0] == 0, \
        "a DM row exists for a person no DM was sent to"
    checks += 1

    # Only FIRE rows produced DMs; SUPPRESSED and ABSTAIN items are untouched.
    sent_wids = {r[0] for r in conn.execute("SELECT work_item_id FROM triage_message")}
    fire_wids = {r.work_item_id for r in fires}
    assert sent_wids <= fire_wids, "a DM was sent about an item that did not fire"
    checks += 1

    # The full accounting mode: every item, including the quiet ones.
    everything = ST.send_triage_dms(conn, slack, integ, results, NOW, only_fires=False,
                                    email_for_login=email_for_login)
    assert len(everything) == len(results), "only_fires=False did not account for every item"
    assert sum(1 for r in everything if r.reason == "not_a_fire") == len(results) - len(fires)
    checks += 1

    # =====================================================================
    # E. Not nagging: a second run the same day sends nothing new
    # =====================================================================
    slack.reset()
    again = ST.send_triage_dms(conn, slack, integ, results, NOW,
                               email_for_login=email_for_login)
    s2 = ST.summarise_sends(again)
    assert s2[ST.SENT] == 0, "a second run re-sent DMs that were already waiting"
    assert s2["skipped_by_reason"].get("open_dm_awaiting_response") == 4
    assert not slack.of("chat.postMessage"), "a duplicate message was posted"
    assert conn.execute("SELECT COUNT(*) FROM triage_message").fetchone()[0] == 4
    checks += 1

    # =====================================================================
    # F. [Handled Offline]
    # =====================================================================
    msg = conn.execute(
        """SELECT id, external_channel_id, external_message_ts, work_item_id
           FROM triage_message ORDER BY id LIMIT 1""").fetchone()
    mid, chan, ts, wid = msg
    slack.reset()
    out = ST.handle_interaction(
        conn, block_actions(ST.ACTION_HANDLED_OFFLINE, chan, ts), slack, NOW)
    assert out.handled and out.action == "response_recorded"
    assert out.response_type == "handled_offline"
    r = conn.execute(
        "SELECT response_type, blocked_on_text, responded_at FROM triage_response WHERE triage_message_id=?",
        (mid,)).fetchall()
    assert r == [("handled_offline", None, NOW)], f"wrong response row: {r}"
    assert conn.execute("SELECT status, snooze_until FROM triage_message WHERE id=?",
                        (mid,)).fetchone() == ("responded", None)
    checks += 1

    updates = slack.of("chat.update")
    assert len(updates) == 1 and updates[0]["ts"] == ts, "the DM was not rewritten in place"
    assert not any(b.get("type") == "actions" for b in updates[0]["blocks"]), \
        "the buttons were left in place after the answer — a dead button reads as a broken app"
    checks += 1

    # A retried delivery must not write a second row (D-112's lesson).
    slack.reset()
    retry = ST.handle_interaction(
        conn, block_actions(ST.ACTION_HANDLED_OFFLINE, chan, ts), slack, NOW)
    assert retry.handled and retry.action == "already_responded"
    assert conn.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                        (mid,)).fetchone()[0] == 1, "a retried click doubled the response"
    assert not slack.calls, "a retried click still called Slack"
    checks += 1

    # And a different button on an already-answered message changes nothing.
    ST.handle_interaction(conn, block_actions(ST.ACTION_SNOOZE_7D, chan, ts), slack, NOW)
    assert conn.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                        (mid,)).fetchone()[0] == 1
    checks += 1

    # The cooling-off period: quiet tomorrow, speaking again after it lapses.
    d = ST.should_send(conn, wid, plus_days(NOW, 1))
    assert not d.send and d.reason == "recently_answered", f"got {d}"
    d = ST.should_send(conn, wid, plus_days(NOW, ST.RESPONSE_COOLDOWN_DAYS + 1))
    assert d.send, "ARGUS stayed silent forever after one 'handled offline'"
    checks += 1

    # =====================================================================
    # G. [Snooze 7d]
    # =====================================================================
    msg2 = conn.execute(
        """SELECT id, external_channel_id, external_message_ts, work_item_id
           FROM triage_message WHERE status='sent' ORDER BY id LIMIT 1""").fetchone()
    mid2, chan2, ts2, wid2 = msg2
    slack.reset()
    out = ST.handle_interaction(conn, block_actions(ST.ACTION_SNOOZE_7D, chan2, ts2), slack, NOW)
    assert out.response_type == "snooze_7d"
    status, until = conn.execute(
        "SELECT status, snooze_until FROM triage_message WHERE id=?", (mid2,)).fetchone()
    assert status == "responded"
    assert until == plus_days(NOW, ST.SNOOZE_DAYS), f"snooze_until is {until}"
    checks += 1

    d = ST.should_send(conn, wid2, plus_days(NOW, 6))
    assert not d.send and d.reason == "snoozed", f"a snooze did not hold: {d}"
    d = ST.should_send(conn, wid2, plus_days(NOW, 8))
    assert d.send, "a 7-day snooze never expired"
    checks += 1

    # =====================================================================
    # H. [Blocked on X] — the two-step round trip
    # =====================================================================
    msg3 = conn.execute(
        """SELECT id, external_channel_id, external_message_ts, work_item_id
           FROM triage_message WHERE status='sent' ORDER BY id LIMIT 1""").fetchone()
    mid3, chan3, ts3, wid3 = msg3
    slack.reset()
    out = ST.handle_interaction(conn, block_actions(ST.ACTION_BLOCKED_ON, chan3, ts3), slack, NOW)
    assert out.handled and out.action == "modal_opened"
    opened = slack.of("views.open")
    assert len(opened) == 1, "the dialog did not open"
    view = opened[0]["view"]
    assert view["callback_id"] == ST.CALLBACK_BLOCKED_ON
    meta = json.loads(view["private_metadata"])
    assert meta == {"channel": chan3, "ts": ts3}, "the modal lost track of which message it is about"
    inputs = [b for b in view["blocks"] if b["type"] == "input"]
    assert len(inputs) == 1 and inputs[0]["block_id"] == ST.BLOCKED_ON_BLOCK_ID
    assert inputs[0]["element"]["action_id"] == ST.BLOCKED_ON_ACTION_ID
    checks += 1

    # Opening a dialog is not an answer. Cancelling it must leave no trace.
    assert conn.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                        (mid3,)).fetchone()[0] == 0, "opening the dialog recorded an answer"
    assert conn.execute("SELECT status FROM triage_message WHERE id=?",
                        (mid3,)).fetchone()[0] == "sent"
    checks += 1

    # An empty submission is refused with Slack's own error shape, not stored.
    slack.reset()
    bad = ST.handle_interaction(conn, view_submission(chan3, ts3, "   "), slack, NOW)
    assert not bad.handled and bad.action == "validation_error"
    assert bad.response_body["response_action"] == "errors"
    assert ST.BLOCKED_ON_BLOCK_ID in bad.response_body["errors"]
    assert conn.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                        (mid3,)).fetchone()[0] == 0, "an empty blocker was recorded"
    checks += 1

    slack.reset()
    good = ST.handle_interaction(
        conn, view_submission(chan3, ts3, "  waiting on the infra team for a staging DB  "),
        slack, NOW)
    assert good.handled and good.response_type == "blocked_on"
    rt, txt = conn.execute(
        "SELECT response_type, blocked_on_text FROM triage_response WHERE triage_message_id=?",
        (mid3,)).fetchone()
    assert rt == "blocked_on"
    assert txt == "waiting on the infra team for a staging DB", f"stored {txt!r}"
    assert conn.execute("SELECT status FROM triage_message WHERE id=?",
                        (mid3,)).fetchone()[0] == "responded"
    upd = slack.of("chat.update")
    assert len(upd) == 1 and "infra team" in json.dumps(upd[0]["blocks"]), \
        "the rewritten DM does not show what it was recorded as blocked on"
    checks += 1

    # A resubmitted modal must not double the row either.
    ST.handle_interaction(conn, view_submission(chan3, ts3, "something else"), slack, NOW)
    assert conn.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                        (mid3,)).fetchone()[0] == 1, "a resubmitted modal doubled the response"
    checks += 1

    # =====================================================================
    # I. Payloads that are not ours, and coordinates we do not know
    # =====================================================================
    for payload, why in [
        (block_actions("some_other_apps_button", chan3, ts3), "another app's button"),
        (block_actions(ST.ACTION_SNOOZE_7D, "D_UNKNOWN", "999.000"), "unknown coordinates"),
        ({"type": "shortcut"}, "an unhandled payload type"),
        ({"type": "block_actions", "actions": []}, "an empty actions array"),
        (view_submission(chan3, ts3, "x", callback_id="someone_elses_modal"), "another modal"),
    ]:
        before = conn.execute("SELECT COUNT(*) FROM triage_response").fetchone()[0]
        res = ST.handle_interaction(conn, payload, slack, NOW)
        assert not res.handled, f"ARGUS claimed to handle {why}"
        after = conn.execute("SELECT COUNT(*) FROM triage_response").fetchone()[0]
        assert before == after, f"{why} wrote a response row"
    checks += 1

    # =====================================================================
    # J. When Slack itself fails
    # =====================================================================
    # A post that fails leaves no half-tracked message behind.
    conn2, ids2, results2 = build_world()
    integ2 = ST.get_or_create_slack_integration(conn2, TEAM_ID, "secrets/slack_bot_token.txt",
                                                "chat:write", NOW)
    broken = FakeSlack(emails=SLACK_USERS, fail={"chat.postMessage": "channel_not_found"})
    out2 = ST.send_triage_dms(conn2, broken, integ2, results2, NOW,
                              email_for_login=email_for_login)
    s3 = ST.summarise_sends(out2)
    assert s3[ST.SENT] == 0 and s3[ST.FAILED] == 6
    assert s3["failed_by_reason"].get("slack_error") == 4
    assert conn2.execute("SELECT COUNT(*) FROM triage_message").fetchone()[0] == 0, \
        "a failed post still created a triage_message row"
    checks += 1

    # A redraw that fails must NOT lose the developer's answer.
    conn3, ids3, results3 = build_world()
    integ3 = ST.get_or_create_slack_integration(conn3, TEAM_ID, "secrets/slack_bot_token.txt",
                                                "chat:write", NOW)
    flaky = FakeSlack(emails=SLACK_USERS)
    ST.send_triage_dms(conn3, flaky, integ3, results3, NOW, email_for_login=email_for_login)
    m = conn3.execute("""SELECT id, external_channel_id, external_message_ts
                         FROM triage_message ORDER BY id LIMIT 1""").fetchone()
    flaky.fail = {"chat.update": "message_not_found"}
    res = ST.handle_interaction(
        conn3, block_actions(ST.ACTION_HANDLED_OFFLINE, m[1], m[2]), flaky, NOW)
    assert res.handled and res.action == "response_recorded"
    assert "message_update_failed" in res.reason, "a failed redraw was reported as success"
    assert conn3.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                         (m[0],)).fetchone()[0] == 1, \
        "the answer was lost because a cosmetic redraw failed"
    checks += 1

    # =====================================================================
    # J2. An ignored DM must not silence an item forever
    #
    # This section exists because of a defect found by simulating a month
    # of daily runs and reading the output, not by a test: without expiry,
    # a DM nobody clicks sits at 'sent' forever and blocks every future
    # alert on that item. Silence because a developer ignored one message
    # looked exactly like silence because nothing was wrong.
    # =====================================================================
    conn4, ids4, results4 = build_world()
    integ4 = ST.get_or_create_slack_integration(conn4, TEAM_ID, "secrets/slack_bot_token.txt",
                                                "chat:write", NOW)
    quiet = FakeSlack(emails=SLACK_USERS)
    ST.send_triage_dms(conn4, quiet, integ4, results4, NOW, email_for_login=email_for_login)
    assert conn4.execute(
        "SELECT COUNT(*) FROM triage_message WHERE status='sent'").fetchone()[0] == 4

    # Nobody clicks anything, ever. Before expiry falls due, ARGUS stays quiet.
    mid_run = ST.send_triage_dms(conn4, quiet, integ4, results4, plus_days(NOW, 3),
                                 email_for_login=email_for_login)
    assert ST.summarise_sends(mid_run)["skipped_by_reason"].get(
        "open_dm_awaiting_response") == 4, "ARGUS nagged before the DM had had a fair chance"
    checks += 1

    # Once expiry falls due the message is written off — as a counted fact —
    # and the item becomes eligible again.
    later = plus_days(NOW, ST.EXPIRE_UNANSWERED_DAYS + 1)
    after = ST.send_triage_dms(conn4, quiet, integ4, results4, later,
                               email_for_login=email_for_login)
    assert ST.summarise_sends(after)[ST.SENT] == 4, \
        "an ignored DM silenced its item permanently"
    expired = conn4.execute(
        "SELECT COUNT(*), MIN(suppressed_reason) FROM triage_message WHERE status='expired'"
    ).fetchone()
    assert expired[0] == 4, "unanswered DMs were not written off as expired"
    assert "unanswered" in (expired[1] or ""), "expiry did not record why"
    checks += 1

    # A late click on an expired DM is still a real answer and is still kept.
    old = conn4.execute("""SELECT id, external_channel_id, external_message_ts
                           FROM triage_message WHERE status='expired' ORDER BY id LIMIT 1""").fetchone()
    ST.handle_interaction(conn4, block_actions(ST.ACTION_HANDLED_OFFLINE, old[1], old[2]),
                          quiet, later)
    assert conn4.execute("SELECT COUNT(*) FROM triage_response WHERE triage_message_id=?",
                         (old[0],)).fetchone()[0] == 1, "a late answer was thrown away"
    checks += 1

    # =====================================================================
    # K. No hidden wall clock
    # =====================================================================
    for bad_now in ["", "not-a-date", "yesterday"]:
        try:
            ST.should_send(conn, wid, bad_now)
            raise AssertionError(f"{bad_now!r} was accepted as a reference time")
        except ValueError as exc:
            assert "D-064" in str(exc)
    checks += 1

    # =====================================================================
    # L. The ledger 6.8 will read
    # =====================================================================
    ledger = ST.triage_ledger(conn)
    assert len(ledger) == 4
    kinds = sorted(e["response_type"] or "none" for e in ledger)
    assert kinds == ["blocked_on", "handled_offline", "none", "snooze_7d"], kinds
    assert all(e["sent_to"] in ("marco", "dana") for e in ledger)
    blocked = next(e for e in ledger if e["response_type"] == "blocked_on")
    assert blocked["blocked_on_text"] == "waiting on the infra team for a staging DB"
    checks += 1

    print_report(conn, sends, ledger)
    print(f"\nAll {checks} fixture-based checks passed.")


def print_report(conn, sends, ledger):
    print("\n--- What ARGUS did with the 5 alerts the filter fired ---")
    print(f"{'item':<16}{'to':<8}{'outcome':<9}{'reason':<28}detail")
    for s in sends:
        print(f"{s.item_key:<16}{(s.recipient_login or '-'):<8}{s.outcome:<9}"
              f"{s.reason:<28}{s.detail}")

    print("\n--- The triage ledger (what step 6.8's digest reads) ---")
    print(f"{'item':<16}{'to':<8}{'status':<11}{'answer':<17}extra")
    for e in ledger:
        extra = e["blocked_on_text"] or (f"until {e['snooze_until']}" if e["snooze_until"] else "")
        print(f"{e['item']:<16}{e['sent_to']:<8}{e['status']:<11}"
              f"{(e['response_type'] or '—'):<17}{extra}")

    print("\n--- Identity resolution ---")
    for login, uid, via, detail in conn.execute(
            """SELECT a.source_key, si.slack_user_id, si.resolved_via, si.matched_email
               FROM slack_identity si JOIN actor a ON a.id = si.actor_id
               ORDER BY a.source_key"""):
        print(f"  {login:<22}{(uid or '—'):<16}{via:<14}{detail or ''}")


if __name__ == "__main__":
    run()
