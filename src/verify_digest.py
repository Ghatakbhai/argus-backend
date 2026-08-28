"""
ARGUS — Phase 6.8 verification: the Unified Standup Digest, offline.

Same discipline as the five verifiers before it: every assertion fails
loudly, nothing passes silently, fixtures are realistic rather than
convenient, and — the lesson that has now caught the one real defect in
each of the last THREE steps — the run prints its own output so a human can
read what actually happened instead of trusting a pass line.

Section H is the important one. It simulates six weeks of daily runs and
prints every morning's digest, because this project has a characteristic
defect: **a temporary state quietly becoming a permanent one.** It appeared
at 6.4 (a double-abstain reporting one reason), at 6.6 (an unanswered DM
silencing an item forever) and at 6.7 (a release throttle that never
stopped throttling). Every one of them passed its tests first. Three
candidates existed in this step by construction — a blocker report, a
give-up after three unanswered asks, and a "held since" date — and the
simulation is what settles whether any of them rots.

Slack is stood in for by 6.6's `FakeSlack`, extended by 6.7's
`ProfileSlack`. D-115 stands: nothing here has spoken to real Slack, so
what is proved is that ARGUS assembles and renders honestly — not that
Slack accepts the payload. 6.9 owns that.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
import digest as DG
import presence as P
import slack_triage as ST
import sprint_filter as SF
import verify_presence as VP
import verify_slack_triage as VST

NOW = VST.NOW                                   # 2026-08-21T12:00:00Z
TEAM_ID = "T0ARGUS01"
LEAD_UID = "U_LEAD"
CHANNEL = "C_DEV_STANDUP"


def days(base: str, n: float) -> str:
    return VST.plus_days(base, n)


class DigestSlack(VP.ProfileSlack):
    """6.7's fake, plus the ability to post somewhere that is not a DM.

    6.6's `FakeSlack` asserts that every `chat.postMessage` goes to a `D…`
    channel, and it was right to: everything 6.6 sent was a DM. 6.8 makes
    the first non-DM post in the project's history, which is worth pausing
    on rather than patching past — it means 6.5's deliberately DM-only
    scopes are no longer sufficient, and the bot must be invited to
    #dev-standup before this works on a real workspace. Recorded at D-118
    and carried to 6.9 as a live-environment task, not assumed away here.
    """

    def call(self, method: str, **args):
        if method == "chat.postMessage":
            ch = args.get("channel", "")
            assert ch and ch[0] in "DC", f"posted to {ch!r}, not a DM or a channel"
            assert args.get("text"), "chat.postMessage sent with no fallback text"
            assert isinstance(args.get("blocks"), list) and args["blocks"], "no blocks"
            self.calls.append((method, args))
            if method in self.fail:
                raise ST.SlackError(method, self.fail[method])
            self._ts += 1
            return {"ok": True, "channel": ch, "ts": f"{self._ts}.000100"}
        return super().call(method, **args)


# ---------------------------------------------------------------------------
# World building
# ---------------------------------------------------------------------------

def build():
    """The 6.4 world, with Slack identities resolved the way 6.6 resolves them.

    marco and dana match by email; **alice deliberately does not**. An alert
    with a real recipient ARGUS cannot find in Slack is not a hypothetical —
    it is what happens on every team with a contractor, a renamed account or
    a personal-email GitHub login — and schema section 12 reserved an
    'unresolved' identity row specifically so this digest could report it.
    """
    conn, ids, results = VST.build_world()
    integ = ST.get_or_create_slack_integration(
        conn, TEAM_ID, "secrets/slack_bot_token.txt",
        "chat:write,im:write,users:read,users:read.email,users.profile:read", NOW)
    fake = VP.ProfileSlack(emails=VST.SLACK_USERS)
    for login in ("marco", "dana", "alice"):
        ST.resolve_identity(conn, integ, login, fake, NOW,
                            email_for_login=VST.email_for_login)
    conn.commit()
    return conn, integ, results


def actor_id(conn, login):
    return ST._actor_id_for_login(conn, login)


def wid_of(conn, item_key):
    n = int(item_key.split("#")[1])
    return conn.execute(
        "SELECT id FROM work_item WHERE source_number = ?", (n,)).fetchone()[0]


def force_answer(conn, wid, login, response_type, text, at):
    """Record a DM that was sent and answered, without a live Slack.

    Writes the rows 6.6 would have written. Deliberately not a shortcut
    around `handle_interaction` — that path has its own 36 checks at 6.6 —
    but the only way to place an answer at an arbitrary point in the past,
    which the six-week simulation needs.
    """
    cur = conn.execute(
        """INSERT INTO triage_message (integration_id, work_item_id, sent_to_actor_id,
                                        external_channel_id, external_message_ts,
                                        sent_at, status)
           VALUES ((SELECT MIN(id) FROM integration), ?, ?, 'D_X', ?, ?, 'responded')""",
        (wid, actor_id(conn, login), f"{abs(hash(at)) % 10**6}.0001", at))
    conn.execute(
        """INSERT INTO triage_response (triage_message_id, response_type,
                                         blocked_on_text, responded_at)
           VALUES (?,?,?,?)""", (cur.lastrowid, response_type, text, at))
    conn.commit()
    return cur.lastrowid


def force_ignored_ask(conn, wid, login, sent_at, status="expired"):
    """A DM that was sent and never answered.

    Written as 'sent' by the simulation, which then calls 6.6's own
    `expire_stale_messages` on each simulated morning exactly as the daily
    job does. Letting the real expiry code make the transition is the
    difference between testing this step and testing a story about it.
    """
    conn.execute(
        """INSERT INTO triage_message (integration_id, work_item_id, sent_to_actor_id,
                                        external_channel_id, external_message_ts,
                                        sent_at, status, suppressed_reason)
           VALUES ((SELECT MIN(id) FROM integration), ?, ?, 'D_X', ?, ?, ?, NULL)""",
        (wid, actor_id(conn, login), f"{abs(hash(sent_at)) % 10**6}.0002",
         sent_at, status))
    conn.commit()


def set_presence(conn, login, status, frm, to=None):
    conn.execute(
        """INSERT INTO presence (actor_id, status, detected_via, effective_from,
                                  effective_to, detected_at)
           VALUES (?,?, 'slack_status', ?,?,?)""",
        (actor_id(conn, login), status, frm, to, frm))
    conn.commit()


def backdate_item(conn, wid, days_back: float):
    """Push an item's whole history further into the past.

    Needed because the two are not independent: for ARGUS to have asked
    about an item three times and been ignored, three weeks must have
    passed with nobody touching it — so an item with three ignored asks is
    necessarily an item that has been idle for at least that long. Placing
    the asks without also aging the item would have built a world that
    cannot occur, and a fixture that cannot occur proves nothing.
    """
    from datetime import timedelta
    rows = conn.execute(
        "SELECT id, occurred_at FROM event WHERE work_item_id = ? AND occurred_at IS NOT NULL",
        (wid,)).fetchall()
    for eid, at in rows:
        conn.execute("UPDATE event SET occurred_at = ? WHERE id = ?",
                     (ST._iso(ST._parse(at) - timedelta(days=days_back)), eid))
    conn.commit()


def add_human_event(conn, wid, login, at):
    """A real person did something to the item — a comment, in effect."""
    conn.execute(
        """INSERT INTO event (snapshot_id, work_item_id, actor_id, type, occurred_at,
                               date_precision, counts_as_human, human_reason, detail)
           VALUES ((SELECT snapshot_id FROM work_item WHERE id = ?), ?, ?,
                   'commented', ?, 'exact', 1, 'human', 'verify_digest')""",
        (wid, wid, actor_id(conn, login), at))
    conn.commit()


# ---------------------------------------------------------------------------

def run():
    checks = 0
    conn, integ, results = build()
    fires = [r for r in results if r.outcome == SF.FIRE]
    # 5 -> 6 at Phase 7.4X: P3 (Ghost State) fires on #417, a merged PR
    # whose ENG-101 is still 'In Progress' in an active sprint. The 6.4
    # fixtures were not edited to produce this — see
    # verify_sprint_filter.py's own note on #417.
    assert len(fires) == 6, f"expected 6 FIREs from the 6.4 world, got {len(fires)}"

    w401 = wid_of(conn, "acme/web#401")
    w410 = wid_of(conn, "acme/web#410")
    w423 = wid_of(conn, "acme/web#423")
    w425 = wid_of(conn, "acme/web#425")

    # =====================================================================
    # A. An empty morning is still a message  (Dirgh's call, session 34)
    # =====================================================================
    empty = DG.collect(conn, [r for r in results if r.outcome != SF.FIRE], NOW,
                       team_label="acme/web")
    assert empty.all_clear, "a world with no fires and no history is not all-clear"
    # 18 -> 17 at Phase 7.4X: one more of the 23 items now FIREs (P3 on
    # #417), so one fewer is left in the not-fired set this all-clear is
    # built from. The suppressed count is unchanged.
    assert empty.counts.items_checked == 17 and empty.counts.suppressed == 6, \
        empty.counts.as_dict()
    blocks = DG.render_slack_blocks(empty)
    assert blocks, "an all-clear morning produced NO message — Dirgh asked for one"
    flat = json.dumps(blocks)
    assert "nothing stuck" in flat.lower()
    assert "17 items checked" in flat and "suppressed" in flat, \
        "the all-clear must carry its evidence, or it proves nothing about liveness"
    checks += 1
    print("  check 1  a quiet morning still sends a short all-clear, with its counts")

    # And the same is true of every renderer, not just the DM.
    assert "nothing stuck" in DG.render_channel_text(empty).lower()
    assert "nothing stuck" in DG.render_slack_text(empty).lower()
    assert "Nothing stuck" in DG.render_html(empty)
    checks += 1
    print("  check 2  all-clear reaches the channel post, the HTML and the push text")

    # =====================================================================
    # B. Ranking — Dirgh's order, top to bottom
    # =====================================================================
    force_answer(conn, w401, "marco", "blocked_on",
                 "waiting on the infra team to unblock the staging deploy",
                 days(NOW, -2))
    set_presence(conn, "dana", P.OUT_OF_OFFICE, days(NOW, -9))
    conn.execute(
        """INSERT INTO triage_message (integration_id, work_item_id, sent_to_actor_id,
                                        external_channel_id, external_message_ts,
                                        sent_at, status, suppressed_reason)
           VALUES (?,?,?,NULL,NULL,?, 'suppressed_presence', 'presence:1: out of office')""",
        (integ, w410, actor_id(conn, "dana"), days(NOW, -8)))
    backdate_item(conn, w423, 25)          # see backdate_item: the two go together
    for k in (21, 14, 8):
        force_ignored_ask(conn, w423, "marco", days(NOW, -k))
    conn.commit()
    results = SF.run_pipeline(conn)        # the item is now genuinely 30 days idle

    d = DG.collect(conn, results, NOW, team_label="acme/web")
    got = [(r.section, r.item_key) for r in d.rows]
    assert got[0][0] == DG.SECTION_BLOCKED, f"a named blocker is not on top: {got}"
    assert got[0][1] == "acme/web#401", got
    order = [r.section for r in d.rows]
    assert order.index(DG.SECTION_BLOCKED) < order.index(DG.SECTION_ESCALATION) \
        < order.index(DG.SECTION_UNANSWERED), order
    checks += 1
    print("  check 3  blockers -> escalations -> unanswered, exactly as Dirgh ranked them")

    # A two-day blocker outranks a nine-day absence. That is the whole point
    # of choosing this ordering: recency loses to actionability.
    assert d.rows[0].age_hours < d.rows[1].age_hours, \
        "the ranking fell back to plain age and lost Dirgh's ordering"
    checks += 1
    print("  check 4  a 2-day named blocker outranks a 9-day absence, by design")

    # =====================================================================
    # C. Each section says something true
    # =====================================================================
    esc = d.section(DG.SECTION_ESCALATION)
    assert len(esc) == 1 and esc[0].item_key == "acme/web#410", [r.item_key for r in esc]
    assert "9 days" in esc[0].headline, esc[0].headline
    checks += 1
    print("  check 5  a 9-day absence with a held alert escalates to the lead")

    un = d.section(DG.SECTION_UNANSWERED)
    assert len(un) == 1 and un[0].item_key == "acme/web#423", [r.item_key for r in un]
    assert "asked 3 times" in un[0].headline.lower(), un[0].headline
    checks += 1
    print("  check 6  three ignored asks move an item from DMs to the lead's digest")

    unreach = d.section(DG.SECTION_UNREACHABLE)
    assert [r.item_key for r in unreach] == ["acme/web#422"], [r.item_key for r in unreach]
    assert "alice" in unreach[0].headline
    checks += 1
    print("  check 7  a FIRE with no resolvable Slack account is reported, not swallowed")

    # =====================================================================
    # D. One item never appears twice
    # =====================================================================
    keys = [r.item_key for r in d.rows]
    assert len(keys) == len(set(keys)), f"an item is double-counted: {keys}"
    checks += 1
    print("  check 8  one item, one row — no heading inflates the size of the board")

    # =====================================================================
    # E. The channel post names nobody   (Dirgh's call, session 34)
    # =====================================================================
    ch = json.dumps(DG.render_channel_blocks(d))
    for name in ("marco", "dana", "alice", "#401", "#410", "#422", "#423"):
        assert name not in ch, f"the channel post leaked {name!r}: {ch}"
    assert "3" in ch or "1" in ch, "the channel post carries no counts at all"
    checks += 1
    print("  check 9  the #dev-standup post carries counts and leaks no name or PR number")

    # The lead's DM, by contrast, must name people — that is its whole job.
    lead = json.dumps(DG.render_slack_blocks(d))
    assert "marco" in lead and "dana" in lead, "the lead's DM named nobody"
    checks += 1
    print("  check 10 the lead's DM does name people — the two renderings differ on purpose")

    # =====================================================================
    # F. Block Kit shape, and Slack's hard limits
    # =====================================================================
    for b in DG.render_slack_blocks(d):
        assert b.get("type") in {"header", "section", "context", "divider", "actions"}, b
        if b["type"] == "header":
            assert b["text"]["type"] == "plain_text", "header blocks take plain_text only"
            assert len(b["text"]["text"]) <= 150, "header text over Slack's limit"
        if b["type"] == "context":
            assert len(b["elements"]) <= 10, "context takes at most 10 elements"
    checks += 1
    print("  check 11 every emitted block is a real Block Kit type with legal fields")

    # A flood must truncate loudly, and never exceed 50 blocks.
    flood = DG.Digest(generated_at=NOW, team_label="acme/web", rows=[
        DG.DigestRow(section=DG.SECTION_AWAITING, item_key=f"acme/web#{900 + i}",
                     headline="Waiting on somebody", age_hours=float(i),
                     age_label=f"{i}h", work_item_id=9000 + i)
        for i in range(60)])
    fb = DG.render_slack_blocks(flood)
    assert len(fb) <= DG.SLACK_BLOCK_LIMIT, f"{len(fb)} blocks; Slack refuses over 50"
    assert "and 55 more" in json.dumps(fb), "60 rows were cut down to 5 with no notice"
    checks += 1
    print("  check 12 60 rows truncate to a legal message that SAYS it truncated")

    # =====================================================================
    # G. The HTML report: self-contained, complete, and escaped
    # =====================================================================
    hostile = DG.Digest(generated_at=NOW, team_label="acme/web", rows=[
        DG.DigestRow(section=DG.SECTION_BLOCKED, item_key="acme/web#1",
                     headline="<script>alert('xss')</script> & \"quoted\"",
                     person="mallory", age_hours=1.0, age_label="1h", work_item_id=1)])
    h = DG.render_html(hostile)
    assert "<script>alert" not in h, "a developer's typed blocker text reached the page as HTML"
    assert "&lt;script&gt;" in h, "the text was dropped instead of escaped"
    checks += 1
    print("  check 13 free text typed by a developer is escaped, not executed")

    full = DG.render_html(flood)
    assert full.count("acme/web#9") >= 60, "the HTML report truncated; it must never"
    checks += 1
    print("  check 14 the HTML report shows all 60 rows — the DM truncates, this does not")

    page = DG.render_html(d)
    external = re.findall(r'(?:src|href)\s*=\s*["\'](https?:)?//[^"\']+', page)
    external = [u for u in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)', page)
                if u.startswith("http") and "github.com" not in u and "acme" not in u]
    assert not external, f"the report is not self-contained: {external}"
    assert "<script" not in page.lower(), "the report ships script; it must be inert"
    assert "prefers-color-scheme" in page, "no dark rendering; leads read this at 7am"
    assert "viewport" in page, "not readable on a phone"
    checks += 1
    print("  check 15 the report is self-contained, script-free, dark-aware and responsive")

    # The number Phase 6 is actually judged on must be on the page.
    assert "not active sprint work" in page or "not_active_sprint_work" in page
    assert "Suppressed, by reason" in page
    checks += 1
    print("  check 16 the suppressed-by-reason breakdown — Phase 6's kill number — is on the page")

    # =====================================================================
    # H. Both renderings agree, because both read the same collection
    # =====================================================================
    r = DG.build_digest(conn, results, NOW, team_label="acme/web")
    assert (len(r.digest.rows) == len(d.rows)), "collect() is not deterministic"
    n_html = sum(r.html.count(row.item_key) for row in r.digest.rows)
    assert n_html >= len(r.digest.rows), "the HTML lost rows the digest had"
    for row in r.digest.rows[:5]:
        assert row.item_key in json.dumps(r.lead_blocks), \
            f"{row.item_key} is in the report but not in the top of the DM"
    checks += 1
    print("  check 17 the DM and the report are rendered from one collection and agree")

    # =====================================================================
    # I. Sending is separate from building, and every failure is reported
    # =====================================================================
    fake = DigestSlack(emails=VST.SLACK_USERS)
    out = DG.send_digest(conn, fake, r, lead_slack_user_id=LEAD_UID, channel_id=CHANNEL)
    assert out["lead"]["ok"] and out["channel"]["ok"], out
    posted = [a for m, a in fake.calls if m == "chat.postMessage"]
    assert any(a["channel"] == CHANNEL for a in posted), "the channel post never went"
    assert all(a.get("text") for a in posted), "a post went with no fallback text"
    checks += 1
    print("  check 18 the lead DM and the channel post both go, each with fallback text")

    # 6.5 took DM-only scopes on purpose. Until the bot is invited to
    # #dev-standup this is the expected error, and it must not cost the DM.
    class NotInChannel(DigestSlack):
        def call(self, method, **a):
            if method == "chat.postMessage" and a.get("channel") == CHANNEL:
                raise ST.SlackError(method, "not_in_channel")
            return super().call(method, **a)

    out = DG.send_digest(conn, NotInChannel(emails=VST.SLACK_USERS), r,
                         lead_slack_user_id=LEAD_UID, channel_id=CHANNEL)
    assert out["lead"]["ok"], "a channel failure took the lead's DM down with it"
    assert out["channel"]["ok"] is False and out["channel"]["error"] == "not_in_channel", out
    checks += 1
    print("  check 19 a channel the bot was never invited to fails loudly and alone")

    assert DG.collect(conn, results, NOW).as_dict() == \
        DG.collect(conn, results, NOW).as_dict(), "collect() mutated something"
    before = conn.execute("SELECT COUNT(*) FROM triage_message").fetchone()[0]
    DG.build_digest(conn, results, NOW)
    assert conn.execute("SELECT COUNT(*) FROM triage_message").fetchone()[0] == before, \
        "building a digest wrote a row; it must be read-only"
    checks += 1
    print("  check 20 building a digest twice changes nothing — it is read-only")

    # =====================================================================
    # J. The give-up limiter, and the reset that keeps it from going permanent
    # =====================================================================
    lim = DG.give_up_limiter(conn)
    assert lim(actor_id(conn, "marco"), w423, NOW)["reason"] == "unanswered_ask_limit"
    assert lim(actor_id(conn, "marco"), w401, NOW) is None, "an answered item was given up on"
    checks += 1
    print("  check 21 three ignored asks stop the DMs; an answered item is untouched")

    add_human_event(conn, w423, "marco", days(NOW, -1))
    assert DG.unanswered_ask_count(conn, w423) == 0, \
        "the give-up count survived the developer coming back to the item"
    assert lim(actor_id(conn, "marco"), w423, NOW) is None, \
        "ARGUS stayed permanently silent about an item somebody is actively working on"
    checks += 1
    print("  check 22 a human touching the item resets the count — giving up is not permanent")

    # And it drops out of the digest at the same moment, without a flag to clear.
    d2 = DG.collect(conn, results, NOW, team_label="acme/web")
    assert not d2.section(DG.SECTION_UNANSWERED), \
        "the digest still lists an item ARGUS has resumed asking about"
    checks += 1
    print("  check 23 the digest row leaves with it — no state left behind to go stale")

    # Chaining: 6.7's throttle and 6.8's give-up share one slot, neither loses.
    seen = []
    a_lim = lambda a, w, n: seen.append("a") or None
    b_lim = lambda a, w, n: {"reason": "b_vetoed"}
    c_lim = lambda a, w, n: seen.append("c") or None
    chained = DG.chain_limiters(a_lim, b_lim, c_lim)
    assert chained(1, 1, NOW) == {"reason": "b_vetoed"}, "the first veto did not win"
    assert seen == ["a"], f"a limiter ran after the veto: {seen}"
    assert DG.chain_limiters(None, a_lim)(1, 1, NOW) is None
    checks += 1
    print("  check 24 chain_limiters lets 6.7's throttle and 6.8's give-up share one slot")

    # The claim that matters: 6.6 and 6.7 are untouched by any of this.
    real = DG.chain_limiters(DG.give_up_limiter(conn), P.held_release_limiter(conn))
    assert callable(real) and real(actor_id(conn, "marco"), w425, NOW) is None
    checks += 1
    print("  check 25 the composed limiter drops straight into 6.6's existing hook")

    # =====================================================================
    # K. A row lives only as long as the alert it came from
    # =====================================================================
    # The rule that keeps the board from accumulating. Found by rendering a
    # sample and reading it, not by a test: a blocker reported on a PR that
    # the team later moved to the backlog would otherwise lead the digest
    # until somebody closed the PR, months later.
    parked = [r for r in results if r.work_item_id != w401]
    d3 = DG.collect(conn, parked, NOW, team_label="acme/web")
    assert not [r for r in d3.rows if r.item_key == "acme/web#401"], \
        "an item the filter stopped flagging kept its row in the digest"
    assert d.section(DG.SECTION_BLOCKED), "…but it must be there while the alert is live"
    checks += 1
    print("  check 26 a row disappears the moment the filter stops flagging its item")

    print(f"\n  --- Today's digest, as the tech lead would read it ---\n")
    print(DG.render_text(d))
    return conn, integ, results, checks


# ---------------------------------------------------------------------------
# H. Six weeks of mornings — where this project's defects actually live
# ---------------------------------------------------------------------------

def simulate(checks: int) -> int:
    """Run the same day forty-two times and read what happens.

    Every real defect in the last three steps was found this way and none
    were found by the tests. The question being asked is always the same:
    is there a state that was supposed to be temporary and has quietly
    become permanent?

    Three candidates existed in 6.8 by construction:
      1. a [Blocked on…] answer that is shown forever;
      2. a give-up after three ignored asks that never lifts;
      3. a "held since" date that reports the first absence ever, not this one.
    """
    conn, integ, results = build()
    w401 = wid_of(conn, "acme/web#401")
    w423 = wid_of(conn, "acme/web#423")
    w425 = wid_of(conn, "acme/web#425")

    start = days(NOW, -42)
    backdate_item(conn, w401, 60)          # six weeks must pass with nobody
    backdate_item(conn, w423, 60)          # touching these; see backdate_item

    # #401 — the realistic blocker life-cycle, and the one that decides
    # whether a [Blocked on…] answer rots. marco explains it on day 0. The
    # 7-day cooldown then lapses and ARGUS asks again; he ignores it three
    # times. The question the simulation answers is what the digest does
    # with an explanation that silence has overtaken.
    force_answer(conn, w401, "marco", "blocked_on",
                 "waiting on Legal to approve the licence change", start)
    for k in (10, 17, 24):
        force_ignored_ask(conn, w401, "marco", days(start, k), status="sent")

    # #423 — marco is ignoring it outright, from the first morning.
    for k in range(0, 42, 7):
        force_ignored_ask(conn, w423, "marco", days(start, k), status="sent")
    results = SF.run_pipeline(conn)

    # dana goes away three separate times, and #425 is held each time.
    for i, (out_from, out_to) in enumerate([(3, 10), (17, 24), (35, None)]):
        frm = days(start, out_from)
        to = days(start, out_to) if out_to is not None else None
        set_presence(conn, "dana", P.OUT_OF_OFFICE, frm, to)
        conn.execute(
            """INSERT INTO triage_message (integration_id, work_item_id, sent_to_actor_id,
                                            external_channel_id, external_message_ts,
                                            sent_at, status, suppressed_reason)
               VALUES (?,?,?,NULL,NULL,?, 'suppressed_presence', ?)""",
            (integ, w425, actor_id(conn, "dana"), days(frm, 0.5),
             f"presence:{100 + i}: out of office"))
    conn.commit()

    print("\n  --- Six weeks of mornings ---")
    print(f"  {'day':>4}  {'rows':>4}  sections seen")
    rot = []
    for day in range(0, 43, 3):
        at = days(start, day)
        # Exactly what the daily job does, in the same order: 6.6 writes off
        # the DMs nobody answered, then 6.8 reads the world it leaves behind.
        ST.expire_stale_messages(conn, at)
        d = DG.collect(conn, results, at, team_label="acme/web")
        secs = ",".join(f"{n}:{len(rs)}" for n, rs in d.sections()) or "ALL CLEAR"
        blocked = d.section(DG.SECTION_BLOCKED)
        note = ""
        if blocked and blocked[0].is_stale:
            note = "  (blocker flagged stale)"
        print(f"  {day:>4}  {len(d.rows):>4}  {secs}{note}")
        rot.append((day, at, d))

    # --- candidate 1: does a blocker report rot into permanent noise? ----
    seen_blocked = [(day, d) for day, _, d in rot if d.section(DG.SECTION_BLOCKED)]
    late = [d for day, d in seen_blocked if day > 14]
    assert all(d.section(DG.SECTION_BLOCKED)[0].is_stale for d in late), \
        "a five-week-old blocker was still presented as current fact"
    checks += 1
    print("\n  check 27 a blocker older than 14 days is relabelled, not presented as current")

    by_day = {day: d for day, _, d in rot}
    day42 = rot[-1][2]

    # The blocker did NOT rot. It led the digest while it was current, was
    # relabelled at 14 days, and left the section entirely once ARGUS had
    # asked again and been ignored — replaced by a more current fact rather
    # than deleted. That progression, visible in the table above, is the
    # answer to candidate 1.
    assert by_day[9].section(DG.SECTION_BLOCKED), "the blocker was never shown at all"
    assert not by_day[24].section(DG.SECTION_BLOCKED), \
        "a five-week-old blocker was still leading the digest"
    checks += 1
    print("  check 28 a blocker leads, then goes stale, then yields to silence — it does not rot")

    # --- candidate 2: does a give-up ever lift? --------------------------
    un = day42.section(DG.SECTION_UNANSWERED)
    assert sorted(r.item_key for r in un) == ["acme/web#401", "acme/web#423"], \
        [r.item_key for r in un]
    assert DG.unanswered_ask_count(conn, w423, days(start, 42)) == 6
    # The blocker marco once gave is carried into the row, not thrown away.
    row401 = [r for r in un if r.item_key == "acme/web#401"][0]
    assert "Legal" in row401.detail, \
        f"the blocker he did once give was lost when the row moved section: {row401.detail}"
    checks += 1
    print("  check 29 an ignored item keeps the last thing its owner ever told us")

    add_human_event(conn, w423, "marco", days(start, 41))
    after = DG.collect(conn, results, days(start, 42), team_label="acme/web")
    assert [r.item_key for r in after.section(DG.SECTION_UNANSWERED)] == ["acme/web#401"], \
        "six weeks of silence stayed permanent after the developer came back"
    checks += 1
    print("  check 30 six weeks of ignored asks lift the moment a human touches the item")

    # --- candidate 3: does "held since" report the right absence? --------
    held = [r for r in by_day[39].rows if r.item_key == "acme/web#425"]
    assert held, "an item held during a live absence vanished from the digest"
    row = held[0]
    assert row.section == DG.SECTION_HELD, row.section
    assert days(start, 35.5)[:10] in row.detail, \
        f"'held since' reports an older absence, not the current one: {row.detail}"
    assert days(start, 3.5)[:10] not in row.detail, \
        "'held since' reported dana's FIRST holiday, six weeks ago"
    checks += 1
    print("  check 31 on a third absence, 'held since' names THIS absence, not the first")

    # --- 6.7's wording bug, fixed at source in 6.9 ------------------------
    # `presence.escalations_due` now scopes `held_alerts` to the current
    # unbroken absence (was a lifetime total across every separate absence,
    # D-118). No more local recount in digest.py, and no "in total across
    # all absences" caveat needed — the field is just correct.
    esc = day42.section(DG.SECTION_ESCALATION)
    if esc:
        e = esc[0]
        assert "during this absence" in e.detail, e.detail
        assert "1 alert(s) held during this absence" in e.detail, e.detail
        assert "in total across all absences" not in e.detail, \
            "stale lifetime-total caveat still present after the source fix"
        checks += 1
        print("  check 32 held counts say 'this absence' and are correct at the source (6.9 fix)")

    # --- the digest must return to quiet when the work resolves ----------
    conn.execute("UPDATE work_item SET state = 'merged' WHERE id IN (?,?)", (w401, w423))
    conn.execute("UPDATE presence SET effective_to = ? WHERE effective_to IS NULL",
                 (days(start, 42),))
    conn.execute("UPDATE triage_message SET status = 'responded' WHERE status = 'sent'")
    conn.commit()
    quiet_results = [r for r in results
                     if r.work_item_id not in {w401, w423, w425}
                     and r.item_key != "acme/web#422"]
    quiet = DG.collect(conn, quiet_results, days(start, 43), team_label="acme/web")
    assert quiet.all_clear, \
        f"the board never empties: {[(r.section, r.item_key) for r in quiet.rows]}"
    checks += 1
    print("  check 33 when the work resolves the board empties completely — nothing sticks")

    print("\n  --- Week 6, as the tech lead would read it ---\n")
    print(DG.render_text(day42))
    return checks


if __name__ == "__main__":
    conn, integ, results, checks = run()
    checks = simulate(checks)
    print(f"\nAll {checks} fixture-based checks passed.")
