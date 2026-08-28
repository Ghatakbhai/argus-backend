"""Verification for slack_dispatcher.py (D-167, Milestone 1 Task 2), run
against real PostgreSQL exactly the way every other backend test in this
project is (see tests/README convention in test_slack_app.py's docstring).

Reuses the `client`/`clean_database` fixtures from conftest.py so the schema
(including 7.3's slack_workspace_token/slack_identity/triage_message tables)
is built by the real migration path, not hand-assembled.
"""
import json
import os
import sys

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BACKEND))

from backend import config, db, slack_app, slack_crypto, slack_dispatcher  # noqa: E402
from backend.auth import now_iso  # noqa: E402

from conftest import ADMIN_HEADERS  # noqa: E402


class FakeSlack:
    """Records every call instead of making one — same convention
    test_slack_app.py uses (D-115: no route to slack.com from this sandbox)."""

    def __init__(self, lookup_email_to_user=None):
        self.calls = []
        self._lookup = lookup_email_to_user or {}
        self._ts_counter = 1000

    def call(self, method, **args):
        self.calls.append((method, args))
        if method == "users.lookupByEmail":
            uid = self._lookup.get(args.get("email"))
            if uid is None:
                return {"ok": True, "user": {}}
            return {"ok": True, "user": {"id": uid}}
        if method == "conversations.open":
            return {"ok": True, "channel": {"id": f"D{args['users']}"}}
        if method == "chat.postMessage":
            self._ts_counter += 1
            return {"ok": True, "ts": f"1700000000.{self._ts_counter}"}
        return {"ok": True}


_SLUG_COUNTER = [0]


def _make_live_tenant(client, slug_prefix="rocket"):
    """One fresh 'live' tenant with a real (encrypted) Slack workspace token.
    A unique slug per call: `clean_database` is session-scoped, so tenants
    created by earlier tests in this file are still in the database."""
    _SLUG_COUNTER[0] += 1
    slug = f"{slug_prefix}-{_SLUG_COUNTER[0]}"
    r = client.post("/v1/admin/tenants", headers=ADMIN_HEADERS,
                    json={"slug": slug, "display_name": "Rocket Startup"})
    assert r.status_code == 201, r.text
    tid = r.json()["id"]

    # Status flips only go through the admin plane (argus_admin), never
    # tenant_tx's argus_app role — matching app.py's own
    # set_tenant_status(), which is the only place this project changes it.
    r = client.post(f"/v1/admin/tenants/{slug}/status", headers=ADMIN_HEADERS,
                    params={"new_status": "live"})
    assert r.status_code == 200, r.text

    with db.tenant_tx(tid) as conn:
        src = conn.execute("SELECT id FROM source WHERE name='slack'").fetchone()["id"]
        integ = conn.execute(
            "INSERT INTO integration (tenant_id, source_id, external_account_id,"
            " display_name, scope, credential_ref, installed_at)"
            " VALUES (%s,%s,%s,'Rocket Slack','chat:write','slack_workspace_token',%s)"
            " RETURNING id", (tid, src, f"T{slug}", now_iso())).fetchone()["id"]
        ciphertext = slack_crypto.encrypt_token("xoxb-fake-rocket-token", tid)
        conn.execute(
            "INSERT INTO slack_workspace_token"
            "   (tenant_id, integration_id, team_id, team_name, scopes,"
            "    token_ciphertext, installed_at)"
            " VALUES (%s,%s,%s,'Rocket',%s,%s,%s)",
            (tid, integ, f"T{slug}", "chat:write,users:read.email", ciphertext, now_iso()))
    return {"id": tid, "integration_id": integ}


@pytest.fixture
def live_tenant(client):
    return _make_live_tenant(client)


def _seed_fire_alert(tid, integration_id, login="octocat", kind="human"):
    """One FIRE alert with a real subject_actor_id, ready to dispatch."""
    with db.tenant_tx(tid) as conn:
        src = conn.execute("SELECT id FROM source WHERE name='github'").fetchone()["id"]
        proj = conn.execute(
            "INSERT INTO project (tenant_id, source_id, source_key, display_name)"
            " VALUES (%s,%s,'rocket/api','rocket/api') RETURNING id",
            (tid, src)).fetchone()["id"]
        snap = conn.execute(
            "INSERT INTO snapshot (tenant_id, source_id, project_id, observed_at,"
            " started_at, is_complete) VALUES (%s,%s,%s,%s,%s,1) RETURNING id",
            (tid, src, proj, now_iso(), now_iso())).fetchone()["id"]
        actor = conn.execute(
            "INSERT INTO actor (tenant_id, source_id, source_key, kind, kind_reason)"
            " VALUES (%s,%s,%s,%s,'assumed_human') RETURNING id",
            (tid, src, login, kind)).fetchone()["id"]
        item = conn.execute(
            "INSERT INTO work_item (tenant_id, snapshot_id, project_id, source_number,"
            " kind, title, state, author_id, created_at, url)"
            " VALUES (%s,%s,%s,7,'change_request','fix the thing','open',%s,%s,%s)"
            " RETURNING id",
            (tid, snap, proj, actor, now_iso(), "https://github.com/rocket/api/pull/7")
        ).fetchone()["id"]
        run = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at,"
            " items_checked, alerts_fired, alerts_suppressed)"
            " VALUES (%s,'manual','succeeded',%s,1,1,0) RETURNING id",
            (tid, now_iso())).fetchone()["id"]
        alert = conn.execute(
            "INSERT INTO alert (tenant_id, ingest_run_id, work_item_id, pattern,"
            " outcome, reason, subject_actor_id, decided_at)"
            " VALUES (%s,%s,%s,'P2-review-ghosted','FIRE',"
            "         'approved 52h ago, no reviewer activity since',%s,%s) RETURNING id",
            (tid, run, item, actor, now_iso())).fetchone()["id"]
    return {"run_id": run, "alert_id": alert, "work_item_id": item, "actor_id": actor}


# ---------------------------------------------------------------------------
# 1. The Shadow Mode invariant — the one thing this module must never get wrong.
# ---------------------------------------------------------------------------

def test_refuses_a_non_live_tenant(client):
    _SLUG_COUNTER[0] += 1
    r = client.post("/v1/admin/tenants", headers=ADMIN_HEADERS,
                    json={"slug": f"shadowco-{_SLUG_COUNTER[0]}", "display_name": "Shadow Co"})
    tid = r.json()["id"]  # default status is 'shadow' — never flipped in this test
    with db.tenant_tx(tid) as conn:
        with pytest.raises(slack_dispatcher.TenantNotLive):
            slack_dispatcher.dispatch_tenant_triage_dms(
                conn, tid, ingest_run_id=0, now=now_iso(), transport=FakeSlack())


def test_refuses_when_no_slack_integration(client):
    _SLUG_COUNTER[0] += 1
    slug = f"nowire-{_SLUG_COUNTER[0]}"
    r = client.post("/v1/admin/tenants", headers=ADMIN_HEADERS,
                    json={"slug": slug, "display_name": "No Wire"})
    tid = r.json()["id"]
    r2 = client.post(f"/v1/admin/tenants/{slug}/status", headers=ADMIN_HEADERS,
                     params={"new_status": "live"})
    assert r2.status_code == 200, r2.text
    with db.tenant_tx(tid) as conn:
        with pytest.raises(slack_dispatcher.TenantNotLive):
            slack_dispatcher.dispatch_tenant_triage_dms(
                conn, tid, ingest_run_id=0, now=now_iso())


# ---------------------------------------------------------------------------
# 2. The happy path: FIRE alert -> resolved identity -> a real DM -> logged.
# ---------------------------------------------------------------------------

def test_dispatches_a_fire_alert_end_to_end(client, live_tenant):
    tid, integration_id = live_tenant["id"], live_tenant["integration_id"]
    seeded = _seed_fire_alert(tid, integration_id)
    fake = FakeSlack(lookup_email_to_user={"octocat@example.com": "U999"})

    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(),
            transport=fake, email_for_login=lambda login: "octocat@example.com")

    assert summary.sent == 1 and summary.failed == 0 and summary.skipped == 0
    result = summary.results[0]
    assert result.outcome == slack_dispatcher.SENT
    assert result.slack_user_id == "U999"
    assert result.triage_message_id is not None

    methods = [c[0] for c in fake.calls]
    assert methods == ["users.lookupByEmail", "conversations.open", "chat.postMessage"]
    # The Block Kit body carries the real evidence string and the three
    # buttons `slack_app.handle_interaction` already knows how to answer.
    posted_blocks = fake.calls[2][1]["blocks"]
    button_action_ids = {el["action_id"] for b in posted_blocks if b["type"] == "actions"
                         for el in b["elements"]}
    assert button_action_ids == {slack_app.ACTION_HANDLED_OFFLINE,
                                 slack_app.ACTION_BLOCKED_ON, slack_app.ACTION_SNOOZE_7D}
    assert any("approved 52h ago" in json.dumps(b) for b in posted_blocks)

    with db.tenant_tx(tid) as conn:
        row = conn.execute(
            "SELECT status, external_channel_id, external_message_ts, sent_to_actor_id"
            " FROM triage_message WHERE id = %s", (result.triage_message_id,)).fetchone()
        assert row["status"] == "sent"
        assert row["external_channel_id"] == "DU999"
        assert row["sent_to_actor_id"] == seeded["actor_id"]

        cached = conn.execute(
            "SELECT slack_user_id, resolved_via FROM slack_identity"
            " WHERE integration_id = %s AND actor_id = %s",
            (integration_id, seeded["actor_id"])).fetchone()
        assert cached["slack_user_id"] == "U999"
        assert cached["resolved_via"] == "email_lookup"


def test_a_second_dispatch_of_the_same_alert_is_skipped_not_resent(client, live_tenant):
    tid = live_tenant["id"]
    seeded = _seed_fire_alert(tid, live_tenant["integration_id"])
    fake = FakeSlack(lookup_email_to_user={"octocat@example.com": "U999"})

    with db.tenant_tx(tid) as conn:
        slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=lambda login: "octocat@example.com")

    calls_after_first = len(fake.calls)

    with db.tenant_tx(tid) as conn:
        summary2 = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=lambda login: "octocat@example.com")

    assert summary2.sent == 0 and summary2.skipped == 1
    assert summary2.results[0].reason == "already_dispatched"
    assert len(fake.calls) == calls_after_first  # no new Slack traffic at all


def test_cached_identity_is_reused_without_a_second_lookup(client, live_tenant):
    """Two different FIRE alerts naming the same developer should hit
    users.lookupByEmail once, not twice."""
    tid, integration_id = live_tenant["id"], live_tenant["integration_id"]
    seeded1 = _seed_fire_alert(tid, integration_id, login="octocat")
    with db.tenant_tx(tid) as conn:
        src = conn.execute("SELECT id FROM source WHERE name='github'").fetchone()["id"]
        proj = conn.execute("SELECT id FROM project WHERE tenant_id=%s LIMIT 1",
                            (tid,)).fetchone()["id"]
        snap = conn.execute("SELECT id FROM snapshot WHERE tenant_id=%s LIMIT 1",
                            (tid,)).fetchone()["id"]
        item2 = conn.execute(
            "INSERT INTO work_item (tenant_id, snapshot_id, project_id, source_number,"
            " kind, title, state, author_id, created_at, url)"
            " VALUES (%s,%s,%s,8,'change_request','fix another thing','open',%s,%s,%s)"
            " RETURNING id",
            (tid, snap, proj, seeded1["actor_id"], now_iso(),
             "https://github.com/rocket/api/pull/8")).fetchone()["id"]
        alert2 = conn.execute(
            "INSERT INTO alert (tenant_id, ingest_run_id, work_item_id, pattern,"
            " outcome, reason, subject_actor_id, decided_at)"
            " VALUES (%s,%s,%s,'P2-review-ghosted','FIRE','still ghosted',%s,%s)"
            " RETURNING id",
            (tid, seeded1["run_id"], item2, seeded1["actor_id"], now_iso())).fetchone()["id"]

    fake = FakeSlack(lookup_email_to_user={"octocat@example.com": "U999"})
    with db.tenant_tx(tid) as conn:
        slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=0, now=now_iso(), alert_ids=[seeded1["alert_id"]],
            transport=fake, email_for_login=lambda login: "octocat@example.com")
    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=0, now=now_iso(), alert_ids=[alert2],
            transport=fake, email_for_login=lambda login: "octocat@example.com")

    assert summary.sent == 1
    lookup_calls = [c for c in fake.calls if c[0] == "users.lookupByEmail"]
    assert len(lookup_calls) == 1  # cached the second time


# ---------------------------------------------------------------------------
# 3. Failure and skip paths — every one an explicit, recorded outcome.
# ---------------------------------------------------------------------------

def test_unresolvable_identity_is_suppressed_and_recorded_not_a_silent_failure(
        client, live_tenant):
    """Pre-Milestone 2 slice (D-171): an unresolved identity used to be a
    FAILED outcome with NO triage_message row at all — indistinguishable
    from a real operational error, and invisible to anyone auditing later
    why a FIRE alert never reached a person. It is now recorded as its own
    explicit, non-error status."""
    tid = live_tenant["id"]
    seeded = _seed_fire_alert(tid, live_tenant["integration_id"])
    fake = FakeSlack(lookup_email_to_user={})  # email known, but Slack has nobody

    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=lambda login: "octocat@example.com")

    assert summary.skipped == 1
    assert summary.failed == 0
    assert summary.results[0].reason == "recipient_unresolved"
    assert summary.results[0].triage_message_id is not None
    with db.tenant_tx(tid) as conn:
        row = conn.execute(
            "SELECT status, suppressed_reason, external_channel_id, external_message_ts"
            " FROM triage_message").fetchone()
        assert row["status"] == "suppressed_unresolved_identity"
        assert row["suppressed_reason"]
        assert row["external_channel_id"] is None
        assert row["external_message_ts"] is None


def test_bot_actor_is_skipped(client, live_tenant):
    tid = live_tenant["id"]
    seeded = _seed_fire_alert(tid, live_tenant["integration_id"], login="dependabot[bot]",
                              kind="bot")
    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=FakeSlack())
    assert summary.skipped == 1
    assert summary.results[0].reason == "subject_not_human"


def test_no_transport_is_a_failed_outcome(client, live_tenant):
    """A live tenant whose token can't be found (e.g. revoked) must not raise
    — the caller (a nightly poller) needs to keep going for other tenants."""
    tid = live_tenant["id"]
    with db.tenant_tx(tid) as conn:
        conn.execute("UPDATE slack_workspace_token SET revoked_at = %s"
                    " WHERE tenant_id = %s", (now_iso(), tid))
    seeded = _seed_fire_alert(tid, live_tenant["integration_id"])
    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso())  # transport=None
    assert summary.failed == 1
    assert summary.results[0].reason == "no_slack_transport"


# ---------------------------------------------------------------------------
# 5. Pre-Milestone 2 slice (D-171): the 3-tier `email_for_login` resolver.
# ---------------------------------------------------------------------------

def test_email_resolver_tier1_explicit_map_wins_over_domain_guess(client, live_tenant):
    tid = live_tenant["id"]
    with db.admin_tx() as conn:
        conn.execute("UPDATE tenant SET email_domain = 'rocket.example' WHERE id = %s", (tid,))
    with db.tenant_tx(tid) as conn:
        conn.execute(
            "INSERT INTO tenant_identity_map (tenant_id, github_login, email)"
            " VALUES (%s,'octocat','octo.the.cat@realmail.example')", (tid,))
        resolver = slack_dispatcher.build_email_resolver(conn, tid)
        assert resolver("octocat") == "octo.the.cat@realmail.example"
        # A login with no explicit row still falls through to tier 2.
        assert resolver("hubot") == "hubot@rocket.example"


def test_email_resolver_tier2_domain_guess_when_no_explicit_map(client, live_tenant):
    tid = live_tenant["id"]
    with db.admin_tx() as conn:
        conn.execute("UPDATE tenant SET email_domain = 'rocket.example' WHERE id = %s", (tid,))
    with db.tenant_tx(tid) as conn:
        resolver = slack_dispatcher.build_email_resolver(conn, tid)
    assert resolver("octocat") == "octocat@rocket.example"


def test_email_resolver_tier3_none_when_neither_configured(client, live_tenant):
    tid = live_tenant["id"]
    with db.tenant_tx(tid) as conn:
        resolver = slack_dispatcher.build_email_resolver(conn, tid)
    assert resolver("octocat") is None


def test_email_resolver_is_wired_into_a_real_dispatch(client, live_tenant):
    """End-to-end: the resolver this module builds is what
    `dispatch_tenant_triage_dms` actually uses when the caller passes it —
    the exact way `ingest_worker.run_one()` now calls it."""
    tid, integration_id = live_tenant["id"], live_tenant["integration_id"]
    with db.admin_tx() as conn:
        conn.execute("UPDATE tenant SET email_domain = 'rocket.example' WHERE id = %s", (tid,))
    seeded = _seed_fire_alert(tid, integration_id)
    fake = FakeSlack(lookup_email_to_user={"octocat@rocket.example": "U777"})

    with db.tenant_tx(tid) as conn:
        resolver = slack_dispatcher.build_email_resolver(conn, tid)
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=resolver)

    assert summary.sent == 1
    assert summary.results[0].slack_user_id == "U777"


# ---------------------------------------------------------------------------
# 6. Milestone 2, Task 5.2: cached copilot enrichment renders in the DM.
# ---------------------------------------------------------------------------

def test_copilot_enrichment_cached_in_digest_delivery_renders_in_the_dm(client, live_tenant):
    """`dispatch_tenant_triage_dms` reads the SAME `copilot` dict already
    computed and cached by `dashboard_payload.build_dashboard_payload` at
    ingest time — proven here without a real LLM call, exactly the way this
    project proves every other Slack-facing behavior (a fake transport, a
    hand-built payload row standing in for what `migrate_sqlite.
    record_phase6_run` would have written)."""
    tid, integration_id = live_tenant["id"], live_tenant["integration_id"]
    seeded = _seed_fire_alert(tid, integration_id)
    copilot = {"summary_tldr": "Blocked on a Stripe webhook review; nothing else pending.",
              "blocking_dependency": "Stripe webhook approval",
              "action_draft": "Hey — can you take a quick look, or should I reassign?",
              "suggested_recipient_role": "reviewer"}
    with db.tenant_tx(tid) as conn:
        payload = {"digest": {"rows": [
            {"work_item_id": seeded["work_item_id"], "copilot": copilot},
        ]}}
        conn.execute(
            "INSERT INTO digest_delivery (tenant_id, ingest_run_id, channel, status,"
            " rendered_text, payload_json, delivered_at)"
            " VALUES (%s,%s,'dashboard','shadow','<html></html>',%s,%s)",
            (tid, seeded["run_id"], json.dumps(payload), now_iso()))

    fake = FakeSlack(lookup_email_to_user={"octocat@example.com": "U999"})
    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=lambda login: "octocat@example.com")

    assert summary.sent == 1
    posted_blocks = fake.calls[2][1]["blocks"]
    assert any(copilot["summary_tldr"] in json.dumps(b) for b in posted_blocks)
    button_values = [json.loads(el["value"]) for b in posted_blocks if b["type"] == "actions"
                     for el in b["elements"]]
    assert all(v["action_draft"] == copilot["action_draft"] for v in button_values)


def test_no_cached_copilot_renders_exactly_as_before(client, live_tenant):
    """No digest_delivery row at all (or one with no copilot data) must
    render identically to how this module behaved before Milestone 2 —
    the Fail-Safe Fallback Invariant, proven at the dispatcher layer too."""
    tid, integration_id = live_tenant["id"], live_tenant["integration_id"]
    seeded = _seed_fire_alert(tid, integration_id)
    fake = FakeSlack(lookup_email_to_user={"octocat@example.com": "U999"})
    with db.tenant_tx(tid) as conn:
        summary = slack_dispatcher.dispatch_tenant_triage_dms(
            conn, tid, ingest_run_id=seeded["run_id"], now=now_iso(), transport=fake,
            email_for_login=lambda login: "octocat@example.com")
    assert summary.sent == 1
    posted_blocks = fake.calls[2][1]["blocks"]
    # Same section count as the no-copilot path always had: title, ask,
    # evidence context, actions — no extra TL;DR section inserted.
    assert len([b for b in posted_blocks if b["type"] == "section"]) == 2

