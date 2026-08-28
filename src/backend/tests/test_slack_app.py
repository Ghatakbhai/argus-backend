"""ARGUS Phase 7.3 — the Slack multi-workspace install, tested against real
PostgreSQL and real HTTP.

The claims these checks are here to make true, in the order they matter:

  1. A request that is not signed by Slack, or is signed but old, does not get
     in. (Socket Mode made this question moot in Phase 6; a public Request URL
     makes it the whole ballgame.)
  2. A workspace is bound to exactly one tenant, chosen by an admin-minted
     token, never by anything the workspace itself says.
  3. A bot token is not readable from the database alone.
  4. One developer's single click is recorded exactly once, no matter how many
     times Slack redelivers it.
  5. None of the above leaks across tenants.
"""
import itertools
import json
import os
import re
import time
import urllib.parse

import pytest

from backend import config, db, slack_app, slack_crypto
from backend.auth import now_iso

from conftest import ADMIN_HEADERS

SIGNING = "test-slack-signing-secret"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def signed_post(client, path: str, body: bytes, *, content_type: str,
                timestamp: str | None = None, signature: str | None = None):
    """POST exactly these bytes, signed the way Slack signs them."""
    ts = timestamp if timestamp is not None else str(int(time.time()))
    sig = signature if signature is not None else slack_app.sign_request(SIGNING, body, ts)
    return client.post(path, content=body, headers={
        "content-type": content_type,
        "x-slack-request-timestamp": ts,
        "x-slack-signature": sig,
    })


def post_event(client, envelope: dict, **kw):
    return signed_post(client, "/v1/slack/events",
                       json.dumps(envelope).encode(),
                       content_type="application/json", **kw)


def post_interaction(client, payload: dict, **kw):
    body = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode()
    return signed_post(client, "/v1/slack/interactions", body,
                       content_type="application/x-www-form-urlencoded", **kw)


class FakeSlack:
    """Records every call instead of making it. The sandbox has no route to
    slack.com (D-115) and never has had; every call site takes an injectable
    transport for exactly this reason."""

    def __init__(self):
        self.calls = []
        self.fail_with = None

    def __call__(self, method, **args):
        self.calls.append((method, args))
        if self.fail_with:
            raise slack_app.SlackError(method, self.fail_with)
        return {"ok": True}


# ---------------------------------------------------------------------------
# 1. Request signing — the thing that replaces Socket Mode's implicit trust
# ---------------------------------------------------------------------------

def test_url_verification_handshake_is_answered(client):
    """Slack's one-time ownership check when the Request URL is first saved.
    It is signed like everything else, so this also proves the happy path."""
    r = post_event(client, {"type": "url_verification", "challenge": "abc123xyz"})
    assert r.status_code == 200
    assert r.json()["challenge"] == "abc123xyz"


def test_unsigned_request_is_refused(client):
    r = client.post("/v1/slack/events", json={"type": "url_verification", "challenge": "x"})
    assert r.status_code == 401


def test_wrong_signature_is_refused(client):
    r = post_event(client, {"type": "url_verification", "challenge": "x"},
                   signature="v0=" + "0" * 64)
    assert r.status_code == 401
    assert "bad_signature" in r.json()["detail"]


def test_stale_timestamp_is_refused_even_with_a_valid_signature(client):
    """The replay guard. Without the timestamp window a captured request
    stays valid forever, and its signature is genuinely correct — so this is
    the one refusal that cannot come from the HMAC check."""
    old = str(int(time.time()) - 3600)
    r = post_event(client, {"type": "url_verification", "challenge": "x"}, timestamp=old)
    assert r.status_code == 401
    assert "stale_timestamp" in r.json()["detail"]


def test_signature_covers_the_raw_body_not_the_reparsed_json(client):
    """Sign one byte-sequence, send another that parses to the same object.

    This is the mistake the GitHub webhook was written to avoid at 7.2 and it
    is just as easy to make here: re-serialising parsed JSON changes
    whitespace and key order, and the signature is over bytes.
    """
    signed_bytes = b'{"type":"url_verification","challenge":"x"}'
    other_bytes = b'{ "challenge" : "x" , "type" : "url_verification" }'
    ts = str(int(time.time()))
    sig = slack_app.sign_request(SIGNING, signed_bytes, ts)
    r = client.post("/v1/slack/events", content=other_bytes, headers={
        "content-type": "application/json",
        "x-slack-request-timestamp": ts, "x-slack-signature": sig})
    assert r.status_code == 401


def test_missing_signature_headers_are_named_distinctly(client):
    r = client.post("/v1/slack/events", content=b"{}",
                    headers={"content-type": "application/json",
                             "x-slack-request-timestamp": str(int(time.time()))})
    assert r.status_code == 401
    assert "missing_signature_headers" in r.json()["detail"]


def test_verify_signature_returns_a_reason_for_every_refusal():
    """The endpoint records WHY it refused, so 'someone is replaying requests'
    and 'someone has the wrong secret' are not the same audit line."""
    body, ts = b"{}", str(int(time.time()))
    good = slack_app.sign_request(SIGNING, body, ts)
    assert slack_app.verify_signature(SIGNING, body, ts, good) == (True, "ok")
    assert slack_app.verify_signature("", body, ts, good)[1] == "no_signing_secret_configured"
    assert slack_app.verify_signature(SIGNING, body, ts, None)[1] == "missing_signature_headers"
    assert slack_app.verify_signature(SIGNING, body, "not-a-number", good)[1] == \
        "unparseable_timestamp"
    assert slack_app.verify_signature(SIGNING, body, "1", good)[1] == "stale_timestamp"
    assert slack_app.verify_signature(SIGNING, body, ts, "v0=deadbeef")[1] == "bad_signature"


# ---------------------------------------------------------------------------
# 2. Token encryption at rest
# ---------------------------------------------------------------------------

def test_token_encryption_round_trips():
    sealed = slack_crypto.encrypt_token("xoxb-secret", "11111111-1111-1111-1111-111111111111")
    assert "xoxb-secret" not in sealed
    assert slack_crypto.decrypt_token(sealed, "11111111-1111-1111-1111-111111111111") \
        == "xoxb-secret"


def test_a_ciphertext_cannot_be_moved_between_tenants():
    """The tenant id is bound in as AES-GCM associated data, so a row copied
    from one tenant to another fails to authenticate rather than decrypting.
    Belt to RLS's braces."""
    sealed = slack_crypto.encrypt_token("xoxb-secret", "11111111-1111-1111-1111-111111111111")
    with pytest.raises(slack_crypto.SlackTokenUndecryptable):
        slack_crypto.decrypt_token(sealed, "22222222-2222-2222-2222-222222222222")


def test_tampered_ciphertext_is_rejected_not_silently_wrong():
    tid = "11111111-1111-1111-1111-111111111111"
    sealed = slack_crypto.encrypt_token("xoxb-secret", tid)
    broken = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
    with pytest.raises(slack_crypto.SlackTokenUndecryptable):
        slack_crypto.decrypt_token(broken, tid)
    with pytest.raises(slack_crypto.SlackTokenUndecryptable):
        slack_crypto.decrypt_token("not-even-versioned", tid)


def test_two_encryptions_of_the_same_token_differ():
    """Fresh nonce per call — which is what makes it safe to re-encrypt the
    same token on every reinstall."""
    tid = "11111111-1111-1111-1111-111111111111"
    assert slack_crypto.encrypt_token("xoxb-x", tid) != slack_crypto.encrypt_token("xoxb-x", tid)


# ---------------------------------------------------------------------------
# 3. The install flow
# ---------------------------------------------------------------------------

def test_admin_mints_a_slack_install_link(client, tenants):
    r = client.post("/v1/admin/tenants/acme/slack/install-link", headers=ADMIN_HEADERS)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["token"].startswith("argus_slackclaim_")
    # Points at ARGUS, not at slack.com: the scope list has to be resolved
    # server-side so a link handed out today does not go stale when it changes.
    assert body["install_url"].startswith(config.PUBLIC_BASE_URL + "/v1/slack/install?state=")


def test_install_link_for_an_unknown_tenant_is_404(client, tenants):
    r = client.post("/v1/admin/tenants/nosuchteam/slack/install-link", headers=ADMIN_HEADERS)
    assert r.status_code == 404


def test_install_link_requires_the_admin_secret(client, tenants):
    assert client.post("/v1/admin/tenants/acme/slack/install-link").status_code == 401
    assert client.post("/v1/admin/tenants/acme/slack/install-link",
                       headers={"x-admin-key": "wrong"}).status_code == 401


def test_install_redirects_to_slack_with_the_right_scopes(client, tenants):
    token = client.post("/v1/admin/tenants/acme/slack/install-link",
                        headers=ADMIN_HEADERS).json()["token"]
    r = client.get(f"/v1/slack/install?state={token}", follow_redirects=False)
    assert r.status_code == 302
    q = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["location"]).query)
    assert q["client_id"] == [config.SLACK_CLIENT_ID]
    assert q["state"] == [token]
    assert q["redirect_uri"] == [config.PUBLIC_BASE_URL + "/v1/slack/oauth/callback"]
    # 6.7's presence scope is requested up front (D-145): Slack cannot add a
    # scope to an existing install, so leaving it out means asking fifteen
    # pilot teams to reinstall later.
    assert "users.profile:read" in q["scope"][0]
    assert set(q["scope"][0].split(",")) == set(config.SLACK_BOT_SCOPES.split(","))


def test_a_stale_link_never_reaches_slack(client, tenants):
    """The whole reason /v1/slack/install exists rather than handing out a raw
    slack.com URL: a bad link fails here, before anyone authorises anything
    inside their real workspace."""
    r = client.get("/v1/slack/install?state=argus_slackclaim_nonsense",
                   follow_redirects=False)
    assert r.status_code == 400
    assert "expired" in r.text.lower()
    assert "slack.com/oauth" not in r.text


def test_a_github_install_token_is_not_a_slack_install_token(client, tenants):
    """Provider confusion, closed by install_claim.provider (D-142). Without
    it the two flows mint interchangeable tokens."""
    gh = client.post("/v1/admin/tenants/acme/github/install-link",
                     headers=ADMIN_HEADERS).json()["token"]
    r = client.get(f"/v1/slack/install?state={gh}", follow_redirects=False)
    assert r.status_code == 400


def test_a_slack_install_token_is_not_a_github_install_token(client, tenants):
    sl = client.post("/v1/admin/tenants/acme/slack/install-link",
                     headers=ADMIN_HEADERS).json()["token"]
    r = client.get(f"/v1/github/setup?installation_id=99887766&state={sl}")
    assert r.status_code == 400
    assert "invalid or has expired" in r.text


def _install_workspace(client, monkeypatch, slug, team_id, team_name, token):
    claim = client.post(f"/v1/admin/tenants/{slug}/slack/install-link",
                        headers=ADMIN_HEADERS).json()["token"]
    monkeypatch.setattr(slack_app, "exchange_oauth_code",
                        lambda code, client=None: slack_app.SlackInstall(
                            access_token=token, team_id=team_id, team_name=team_name,
                            bot_user_id=f"U_BOT_{team_id}", app_id="A0ARGUS",
                            installer_user_id="U_INSTALLER",
                            scopes=config.SLACK_BOT_SCOPES))
    return claim, client.get(f"/v1/slack/oauth/callback?code=ok&state={claim}")


@pytest.fixture(scope="module")
def slack_installed(client, tenants):
    """Install a workspace for each tenant, the way a pilot team would.

    Module-scoped and deliberately shared: the point of these tests is that
    two live installs coexist without seeing each other, which cannot be
    shown by two independent single-tenant fixtures.
    """
    import unittest.mock as mock
    out = {}
    for slug, team_id, name, tok in (
            ("acme", "T_ACME", "Acme Rockets HQ", "xoxb-acme-token"),
            ("globex", "T_GLOBEX", "Globex HQ", "xoxb-globex-token")):
        claim = client.post(f"/v1/admin/tenants/{slug}/slack/install-link",
                            headers=ADMIN_HEADERS).json()["token"]
        with mock.patch.object(slack_app, "exchange_oauth_code",
                               lambda code, client=None, _t=tok, _id=team_id, _n=name:
                               slack_app.SlackInstall(
                                   access_token=_t, team_id=_id, team_name=_n,
                                   bot_user_id=f"U_BOT_{_id}", app_id="A0ARGUS",
                                   installer_user_id="U_INSTALLER",
                                   scopes=config.SLACK_BOT_SCOPES)):
            r = client.get(f"/v1/slack/oauth/callback?code=code-{slug}&state={claim}")
        assert r.status_code == 200, r.text
        with db.tenant_tx(tenants[slug]["id"]) as conn:
            row = conn.execute(
                "SELECT w.*, i.id AS integ FROM slack_workspace_token w"
                " JOIN integration i ON i.id = w.integration_id AND i.tenant_id = w.tenant_id"
                " WHERE w.team_id = %s", (team_id,)).fetchone()
        out[slug] = {"team_id": team_id, "token": tok, "row": row,
                     "integration_id": row["integ"], "tenant_id": tenants[slug]["id"]}
    return out


def test_oauth_callback_connects_the_workspace(client, tenants, slack_installed):
    acme = slack_installed["acme"]
    assert acme["row"]["team_name"] == "Acme Rockets HQ"
    assert acme["row"]["bot_user_id"] == "U_BOT_T_ACME"
    assert acme["row"]["revoked_at"] is None
    assert acme["row"]["scopes"] == config.SLACK_BOT_SCOPES


def test_the_stored_token_is_ciphertext_and_decrypts_to_the_real_one(
        client, tenants, slack_installed):
    """The claim D-143 actually makes: a database dump is not a set of live
    Slack credentials."""
    acme = slack_installed["acme"]
    stored = acme["row"]["token_ciphertext"]
    assert "xoxb-acme-token" not in stored
    assert stored.startswith("v1:")
    assert slack_crypto.decrypt_token(stored, acme["tenant_id"]) == "xoxb-acme-token"


def test_the_integration_row_points_at_the_token_not_at_a_secret(
        client, tenants, slack_installed):
    """D-087's rule, kept: `integration.credential_ref` stays a pointer."""
    with db.tenant_tx(tenants["acme"]["id"]) as conn:
        row = conn.execute("SELECT credential_ref, external_account_id, revoked_at"
                           " FROM integration WHERE id=%s",
                           (slack_installed["acme"]["integration_id"],)).fetchone()
    assert row["credential_ref"] == "slack_workspace_token"
    assert row["external_account_id"] == "T_ACME"
    assert row["revoked_at"] is None


def test_an_install_claim_is_single_use(client, tenants, monkeypatch):
    claim, first = _install_workspace(client, monkeypatch, "acme", "T_ONCE", "Once", "xoxb-1")
    assert first.status_code == 200
    second = client.get(f"/v1/slack/oauth/callback?code=again&state={claim}")
    assert second.status_code == 400
    assert "single-use" in second.text


def test_a_workspace_cannot_be_connected_to_two_tenants(client, tenants, monkeypatch):
    """D-144. Without the partial unique index and this check, one team_id
    resolves to two tenants and every button click in that workspace is routed
    by coin flip."""
    _, ok = _install_workspace(client, monkeypatch, "acme", "T_CONTESTED", "Contested",
                               "xoxb-a")
    assert ok.status_code == 200
    _, clash = _install_workspace(client, monkeypatch, "globex", "T_CONTESTED", "Contested",
                                  "xoxb-b")
    assert clash.status_code == 409
    assert "already connected" in clash.text
    # And it does not name the other pilot team.
    assert "acme" not in clash.text.lower()


def test_reinstalling_refreshes_the_token_without_duplicating_the_row(
        client, tenants, monkeypatch):
    _install_workspace(client, monkeypatch, "acme", "T_REDO", "Redo", "xoxb-old")
    _install_workspace(client, monkeypatch, "acme", "T_REDO", "Redo Renamed", "xoxb-new")
    with db.tenant_tx(tenants["acme"]["id"]) as conn:
        rows = conn.execute("SELECT * FROM slack_workspace_token WHERE team_id='T_REDO'"
                            ).fetchall()
    assert len(rows) == 1
    assert rows[0]["team_name"] == "Redo Renamed"
    assert rows[0]["rotated_at"] is not None
    assert slack_crypto.decrypt_token(rows[0]["token_ciphertext"],
                                      tenants["acme"]["id"]) == "xoxb-new"


def test_a_cancelled_install_writes_nothing(client, tenants):
    before = _count_tokens(tenants["acme"]["id"])
    r = client.get("/v1/slack/oauth/callback?error=access_denied")
    assert r.status_code == 400
    assert "cancelled" in r.text.lower()
    assert _count_tokens(tenants["acme"]["id"]) == before


def test_slack_refusing_the_exchange_writes_nothing(client, tenants, monkeypatch):
    claim = client.post("/v1/admin/tenants/acme/slack/install-link",
                        headers=ADMIN_HEADERS).json()["token"]
    before = _count_tokens(tenants["acme"]["id"])

    def boom(code, client=None):
        raise slack_app.SlackError("oauth.v2.access", "invalid_code")
    monkeypatch.setattr(slack_app, "exchange_oauth_code", boom)
    r = client.get(f"/v1/slack/oauth/callback?code=bad&state={claim}")
    assert r.status_code == 400
    assert "invalid_code" in r.text
    assert _count_tokens(tenants["acme"]["id"]) == before
    # The claim was NOT spent by a failed exchange — the pilot contact can
    # click the same link again once whatever Slack objected to is fixed.
    r2 = client.get(f"/v1/slack/install?state={claim}", follow_redirects=False)
    assert r2.status_code == 302


def _count_tokens(tenant_id: str) -> int:
    with db.tenant_tx(tenant_id) as conn:
        return conn.execute("SELECT count(*) AS n FROM slack_workspace_token").fetchone()["n"]


# ---------------------------------------------------------------------------
# 4. Events: routing, dedup, uninstall
# ---------------------------------------------------------------------------

def test_an_event_from_an_unknown_workspace_is_refused_not_guessed_at(client, slack_installed):
    r = post_event(client, {"type": "event_callback", "team_id": "T_NOBODY",
                            "event_id": "Ev_unknown_1", "event": {"type": "app_uninstalled"}})
    assert r.status_code == 200
    assert r.json()["status"] == "unresolved"


def test_a_redelivered_event_is_processed_once(client, tenants, slack_installed):
    envelope = {"type": "event_callback", "team_id": "T_ACME", "event_id": "Ev_dup_1",
                "event": {"type": "app_home_opened"}}
    assert post_event(client, envelope).json()["status"] == "ok"
    # Slack's retry: same event_id, and it means the same single thing.
    assert post_event(client, envelope).json()["status"] == "duplicate"
    with db.tenant_tx(tenants["acme"]["id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM slack_event WHERE dedup_key=%s",
                         ("event:Ev_dup_1",)).fetchone()["n"]
    assert n == 1


def test_uninstalling_revokes_the_workspace_on_both_tables(client, tenants, monkeypatch):
    """Missing either half leaves a half-uninstalled workspace: still routable
    but with no token, or tokenless but still blocking the team_id."""
    _install_workspace(client, monkeypatch, "globex", "T_LEAVING", "Leaving", "xoxb-bye")
    r = post_event(client, {"type": "event_callback", "team_id": "T_LEAVING",
                            "event_id": "Ev_bye_1", "event": {"type": "app_uninstalled"}})
    assert r.json()["action"] == "workspace_revoked"
    with db.tenant_tx(tenants["globex"]["id"]) as conn:
        w = conn.execute("SELECT * FROM slack_workspace_token WHERE team_id='T_LEAVING'"
                         ).fetchone()
        i = conn.execute("SELECT revoked_at FROM integration WHERE id=%s",
                         (w["integration_id"],)).fetchone()
    assert w["revoked_at"] is not None and w["revoked_reason"] == "app_uninstalled"
    assert i["revoked_at"] is not None


def test_a_revoked_workspace_can_be_claimed_by_another_tenant_later(
        client, tenants, monkeypatch):
    """The partial unique index covers live installs only, on purpose: a pilot
    leaving one tenant and joining another is a legitimate thing to do."""
    _install_workspace(client, monkeypatch, "acme", "T_MOVER", "Mover", "xoxb-m1")
    post_event(client, {"type": "event_callback", "team_id": "T_MOVER",
                        "event_id": "Ev_move_1", "event": {"type": "app_uninstalled"}})
    _, again = _install_workspace(client, monkeypatch, "globex", "T_MOVER", "Mover",
                                  "xoxb-m2")
    assert again.status_code == 200


def test_tokens_revoked_is_treated_as_an_uninstall(client, tenants, monkeypatch):
    _install_workspace(client, monkeypatch, "acme", "T_REVOKED", "Revoked", "xoxb-r")
    r = post_event(client, {"type": "event_callback", "team_id": "T_REVOKED",
                            "event_id": "Ev_rev_1",
                            "event": {"type": "tokens_revoked",
                                      "tokens": {"bot": ["U_BOT_T_REVOKED"]}}})
    assert r.json()["action"] == "workspace_revoked"


def test_a_suspended_tenant_stops_receiving_events(client, tenants, monkeypatch):
    _install_workspace(client, monkeypatch, "globex", "T_SUSPEND", "Susp", "xoxb-s")
    client.post("/v1/admin/tenants/globex/status?new_status=suspended", headers=ADMIN_HEADERS)
    try:
        r = post_event(client, {"type": "event_callback", "team_id": "T_SUSPEND",
                                "event_id": "Ev_susp_1", "event": {"type": "app_uninstalled"}})
        assert r.json()["status"] == "ignored"
    finally:
        client.post("/v1/admin/tenants/globex/status?new_status=shadow",
                    headers=ADMIN_HEADERS)


# ---------------------------------------------------------------------------
# 5. Interactivity — the actual product surface
# ---------------------------------------------------------------------------

_TS = itertools.count(1)


@pytest.fixture
def dm(client, tenants, slack_installed):
    """A triage DM ARGUS has 'sent', one per test, in the named tenant.

    Each gets its own message ts, because (channel, ts) is the key the whole
    interaction path routes on — sharing one across tests would make a
    dedup bug look like a passing test.
    """
    def _make(slug="acme", channel="D_ACME", ts=None):
        ts = ts or f"17560000{next(_TS):04d}.000100"
        info = slack_installed[slug]
        with db.tenant_tx(info["tenant_id"]) as conn:
            row = conn.execute(
                "INSERT INTO triage_message (tenant_id, integration_id, work_item_id,"
                " sent_to_actor_id, external_channel_id, external_message_ts, sent_at, status)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,'sent') RETURNING id",
                (info["tenant_id"], info["integration_id"], tenants[slug]["work_item_id"],
                 tenants[slug]["actor_id"], channel, ts, now_iso())).fetchone()
        return {"id": row["id"], "channel": channel, "ts": ts, **info}
    return _make


def click(dm_row, action_id, *, team_id=None):
    return {
        "type": "block_actions",
        "team": {"id": team_id or dm_row["team_id"]},
        "user": {"id": "U_DEV"},
        "trigger_id": "trigger.123",
        "container": {"channel_id": dm_row["channel"], "message_ts": dm_row["ts"]},
        "channel": {"id": dm_row["channel"]},
        "message": {"ts": dm_row["ts"]},
        "actions": [{"action_id": action_id, "type": "button"}],
    }


@pytest.fixture
def fake_slack(monkeypatch):
    """Patch the transport's call method, NOT `transport_for`.

    That way the stored ciphertext is really decrypted on every interaction —
    so these tests also prove the token written at install time is the token
    the button handler gets back.
    """
    recorder = FakeSlack()
    seen = {}

    def call(self, method, **args):
        seen["token"] = self._token
        return recorder(method, **args)
    monkeypatch.setattr(slack_app.TenantSlackTransport, "call", call)
    recorder.seen = seen
    return recorder


def test_handled_offline_is_recorded_and_the_dm_is_rewritten(
        client, tenants, dm, fake_slack):
    row = dm("acme")
    r = post_interaction(client, click(row, slack_app.ACTION_HANDLED_OFFLINE))
    assert r.status_code == 200
    with db.tenant_tx(row["tenant_id"]) as conn:
        resp = conn.execute("SELECT * FROM triage_response WHERE triage_message_id=%s",
                            (row["id"],)).fetchall()
        msg = conn.execute("SELECT status FROM triage_message WHERE id=%s",
                           (row["id"],)).fetchone()
    assert len(resp) == 1 and resp[0]["response_type"] == "handled_offline"
    assert msg["status"] == "responded"
    assert [m for m, _ in fake_slack.calls] == ["chat.update"]
    # The transport really decrypted this workspace's own token.
    assert fake_slack.seen["token"] == "xoxb-acme-token"


def test_a_redelivered_click_records_one_response(client, tenants, dm, fake_slack):
    """Slack retries anything it does not see a 2xx for in three seconds. Two
    rows here would corrupt 7.8's satisfaction number, which is the one thing
    this whole phase exists to measure."""
    row = dm("acme")
    payload = click(row, slack_app.ACTION_SNOOZE_7D)
    first = post_interaction(client, payload)
    second = post_interaction(client, payload)
    assert first.status_code == 200 and second.status_code == 200
    assert second.json() == {"status": "duplicate"}
    with db.tenant_tx(row["tenant_id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM triage_response WHERE triage_message_id=%s",
                         (row["id"],)).fetchone()["n"]
    assert n == 1


def test_snooze_sets_a_seven_day_deadline(client, tenants, dm, fake_slack):
    row = dm("acme")
    post_interaction(client, click(row, slack_app.ACTION_SNOOZE_7D))
    with db.tenant_tx(row["tenant_id"]) as conn:
        msg = conn.execute("SELECT snooze_until, sent_at FROM triage_message WHERE id=%s",
                           (row["id"],)).fetchone()
    from datetime import datetime
    delta = (datetime.strptime(msg["snooze_until"], "%Y-%m-%dT%H:%M:%SZ")
             - datetime.strptime(now_iso(), "%Y-%m-%dT%H:%M:%SZ"))
    assert 6.9 < delta.days + delta.seconds / 86400 < 7.1


def test_blocked_on_opens_a_modal_and_records_nothing_yet(client, tenants, dm, fake_slack):
    """Opening a dialog is not an answer, and a user who cancels it has said
    nothing. Carried over from Phase 6 unchanged."""
    row = dm("acme")
    post_interaction(client, click(row, slack_app.ACTION_BLOCKED_ON))
    assert [m for m, _ in fake_slack.calls] == ["views.open"]
    with db.tenant_tx(row["tenant_id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM triage_response WHERE triage_message_id=%s",
                         (row["id"],)).fetchone()["n"]
        msg = conn.execute("SELECT status FROM triage_message WHERE id=%s",
                           (row["id"],)).fetchone()
    assert n == 0 and msg["status"] == "sent"


def submission(row, text, view_id="V_1"):
    return {
        "type": "view_submission",
        "team": {"id": row["team_id"]},
        "view": {"id": view_id, "callback_id": slack_app.CALLBACK_BLOCKED_ON,
                 "private_metadata": json.dumps({"channel": row["channel"], "ts": row["ts"]}),
                 "state": {"values": {slack_app.BLOCKED_ON_BLOCK_ID: {
                     slack_app.BLOCKED_ON_ACTION_ID: {"value": text}}}}},
    }


def test_the_modal_answer_is_what_gets_recorded(client, tenants, dm, fake_slack):
    row = dm("acme")
    post_interaction(client, click(row, slack_app.ACTION_BLOCKED_ON))
    r = post_interaction(client, submission(row, "waiting on infra for a staging DB",
                                            view_id="V_blocked_1"))
    assert r.status_code == 200
    with db.tenant_tx(row["tenant_id"]) as conn:
        resp = conn.execute("SELECT * FROM triage_response WHERE triage_message_id=%s",
                            (row["id"],)).fetchone()
    assert resp["response_type"] == "blocked_on"
    assert resp["blocked_on_text"] == "waiting on infra for a staging DB"
    # The raw payload is kept, so a disputed response can be reconstructed.
    assert json.loads(resp["raw_payload"])["type"] == "view_submission"


def test_an_empty_modal_answer_is_pushed_back_not_stored(client, tenants, dm, fake_slack):
    """'Blocked on nothing' in the morning digest is worse than useless."""
    row = dm("acme")
    r = post_interaction(client, submission(row, "   ", view_id="V_empty_1"))
    assert r.json()["response_action"] == "errors"
    assert slack_app.BLOCKED_ON_BLOCK_ID in r.json()["errors"]
    with db.tenant_tx(row["tenant_id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM triage_response WHERE triage_message_id=%s",
                         (row["id"],)).fetchone()["n"]
    assert n == 0


def test_a_failed_redraw_does_not_lose_the_answer(client, tenants, dm, fake_slack):
    """Database first, Slack second — Phase 6's ordering, kept. Losing a
    developer's answer because a cosmetic redraw failed would be the worst
    possible trade."""
    row = dm("acme")
    fake_slack.fail_with = "channel_not_found"
    post_interaction(client, click(row, slack_app.ACTION_HANDLED_OFFLINE))
    with db.tenant_tx(row["tenant_id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM triage_response WHERE triage_message_id=%s",
                         (row["id"],)).fetchone()["n"]
    assert n == 1


def test_a_click_on_something_that_is_not_an_argus_dm_is_ignored(client, dm, fake_slack):
    row = dm("acme")
    stray = click(row, slack_app.ACTION_HANDLED_OFFLINE)
    stray["container"]["message_ts"] = "1700000000.999999"
    stray["message"]["ts"] = "1700000000.999999"
    r = post_interaction(client, stray)
    assert r.status_code == 200
    assert fake_slack.calls == []


def test_a_click_from_a_revoked_workspace_is_ignored(client, tenants, monkeypatch,
                                                     fake_slack):
    _install_workspace(client, monkeypatch, "acme", "T_DEAD", "Dead", "xoxb-d")
    post_event(client, {"type": "event_callback", "team_id": "T_DEAD",
                        "event_id": "Ev_dead_1", "event": {"type": "app_uninstalled"}})
    r = post_interaction(client, {"type": "block_actions", "team": {"id": "T_DEAD"},
                                  "container": {"channel_id": "D_X", "message_ts": "1.1"},
                                  "actions": [{"action_id": slack_app.ACTION_SNOOZE_7D}]})
    assert r.status_code == 200 and r.json()["status"] == "unresolved"


# ---------------------------------------------------------------------------
# 6. Isolation — the same wall 7.1 built, extended over 7.3's tables
# ---------------------------------------------------------------------------

def test_one_tenants_workspace_token_is_invisible_to_the_other(client, tenants,
                                                               slack_installed):
    with db.tenant_tx(tenants["globex"]["id"]) as conn:
        rows = conn.execute("SELECT team_id FROM slack_workspace_token").fetchall()
    teams = {r["team_id"] for r in rows}
    assert "T_ACME" not in teams
    assert "T_GLOBEX" in teams


def test_slack_tables_return_nothing_with_no_tenant_bound(client, slack_installed):
    """Fail closed. If the binding is ever missing, the policies see NULL and
    the query returns zero rows — a bug shows up as an empty screen, never as
    another team's data."""
    with db.unbound_app_tx() as conn:
        assert conn.execute("SELECT count(*) AS n FROM slack_workspace_token"
                            ).fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM slack_event").fetchone()["n"] == 0


def test_rls_is_forced_on_both_new_tables(client):
    with db.unbound_app_tx() as conn:
        rows = conn.execute(
            "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class"
            " WHERE relname IN ('slack_workspace_token','slack_event')").fetchall()
    assert len(rows) == 2
    for r in rows:
        assert r["relrowsecurity"] and r["relforcerowsecurity"], r["relname"]


def test_the_app_role_still_cannot_read_install_claims(client):
    """7.2's rule, re-checked now that a second kind of claim lives in that
    table: a bearer-token hash gets the same treatment as an API key."""
    import psycopg
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.unbound_app_tx() as conn:
            conn.execute("SELECT * FROM install_claim")


def test_a_click_routed_by_team_id_cannot_reach_the_other_tenants_dm(
        client, tenants, dm, fake_slack):
    """The routing test that matters: acme's DM coordinates, presented with
    globex's team_id. RLS scopes the lookup, so it finds nothing rather than
    recording an answer against another team's message."""
    acme_dm = dm("acme", channel="D_SHARED", ts="1756009999.000777")
    payload = click(acme_dm, slack_app.ACTION_HANDLED_OFFLINE, team_id="T_GLOBEX")
    r = post_interaction(client, payload)
    assert r.status_code == 200
    with db.tenant_tx(tenants["acme"]["id"]) as conn:
        n = conn.execute("SELECT count(*) AS n FROM triage_response WHERE triage_message_id=%s",
                         (acme_dm["id"],)).fetchone()["n"]
    assert n == 0
    assert fake_slack.calls == []


# ---------------------------------------------------------------------------
# 7. Drift — the copy of Phase 6's constants cannot quietly diverge
# ---------------------------------------------------------------------------

def test_the_action_ids_still_match_phase_6(client):
    """`backend/` deliberately imports nothing from the Phase 6 engine (7.1's
    rule, kept). The price is a copy of six string constants, and this is the
    check that keeps the copy honest: change one without the other and a live
    button silently stops being recognised (D-146)."""
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    source = open(os.path.join(here, "slack_triage.py"), encoding="utf-8").read()
    for name in ("CALLBACK_BLOCKED_ON", "ACTION_HANDLED_OFFLINE", "ACTION_BLOCKED_ON",
                 "ACTION_SNOOZE_7D", "BLOCKED_ON_BLOCK_ID", "BLOCKED_ON_ACTION_ID"):
        m = re.search(rf'^{name} = "([^"]+)"', source, re.M)
        assert m, f"{name} is no longer defined in slack_triage.py"
        assert m.group(1) == getattr(slack_app, name), (
            f"{name} drifted: slack_triage.py has {m.group(1)!r}, "
            f"slack_app.py has {getattr(slack_app, name)!r}")
    assert slack_app.SNOOZE_DAYS == int(re.search(r"^SNOOZE_DAYS = (\d+)", source, re.M).group(1))


# ---------------------------------------------------------------------------
# 8. The app manifest — what a pilot team's security reviewer reads
# ---------------------------------------------------------------------------

BASE = "https://argus-backend-2nv0.onrender.com"


def test_the_manifest_turns_socket_mode_off():
    """The one line that makes this step possible. Socket Mode is not
    available to a distributed app, and distribution is the entire point of
    7.3 (D-140)."""
    m = slack_app.build_manifest(BASE)
    assert m["settings"]["socket_mode_enabled"] is False


def test_the_manifest_points_all_three_urls_at_this_backend():
    m = slack_app.build_manifest(BASE + "/")   # trailing slash, deliberately
    assert m["settings"]["event_subscriptions"]["request_url"] == BASE + "/v1/slack/events"
    assert m["settings"]["interactivity"]["request_url"] == BASE + "/v1/slack/interactions"
    assert m["oauth_config"]["redirect_urls"] == [BASE + "/v1/slack/oauth/callback"]


def test_the_manifest_asks_for_exactly_the_configured_scopes_and_no_more():
    """A scope that is in the manifest but not in config is one ARGUS asks a
    customer for and never uses; one in config but not the manifest breaks at
    runtime. They have to be the same list."""
    m = slack_app.build_manifest(BASE)
    assert m["oauth_config"]["scopes"]["bot"] == config.SLACK_BOT_SCOPES.split(",")


def test_the_manifest_asks_for_nothing_that_reads_channels():
    """ARGUS reads GitHub and Jira. It reads nothing in Slack — it only sends
    DMs and receives answers to them. The permission list is where a pilot
    team's security review will check that claim."""
    scopes = slack_app.build_manifest(BASE)["oauth_config"]["scopes"]["bot"]
    for forbidden in ("channels:history", "channels:read", "groups:history", "im:history",
                      "mpim:history", "files:read", "search:read", "chat:write.public"):
        assert forbidden not in scopes


def test_the_manifest_subscribes_only_to_uninstall_events():
    """Every subscribed event is one a customer has to be told about. These
    two are the ones ARGUS acts on, and they are the ones 7.8's uninstall rate
    is measured from."""
    events = slack_app.build_manifest(BASE)["settings"]["event_subscriptions"]["bot_events"]
    assert set(events) == slack_app.UNINSTALL_EVENTS
    assert set(events) == {"app_uninstalled", "tokens_revoked"}


def test_the_generated_setup_page_carries_no_secret():
    """The GitHub equivalent had to live in `secrets/` because it embedded the
    live setup secret. This one is safe to keep and share, and this check is
    what keeps that true if the page is ever edited."""
    from backend.make_slack_app_page import render
    page = render(BASE)
    for secret in (config.SLACK_CLIENT_SECRET, config.SLACK_SIGNING_SECRET,
                   config.SLACK_TOKEN_KEY, config.ADMIN_SECRET):
        assert secret and secret not in page
    assert "xoxb-" not in page
    # It should still contain the thing it exists to deliver.
    assert "socket_mode_enabled" in page and "users.profile:read" in page


# ---------------------------------------------------------------------------
# 9. The state the live deployment is in RIGHT NOW
#
# This code ships before the Slack app exists — that is Dirgh's Option B: build
# both backends, then do every registration click in one session at 7.5. So the
# behaviour that matters most on the day of the deploy is what happens with
# none of the Slack variables set. It has to be: the service starts, GitHub
# keeps working, and every Slack surface refuses politely instead of crashing.
# ---------------------------------------------------------------------------

def test_health_still_reports_a_running_service(client):
    r = client.get("/v1/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "phase": "7.5"}


def test_with_no_signing_secret_every_slack_request_is_refused(client, monkeypatch):
    """Fails closed. Before the secret is set there is no way to tell a real
    Slack request from a forged one, so nothing is trusted."""
    monkeypatch.setattr(config, "SLACK_SIGNING_SECRET", None)
    r = post_event(client, {"type": "url_verification", "challenge": "x"})
    assert r.status_code == 401
    assert "no_signing_secret_configured" in r.json()["detail"]


def test_with_no_client_id_the_install_page_says_so_and_sends_nobody_to_slack(
        client, tenants, monkeypatch):
    token = client.post("/v1/admin/tenants/acme/slack/install-link",
                        headers=ADMIN_HEADERS).json()["token"]
    monkeypatch.setattr(config, "SLACK_CLIENT_ID", None)
    r = client.get(f"/v1/slack/install?state={token}", follow_redirects=False)
    assert r.status_code == 503
    assert "not configured" in r.text.lower()


def test_with_no_token_key_the_callback_refuses_rather_than_storing_a_bare_token(
        client, tenants, monkeypatch):
    """The silent downgrade this project must not make: no key, no storage.
    Writing the bot token in the clear 'just for now' is how a credential ends
    up plaintext in production for a month."""
    claim = client.post("/v1/admin/tenants/acme/slack/install-link",
                        headers=ADMIN_HEADERS).json()["token"]
    monkeypatch.setattr(config, "SLACK_TOKEN_KEY", None)
    r = client.get(f"/v1/slack/oauth/callback?code=x&state={claim}")
    assert r.status_code == 503
    assert "securely" in r.text
    # The claim survives, so the same link works once the key is set.
    monkeypatch.undo()
    assert client.get(f"/v1/slack/install?state={claim}",
                      follow_redirects=False).status_code == 302


def test_the_github_surface_is_untouched_by_any_of_this(client, tenants):
    """7.3 changed `argus_claim_installation` (to check `provider`) and the
    function 7.2's install-link endpoint calls. Both are on GitHub's path, so
    the GitHub flow gets re-proved end to end here rather than assumed intact.
    """
    link = client.post("/v1/admin/tenants/globex/github/install-link",
                       headers=ADMIN_HEADERS)
    assert link.status_code == 201
    token = link.json()["token"]
    assert token.startswith("argus_claim_")
    r = client.get(f"/v1/github/setup?installation_id=55443322&state={token}")
    assert r.status_code == 200 and "now connected" in r.text
    with db.tenant_tx(tenants["globex"]["id"]) as conn:
        row = conn.execute(
            "SELECT credential_ref FROM integration WHERE external_account_id='55443322'"
        ).fetchone()
    assert row["credential_ref"] == "github_app_installation"
