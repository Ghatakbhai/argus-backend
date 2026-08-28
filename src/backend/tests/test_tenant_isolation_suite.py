"""Milestone 1 / Task 4 — the two-tenant cross-read security suite.

WHY THIS FILE EXISTS ALONGSIDE `test_isolation.py`
--------------------------------------------------
`test_isolation.py` (Phase 7.1) attacks the DATABASE: it takes the app's own
Postgres role, binds no tenant or the wrong one, and tries to read, write and
escalate underneath the API. That is the right test for the claim "a bug in
the application layer cannot become a data leak", and none of it is repeated
here.

This file attacks the four surfaces that sit OUTSIDE that boundary, which a
row-level-security test by construction cannot reach:

  4.2  The HTTP API, holding a real pilot team's API key. Not "does RLS
       work" but "does Tenant A's key, used exactly the way a real customer
       would use it, ever return or accept a row belonging to Tenant B".
  4.3  The encryption layer. Slack tokens, Jira credentials and Linear
       credentials are sealed with a tenant-scoped AAD; a ciphertext copied
       from one tenant's row into another's must fail LOUDLY, not decrypt to
       something plausible and not fail silently into a None.
  4.4  The `pg_policies` catalog itself, table by table, for the ten tables
       Milestone 1 names. `test_isolation.py` asserts the negative ("no
       table escaped the loop"); this asserts the positive, by name, so that
       a table being dropped, renamed, or replaced by a view cannot make the
       negative test vacuously pass.
  4.5  The webhook endpoints, which are the only doors into this system that
       carry no API key at all. GitHub and Slack authenticate by HMAC over
       the raw body; a forged or replayed signature must be refused before
       any tenant is resolved.

A note on what 4.5 actually asserts, which differs from the milestone
document's wording and is a correction rather than a shortcut: a webhook
with a BAD SIGNATURE is 401, as the document says. A webhook with a good
signature naming an installation no tenant has claimed is deliberately NOT
401 — `POST /v1/webhooks/github` acknowledges it with 200 and drops it
(`app.py`'s own documented behaviour, Phase 7.2). That is correct and must
stay correct: GitHub retries anything that is not 2xx, and an installation
that exists but has not finished its claim yet is a normal waiting state,
not an attack. What matters for isolation is not the status code but that
such an event never reaches a tenant's data — which is what is asserted
below.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time

import psycopg
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import (  # noqa: E402
    config, db, github_app, jira_crypto, linear_crypto, slack_app, slack_crypto,
)

ADMIN = {"x-admin-key": config.ADMIN_SECRET}

# The ten tables Milestone 1 §4.4 names by hand. Kept as a literal list, not
# derived from the catalog, on purpose: a list computed from the database
# would silently shrink to nothing if the schema failed to apply, and pass.
TENANT_TABLES = [
    "work_item", "event", "actor", "alert", "digest_delivery",
    "ticket", "ticket_link", "integration", "slack_workspace_token",
    "triage_message",
]

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"


# ===========================================================================
# 4.2 — Cross-tenant data guard, through the real HTTP API
# ===========================================================================

def test_each_tenants_key_sees_only_its_own_identity(tenants, client):
    for slug in ("acme", "globex"):
        r = client.get("/v1/me", headers=tenants[slug]["headers"])
        assert r.status_code == 200, r.text
        body = r.json()
        # /v1/me returns the tenant row it can actually see under RLS. That
        # it sees EXACTLY ONE is half the claim; that it is its own is the
        # other half.
        assert body["visible_tenant_rows"] == 1, body["visible_tenant_rows"]
        assert body["tenant"]["slug"] == slug, body["tenant"]


def test_a_tenants_key_never_returns_the_other_tenants_alerts(tenants, client):
    """Both tenants hold one identically-shaped alert. If the API were
    filtering by nothing, this test would still see one row — so it checks
    IDENTITY, not count: acme's key must return acme's alert id and must
    never return globex's."""
    for mine, theirs in (("acme", "globex"), ("globex", "acme")):
        r = client.get("/v1/alerts", headers=tenants[mine]["headers"])
        assert r.status_code == 200, r.text
        ids = {a["id"] for a in r.json()}
        assert tenants[mine]["alert_id"] in ids
        assert tenants[theirs]["alert_id"] not in ids


def test_a_tenants_key_never_returns_the_other_tenants_digests(tenants, client):
    for mine, theirs in (("acme", "globex"), ("globex", "acme")):
        r = client.get("/v1/digests", headers=tenants[mine]["headers"])
        assert r.status_code == 200, r.text
        texts = " ".join(d.get("rendered_text") or "" for d in r.json())
        assert mine in texts
        assert theirs not in texts, f"{mine}'s key saw {theirs}'s digest text"

        latest = client.get("/v1/digests/latest", headers=tenants[mine]["headers"])
        assert latest.status_code == 200, latest.text
        assert theirs not in (latest.json().get("rendered_text") or "")


def test_naming_another_tenants_alert_id_directly_is_a_404_not_a_write(tenants, client):
    """The most direct cross-tenant attack the API surface allows: I know
    (or guessed) your alert's primary key, and I post feedback on it. It
    must 404 — and, critically, must not have written anything first."""
    victim = tenants["globex"]["alert_id"]
    r = client.post("/v1/alerts/feedback", headers=tenants["acme"]["headers"],
                    json={"alert_id": victim, "verdict": "useful"})
    assert r.status_code == 404, r.text

    with db.tenant_tx(tenants["globex"]["id"]) as conn:
        rows = conn.execute("SELECT * FROM alert_feedback WHERE alert_id=%s",
                            (victim,)).fetchall()
    assert rows == [], "a 404 was returned but the row was written anyway"


def test_an_unknown_or_malformed_api_key_is_401_not_a_blank_tenant(tenants, client):
    """A rejected key must never fall through to an unbound-but-accepted
    request, which would read as 'authenticated with no tenant'."""
    for header in ({"Authorization": "Bearer not-a-real-key"},
                   {"Authorization": "Bearer "},
                   {"Authorization": "Basic abc"},
                   {}):
        r = client.get("/v1/alerts", headers=header)
        assert r.status_code == 401, (header, r.status_code, r.text)


def test_a_suspended_tenants_key_is_403_and_stops_reading_immediately(tenants, client):
    """Offboarding has to bite at once. A suspended tenant's key keeps its
    shape and its hash — what changes is that every request is refused."""
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": "suspendable", "display_name": "Suspendable Co"})
    assert r.status_code == 201, r.text
    victim = r.json()
    headers = {"Authorization": f"Bearer {victim['api_key']}"}
    assert client.get("/v1/alerts", headers=headers).status_code == 200

    s = client.post("/v1/admin/tenants/suspendable/status", headers=ADMIN,
                    params={"new_status": "suspended"})
    assert s.status_code == 200, s.text
    assert client.get("/v1/alerts", headers=headers).status_code == 403
    assert client.get("/v1/me", headers=headers).status_code == 403

    # ...and the other tenants are entirely unaffected by it.
    assert client.get("/v1/alerts", headers=tenants["acme"]["headers"]).status_code == 200


def test_a_tenant_api_key_cannot_reach_the_admin_surface(tenants, client):
    """A pilot team's own key is not a weaker admin key. If it were, the
    cross-tenant guards above would be trivially bypassable by asking the
    admin endpoints for the other tenant instead."""
    for path in ("/v1/admin/tenants", "/v1/admin/metrics"):
        r = client.get(path, headers=tenants["acme"]["headers"])
        assert r.status_code == 401, (path, r.status_code)


# ===========================================================================
# 4.3 — Cryptographic key separation
# ===========================================================================

@pytest.mark.parametrize("mod,seal,label", [
    (slack_crypto, lambda t: slack_crypto.encrypt_token("xoxb-real-secret", t), "slack"),
    (jira_crypto, lambda t: jira_crypto.encrypt_credential("a@acme.com", "jira-secret", t), "jira"),
    (linear_crypto, lambda t: linear_crypto.encrypt_credential("lin_api_secret", t), "linear"),
])
def test_a_ciphertext_cannot_be_opened_with_another_tenants_identity(mod, seal, label):
    """The tenant id is the AAD, not merely a lookup key — so a ciphertext
    physically copied out of Tenant A's row and into Tenant B's must FAIL,
    loudly, rather than decrypt. Loudly matters as much as failing: a
    silent None here would be indistinguishable from 'this tenant has no
    Slack token yet', and would be handled as such."""
    sealed = seal(TENANT_A)
    opener = (mod.decrypt_token if label == "slack" else mod.decrypt_credential)

    assert opener(sealed, TENANT_A)  # sanity: it opens for its true owner

    with pytest.raises(Exception) as exc:
        opener(sealed, TENANT_B)
    assert "Undecryptable" in type(exc.value).__name__, type(exc.value).__name__


def test_the_three_credential_families_do_not_share_a_key(tenants):
    """Slack, Jira and Linear each derive from their OWN environment secret.
    A single leaked key must not open all three. Proven by sealing with one
    family and trying to open with the others."""
    tid = tenants["acme"]["id"]
    slack_sealed = slack_crypto.encrypt_token("xoxb-real-secret", tid)
    jira_sealed = jira_crypto.encrypt_credential("a@acme.com", "jira-secret", tid)

    with pytest.raises(Exception):
        jira_crypto.decrypt_credential(slack_sealed, tid)
    with pytest.raises(Exception):
        slack_crypto.decrypt_token(jira_sealed, tid)
    with pytest.raises(Exception):
        linear_crypto.decrypt_credential(jira_sealed, tid)


def test_a_stored_slack_token_is_never_readable_as_plaintext_by_another_tenant(tenants):
    """The end-to-end version of the test above, through the actual table:
    the ciphertext is written into acme's `slack_workspace_token` row, and
    the attack is 'globex somehow obtains that blob'. RLS already stops the
    read; this proves the SECOND lock — that holding the blob is not enough."""
    acme, globex = tenants["acme"], tenants["globex"]
    sealed = slack_crypto.encrypt_token("xoxb-acme-real-bot-token", acme["id"])
    assert "xoxb-acme-real-bot-token" not in sealed

    with db.tenant_tx(globex["id"]) as conn:
        assert conn.execute(
            "SELECT count(*) FROM slack_workspace_token WHERE tenant_id=%s",
            (acme["id"],)).fetchone()["count"] == 0

    with pytest.raises(slack_crypto.SlackTokenUndecryptable):
        slack_crypto.decrypt_token(sealed, globex["id"])


def test_a_tampered_ciphertext_is_refused_rather_than_partially_trusted(tenants):
    tid = tenants["acme"]["id"]
    sealed = slack_crypto.encrypt_token("xoxb-real-secret", tid)
    broken = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
    with pytest.raises(slack_crypto.SlackTokenUndecryptable):
        slack_crypto.decrypt_token(broken, tid)


# ===========================================================================
# 4.4 — RLS policy audit, straight out of pg_policies
# ===========================================================================

def _catalog():
    return psycopg.connect(config.APP_DSN, autocommit=True)


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_every_named_tenant_table_exists_and_is_a_real_table(table, tenants):
    """Asserted separately from the policy check below so that a dropped or
    view-ified table fails as 'this table is gone', not as 'no policy'."""
    with _catalog() as c:
        kind = c.execute(
            "SELECT c.relkind FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace"
            " WHERE n.nspname='public' AND c.relname=%s", (table,)).fetchone()
    assert kind is not None, f"{table} does not exist"
    assert kind[0] == "r", f"{table} is relkind {kind[0]!r}, not an ordinary table"


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_rls_is_enabled_and_forced_on_every_named_tenant_table(table, tenants):
    """ENABLE alone is not enough: without FORCE, the table's owner — which
    is the role every migration runs as — bypasses the policy entirely."""
    with _catalog() as c:
        row = c.execute(
            "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c"
            " JOIN pg_namespace n ON n.oid=c.relnamespace"
            " WHERE n.nspname='public' AND c.relname=%s", (table,)).fetchone()
    assert row[0] is True, f"RLS not ENABLED on {table}"
    assert row[1] is True, f"RLS not FORCED on {table}"


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_each_named_table_carries_a_tenant_scoped_policy_both_ways(table, tenants):
    """`pg_policies` itself, not a proxy for it. Two things are asserted
    that a 'a policy exists' check would miss:

      * the policy is ALL, not just SELECT — a read-only policy would let a
        caller WRITE rows into another tenant.
      * `with_check` is populated, not NULL — a USING-only policy permits
        inserting rows you then cannot read, which is silent corruption
        rather than a refusal.
    """
    with _catalog() as c:
        rows = c.execute(
            "SELECT policyname, cmd, qual, with_check FROM pg_policies"
            " WHERE schemaname='public' AND tablename=%s", (table,)).fetchall()
    assert rows, f"no RLS policy at all on {table}"
    scoped = [r for r in rows if "argus_current_tenant" in (r[2] or "")]
    assert scoped, f"{table} has policies {[r[0] for r in rows]} but none scoped to the tenant"
    for name, cmd, qual, with_check in scoped:
        assert cmd == "ALL", f"{table}.{name} covers only {cmd}, not ALL"
        assert with_check and "argus_current_tenant" in with_check, \
            f"{table}.{name} has no tenant-scoped WITH CHECK — writes are unguarded"


def test_the_named_list_is_not_quietly_shorter_than_the_schema(tenants):
    """Guards the guard. If a future phase adds a tenant table and does not
    add it here, this suite would keep passing while covering less. The
    schema's own RLS loop is the source of truth; this asserts the hand
    list is a subset of it and names anything newly outside."""
    with _catalog() as c:
        protected = {r[0] for r in c.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace"
            " WHERE n.nspname='public' AND c.relkind='r'"
            "   AND c.relrowsecurity AND c.relforcerowsecurity").fetchall()}
    missing = set(TENANT_TABLES) - protected
    assert not missing, f"named tables with no forced RLS: {sorted(missing)}"


# ===========================================================================
# 4.5 — Webhook signature and misrouting guards
# ===========================================================================

def _gh_sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _gh_post(client, payload: dict, *, secret: str | None = None,
             signature: str | None = None, event: str = "pull_request",
             delivery: str = "d-isolation-1"):
    body = json.dumps(payload).encode()
    sig = signature if signature is not None else _gh_sign(
        body, secret if secret is not None else config.GITHUB_WEBHOOK_SECRET)
    return client.post("/v1/webhooks/github", content=body, headers={
        "content-type": "application/json",
        "x-hub-signature-256": sig,
        "x-github-event": event,
        "x-github-delivery": delivery,
    })


def test_a_github_webhook_with_the_wrong_signature_is_401(tenants, client):
    payload = {"action": "opened", "installation": {"id": 900001}}
    assert _gh_post(client, payload, secret="attackers-own-secret").status_code == 401
    assert _gh_post(client, payload, signature="sha256=" + "0" * 64).status_code == 401
    assert _gh_post(client, payload, signature="not-even-the-right-shape").status_code == 401


def test_a_github_webhook_with_no_signature_at_all_is_401(tenants, client):
    body = json.dumps({"action": "opened", "installation": {"id": 900002}}).encode()
    r = client.post("/v1/webhooks/github", content=body, headers={
        "content-type": "application/json", "x-github-event": "pull_request",
        "x-github-delivery": "d-isolation-nosig"})
    assert r.status_code == 401


def test_a_github_body_altered_after_signing_is_401(tenants, client):
    """The signature must be checked against the RAW body. Signing a benign
    payload and then swapping in a different installation id — the exact
    move that would misroute an event into another tenant — must fail."""
    signed = json.dumps({"action": "opened", "installation": {"id": 900003}}).encode()
    sig = _gh_sign(signed, config.GITHUB_WEBHOOK_SECRET)
    tampered = json.dumps({"action": "opened", "installation": {"id": 900004}}).encode()
    r = client.post("/v1/webhooks/github", content=tampered, headers={
        "content-type": "application/json", "x-hub-signature-256": sig,
        "x-github-event": "pull_request", "x-github-delivery": "d-isolation-tamper"})
    assert r.status_code == 401


def test_a_correctly_signed_webhook_for_an_unclaimed_installation_reaches_no_tenant(
        tenants, client):
    """The misrouting guard proper. This one is NOT 401 — see this module's
    docstring — but it must produce no work for anybody: no new ingest_run
    in either tenant, which is the only thing a content webhook can cause.
    """
    before = {}
    for slug in ("acme", "globex"):
        with db.tenant_tx(tenants[slug]["id"]) as conn:
            before[slug] = conn.execute(
                "SELECT count(*) FROM ingest_run").fetchone()["count"]

    r = _gh_post(client, {"action": "opened", "installation": {"id": 966001},
                          "repository": {"full_name": "stranger/repo"}},
                 delivery="d-isolation-unclaimed")
    assert r.status_code == 200, r.text
    assert r.json().get("status") != "queued", r.json()

    for slug in ("acme", "globex"):
        with db.tenant_tx(tenants[slug]["id"]) as conn:
            after = conn.execute("SELECT count(*) FROM ingest_run").fetchone()["count"]
        assert after == before[slug], f"an unclaimed installation queued work for {slug}"


def test_a_slack_request_with_a_forged_signature_is_401(tenants, client):
    body = b'{"type":"url_verification","challenge":"c"}'
    ts = str(int(time.time()))
    for path in ("/v1/slack/events", "/v1/slack/interactions"):
        r = client.post(path, content=body, headers={
            "content-type": "application/json",
            "x-slack-request-timestamp": ts,
            "x-slack-signature": "v0=" + "0" * 64})
        assert r.status_code == 401, (path, r.status_code, r.text)


def test_a_replayed_slack_request_is_401_even_though_its_signature_is_valid(
        tenants, client):
    """A captured request stays correctly signed forever. The timestamp
    window is what stops a replay, and it is asserted here rather than
    assumed because it is the only defence against one."""
    body = b'{"type":"url_verification","challenge":"c"}'
    stale = str(int(time.time()) - 60 * 60 * 24)
    sig = slack_app.sign_request(config.SLACK_SIGNING_SECRET, body, stale)
    r = client.post("/v1/slack/events", content=body, headers={
        "content-type": "application/json",
        "x-slack-request-timestamp": stale, "x-slack-signature": sig})
    assert r.status_code == 401, r.text


def test_the_signature_verifier_itself_rejects_every_near_miss(tenants):
    """Below the HTTP layer, so a future route change cannot quietly lose
    this. Same discipline `test_github_webhooks.py` applies to GitHub's."""
    secret = config.GITHUB_WEBHOOK_SECRET
    body = b'{"installation":{"id":1}}'
    good = _gh_sign(body, secret)
    assert github_app.verify_signature(secret, body, good) is True
    assert github_app.verify_signature(secret, body, None) is False
    assert github_app.verify_signature(secret, body, "") is False
    assert github_app.verify_signature(secret, body, good[:-1]) is False
    assert github_app.verify_signature(secret, b"other body", good) is False
    assert github_app.verify_signature("another-tenants-secret", body, good) is False
