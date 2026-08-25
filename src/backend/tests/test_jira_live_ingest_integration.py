"""7.4c-d: Jira live ingestion — credential encryption, the admin credential
endpoint, and the actual end-to-end proof the user asked for: a live-shaped
GitHub PR and a live-shaped Jira ticket, sharing one tenant's scratch DB
through `backend.ingest_worker.run_one`, migrated into real Postgres, and
coming out the other end as a real `alert` row with `outcome='FIRE'` — not
just `SUPPRESSED`, which is all 7.4c-b (GitHub-only) could ever produce
(`test_github_live_ingest_integration.py`'s own documented result, and
D-161's finding #1).

Three concerns, in one file, same shape `test_ingest_worker.py` and
`test_slack_app.py` each already hold multiple concerns together:

  1. `jira_crypto` — the encryption primitive itself, mirroring
     `test_slack_app.py`'s own crypto section exactly.
  2. `POST /v1/admin/tenants/{slug}/jira/credentials` — the admin endpoint,
     auth, validation, and idempotent-per-project upsert behavior.
  3. `ingest_worker.run_one` — the real chain, GitHub + Jira together, into
     Postgres, proving a live FIRE and proving one integration's failure
     does not lose the other's data.
"""
from __future__ import annotations

import os
import sys
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import config, db, ingest_worker, jira_crypto  # noqa: E402
from backend.auth import now_iso  # noqa: E402
import github_live_ingest as GLI  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}
_SLUG_COUNTER = iter(range(4000))


# ---------------------------------------------------------------------------
# 1. jira_crypto — mirrors test_slack_app.py's own crypto section exactly.
# ---------------------------------------------------------------------------

def test_credential_encryption_round_trips():
    sealed = jira_crypto.encrypt_credential("a@acme.com", "tok-secret",
                                            "11111111-1111-1111-1111-111111111111")
    assert "tok-secret" not in sealed and "a@acme.com" not in sealed
    opened = jira_crypto.decrypt_credential(sealed, "11111111-1111-1111-1111-111111111111")
    assert opened == {"email": "a@acme.com", "api_token": "tok-secret"}


def test_a_jira_ciphertext_cannot_be_moved_between_tenants():
    sealed = jira_crypto.encrypt_credential("a@acme.com", "tok-secret",
                                            "11111111-1111-1111-1111-111111111111")
    with pytest.raises(jira_crypto.JiraCredentialUndecryptable):
        jira_crypto.decrypt_credential(sealed, "22222222-2222-2222-2222-222222222222")


def test_tampered_jira_ciphertext_is_rejected_not_silently_wrong():
    tid = "11111111-1111-1111-1111-111111111111"
    sealed = jira_crypto.encrypt_credential("a@acme.com", "tok-secret", tid)
    broken = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
    with pytest.raises(jira_crypto.JiraCredentialUndecryptable):
        jira_crypto.decrypt_credential(broken, tid)
    with pytest.raises(jira_crypto.JiraCredentialUndecryptable):
        jira_crypto.decrypt_credential("not-even-versioned", tid)


def test_two_encryptions_of_the_same_jira_credential_differ():
    tid = "11111111-1111-1111-1111-111111111111"
    assert (jira_crypto.encrypt_credential("a@acme.com", "tok-x", tid)
           != jira_crypto.encrypt_credential("a@acme.com", "tok-x", tid))


# ---------------------------------------------------------------------------
# 2. POST /v1/admin/tenants/{slug}/jira/credentials
# ---------------------------------------------------------------------------

@pytest.fixture
def bare_jira_tenant(client):
    slug = f"jira-cred-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Jira Cred Test Co"})
    assert r.status_code == 201, r.text
    return r.json()


def test_setting_jira_credentials_requires_admin(client, bare_jira_tenant):
    r = client.post(f"/v1/admin/tenants/{bare_jira_tenant['slug']}/jira/credentials",
                    json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                          "email": "a@acme.com", "api_token": "tok"})
    assert r.status_code == 401


def test_setting_jira_credentials_for_an_unknown_tenant_404s(client):
    r = client.post("/v1/admin/tenants/does-not-exist/jira/credentials", headers=ADMIN,
                    json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                          "email": "a@acme.com", "api_token": "tok"})
    assert r.status_code == 404


def test_setting_jira_credentials_stores_an_encrypted_row_the_endpoint_never_echoes(
        client, bare_jira_tenant):
    slug = bare_jira_tenant["slug"]
    r = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                    json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                          "email": "a@acme.com", "api_token": "tok-super-secret"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["project_key"] == "ENG"
    assert body["base_url"] == "https://acme.atlassian.net"
    assert "api_token" not in body and "tok-super-secret" not in str(body)

    with db.tenant_tx(bare_jira_tenant["id"]) as conn:
        row = conn.execute(
            "SELECT i.external_account_id, i.display_name, i.credential_ref, i.revoked_at"
            " FROM integration i JOIN source s ON s.id=i.source_id"
            " WHERE s.name='jira'").fetchone()
    assert row["external_account_id"] == "ENG"
    assert row["display_name"] == "https://acme.atlassian.net"
    assert row["revoked_at"] is None
    assert "tok-super-secret" not in row["credential_ref"]  # encrypted at rest, not plaintext
    decrypted = jira_crypto.decrypt_credential(row["credential_ref"], bare_jira_tenant["id"])
    assert decrypted == {"email": "a@acme.com", "api_token": "tok-super-secret"}


def test_setting_jira_credentials_twice_for_the_same_project_upserts_in_place(
        client, bare_jira_tenant):
    """A rotated API token, or a corrected email, must update the SAME
    integration row (one project = one row), not create a second one that
    `_jira_projects` would then ingest twice."""
    slug = bare_jira_tenant["slug"]
    first = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                        json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                              "email": "a@acme.com", "api_token": "tok-v1"})
    assert first.status_code == 201, first.text
    second = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                         json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                               "email": "a@acme.com", "api_token": "tok-v2"})
    assert second.status_code == 201, second.text
    assert second.json()["integration_id"] == first.json()["integration_id"]

    with db.tenant_tx(bare_jira_tenant["id"]) as conn:
        rows = conn.execute(
            "SELECT i.credential_ref FROM integration i JOIN source s ON s.id=i.source_id"
            " WHERE s.name='jira' AND i.external_account_id='ENG'").fetchall()
    assert len(rows) == 1, "must UPDATE the existing row, not insert a second one"
    decrypted = jira_crypto.decrypt_credential(rows[0]["credential_ref"], bare_jira_tenant["id"])
    assert decrypted["api_token"] == "tok-v2"


# ---------------------------------------------------------------------------
# 3. ingest_worker.run_one — the real chain, GitHub + Jira together
# ---------------------------------------------------------------------------

class _FakeHTTPResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body
        self.headers = {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _route(rules):
    def _fake(req, timeout=None):
        for substr, resp in rules.items():
            if substr in req.full_url:
                return resp
        raise AssertionError(f"unrouted URL in test fixture: {req.full_url}")
    return _fake


def _combined_rules(ticket_key="ENG-42", sprint_state="active", status_category="indeterminate",
                    status_name="In Progress"):
    """One GitHub PR (§4.2 Pattern 2 shape, title carrying the ticket key —
    the same `pr_title_key` link method `verify_jira_live_ingest.py` check 3
    already proved resolves) plus one Jira project with that same ticket in
    one sprint, whose state/category are parameters so failure-mode tests
    below can reuse this with a parked or non-active sprint instead.
    """
    issue = (
        ('{"number":42,"title":"[%s] Fix flaky retry budget",'
         '"user":{"login":"amy"},"state":"open","created_at":"2026-08-01T00:00:00Z",'
         '"labels":[],"html_url":"https://github.com/pilotco/widgets/pull/42",'
         '"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
         % ticket_key).encode()
    )
    pr = b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}'
    timeline = (
        b'[{"event":"review_requested","actor":{"login":"amy"},'
        b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]'
    )
    project = b'{"key":"ENG","name":"Engineering"}'
    boards = b'{"values":[{"id":10,"name":"ENG board"}]}'
    sprints = (('{"values":[{"id":501,"name":"Sprint 12","state":"%s",'
               '"startDate":"2026-08-18T00:00:00.000Z","endDate":"2026-09-01T00:00:00.000Z"}]}'
               % sprint_state).encode())
    sprint_issues = (
        ('{"issues":[{"key":"%s","fields":{"summary":"Fix flaky retry budget",'
         '"issuetype":{"name":"Story","subtask":false},'
         '"status":{"name":"%s","statusCategory":{"key":"%s"}},'
         '"assignee":{"accountId":"acc-amy","displayName":"Amy","accountType":"atlassian"},'
         '"created":"2026-08-01T00:00:00.000+0000","updated":"2026-08-19T00:00:00.000+0000"}}]}'
         % (ticket_key, status_name, status_category)).encode()
    )
    backlog = b'{"issues":[]}'
    changelog = b'{"histories":[]}'
    return {
        "installation/repositories": _FakeHTTPResponse(
            200, b'{"total_count":1,"repositories":['
                 b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}}]}'),
        "pilotco/widgets/pulls?state=open": _FakeHTTPResponse(200, b'[{"number":42,"title":"x"}]'),
        "pilotco/widgets/issues/42/timeline": _FakeHTTPResponse(200, timeline),
        "pilotco/widgets/issues/42/comments": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42/reviews": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets/pulls/42": _FakeHTTPResponse(200, pr),
        "pilotco/widgets/issues/42": _FakeHTTPResponse(200, issue),
        "rest/api/3/project/ENG": _FakeHTTPResponse(200, project),
        "rest/agile/1.0/board?projectKeyOrId=ENG": _FakeHTTPResponse(200, boards),
        "rest/agile/1.0/board/10/sprint": _FakeHTTPResponse(200, sprints),
        "rest/agile/1.0/sprint/501/issue": _FakeHTTPResponse(200, sprint_issues),
        "rest/agile/1.0/board/10/backlog": _FakeHTTPResponse(200, backlog),
        f"rest/api/3/issue/{ticket_key}/changelog": _FakeHTTPResponse(200, changelog),
    }


def _mock_network(rules):
    return (
        mock.patch.object(ingest_worker._TOKEN_CACHE, "get",
                          return_value="fake-installation-token"),
        mock.patch("urllib.request.urlopen", side_effect=_route(rules)),
    )


@pytest.fixture
def jira_worker_tenant(client):
    """A tenant with both a claimed GitHub installation (same claim flow
    `worker_tenant` in test_ingest_worker.py proves) and a live Jira
    credential for project ENG at https://acme.atlassian.net — the
    combination §3.1.5 step d actually needs proven together.
    """
    n = next(_SLUG_COUNTER)
    slug = f"jira-worker-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Jira Worker Test Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()

    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    assert link.status_code == 201, link.text
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(700000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    cred = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                       json={"base_url": "https://acme.atlassian.net", "project_key": "ENG",
                             "email": "a@acme.com", "api_token": "tok-real"})
    assert cred.status_code == 201, cred.text
    return tenant


def _insert_running_run(tenant_id):
    with db.tenant_tx(tenant_id) as conn:
        return conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','running',%s) RETURNING id",
            (tenant_id, now_iso())).fetchone()["id"]


def test_a_live_github_pr_and_a_live_jira_ticket_together_produce_a_real_fire(
        client, jira_worker_tenant):
    """THE proof: not 'tickets landed in a table' but 'the frozen, unmodified
    Phase 6 engine reads a real linked, active-sprint ticket and fires' —
    exactly the gap D-161 named (GitHub-only can only ever SUPPRESS) closed
    for real, through the actual production entry point (`run_one`), not a
    hand-assembled scratch DB the way `verify_jira_live_ingest.py` proves it
    at the unit level.
    """
    tid = jira_worker_tenant["id"]
    run_id = _insert_running_run(tid)

    token_patch, url_patch = _mock_network(_combined_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, jira_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 1
    assert result["jira_projects_seen"] == 1
    assert result["jira_projects_ingested"] == 1
    assert result["jira_projects_failed"] == 0
    assert result["jira_tickets_ingested"] == 1
    assert result["FIRE"] == 1, result

    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT pattern, outcome, reason FROM alert WHERE ingest_run_id=%s",
            (run_id,)).fetchone()
        ticket = conn.execute("SELECT source_key, status_category FROM ticket").fetchone()
        link = conn.execute("SELECT link_method FROM ticket_link").fetchone()
        run_row = conn.execute("SELECT status, error_detail FROM ingest_run WHERE id=%s",
                               (run_id,)).fetchone()

    assert alert is not None
    assert alert["pattern"] == "P2-review-ghosted", alert["pattern"]
    assert alert["outcome"] == "FIRE", (alert["outcome"], alert["reason"])
    assert ticket["source_key"] == "ENG-42"
    assert ticket["status_category"] == "in_progress"
    assert link["link_method"] == "pr_title_key"
    assert run_row["status"] == "succeeded"
    assert run_row["error_detail"] is None


def test_a_ticket_in_a_non_active_sprint_still_suppresses_not_fires(
        client, jira_worker_tenant):
    """The gate is real, not a rubber stamp: the same ticket, linked the
    same way, in a 'future' sprint instead of 'active', must still
    SUPPRESS — proving this path can produce SUPPRESSED as well as FIRE,
    not just whatever the fixture happens to be shaped for.
    """
    tid = jira_worker_tenant["id"]
    run_id = _insert_running_run(tid)

    token_patch, url_patch = _mock_network(_combined_rules(sprint_state="future"))
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, jira_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["SUPPRESSED"] == 1
    assert result["FIRE"] == 0

    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT outcome, reason FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
    assert alert["outcome"] == "SUPPRESSED"
    assert alert["reason"] == "not_active_sprint_work", alert["reason"]


def test_a_jira_credential_that_fails_to_decrypt_does_not_lose_githubs_data(
        client, jira_worker_tenant):
    """Simulates the exact failure `_jira_projects` is written to isolate: a
    ciphertext that no longer authenticates (e.g. written under a since-
    rotated key). GitHub's own real work item must still make it all the
    way to a Postgres alert row.
    """
    tid = jira_worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        conn.execute(
            "UPDATE integration SET credential_ref='v1:bm90LXJlYWwtY2lwaGVydGV4dA=='"
            " WHERE tenant_id=%s AND source_id=(SELECT id FROM source WHERE name='jira')",
            (tid,))

    run_id = _insert_running_run(tid)
    token_patch, url_patch = _mock_network(_combined_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, jira_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 1
    assert result["jira_projects_failed"] == 1
    assert result["jira_tickets_ingested"] == 0
    # GitHub-only again, since the ticket never made it in — SUPPRESSED,
    # not lost entirely (no alert row at all would be the real bug).
    assert result["SUPPRESSED"] == 1

    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT outcome FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
        run_row = conn.execute("SELECT error_detail FROM ingest_run WHERE id=%s",
                               (run_id,)).fetchone()
    assert alert is not None and alert["outcome"] == "SUPPRESSED"
    assert run_row["error_detail"] and "jira:ENG" in run_row["error_detail"]


def test_a_tenant_with_no_jira_credentials_behaves_exactly_as_before(
        client):
    """The additive-not-required guarantee: a GitHub-only tenant (no Jira
    integration configured at all) runs exactly as 7.4c-b already proved —
    zero jira_projects_seen, SUPPRESSED not FIRE, no regression from this
    session's changes.
    """
    n = next(_SLUG_COUNTER)
    slug = f"gh-only-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "GitHub Only Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()
    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(710000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    run_id = _insert_running_run(tenant["id"])
    token_patch, url_patch = _mock_network(_combined_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tenant["id"], slug, run_id)

    assert result["status"] == "succeeded", result
    assert result["jira_projects_seen"] == 0
    assert result["jira_tickets_ingested"] == 0
    assert result["SUPPRESSED"] == 1
    assert result["FIRE"] == 0

    with db.tenant_tx(tenant["id"]) as conn:
        alert = conn.execute(
            "SELECT outcome, reason FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
    assert alert["outcome"] == "SUPPRESSED"
    assert alert["reason"] == "no_ticket_link", alert["reason"]
