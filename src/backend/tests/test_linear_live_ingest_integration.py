"""7.4c-e: Linear live ingestion — credential encryption, the admin
credential endpoint, and the actual end-to-end proof: a live-shaped GitHub
PR and a live-shaped Linear ticket, sharing one tenant's scratch DB through
`backend.ingest_worker.run_one`, migrated into real Postgres, and coming
out the other end as a real `alert` row with `outcome='FIRE'`.

Mirrors `test_jira_live_ingest_integration.py`'s own three-part shape
exactly:

  1. `linear_crypto` — the encryption primitive itself.
  2. `POST /v1/admin/tenants/{slug}/linear/credentials` — the admin
     endpoint, auth, validation, idempotent-per-team upsert behavior.
  3. `ingest_worker.run_one` — the real chain, GitHub + Linear together,
     into Postgres, proving a live FIRE and proving one integration's
     failure does not lose another's data. Also proves the genuinely new
     three-way case: GitHub + Jira + Linear all connected to the same
     tenant at once — the shape 7.4c-f's pilot rehearsal will actually
     need, not yet exercised by any earlier session's test file.

One real difference from `test_jira_live_ingest_integration.py`'s mock
shape: Linear is a single GraphQL endpoint, so requests to it are routed
by matching an operation name in the POST body, not by URL substring —
see `_route_combined` below.
"""
from __future__ import annotations

import json
import os
import sys
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import config, db, ingest_worker, linear_crypto  # noqa: E402
from backend.auth import now_iso  # noqa: E402
import github_live_ingest as GLI  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}
_SLUG_COUNTER = iter(range(5000))


# ---------------------------------------------------------------------------
# 1. linear_crypto — mirrors test_jira_live_ingest_integration.py's own
#    crypto section exactly, adapted for a single-secret payload.
# ---------------------------------------------------------------------------

def test_linear_credential_encryption_round_trips():
    sealed = linear_crypto.encrypt_credential("lin_api_secret",
                                              "11111111-1111-1111-1111-111111111111")
    assert "lin_api_secret" not in sealed
    opened = linear_crypto.decrypt_credential(sealed, "11111111-1111-1111-1111-111111111111")
    assert opened == {"api_key": "lin_api_secret"}


def test_a_linear_ciphertext_cannot_be_moved_between_tenants():
    sealed = linear_crypto.encrypt_credential("lin_api_secret",
                                              "11111111-1111-1111-1111-111111111111")
    with pytest.raises(linear_crypto.LinearCredentialUndecryptable):
        linear_crypto.decrypt_credential(sealed, "22222222-2222-2222-2222-222222222222")


def test_tampered_linear_ciphertext_is_rejected_not_silently_wrong():
    tid = "11111111-1111-1111-1111-111111111111"
    sealed = linear_crypto.encrypt_credential("lin_api_secret", tid)
    broken = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
    with pytest.raises(linear_crypto.LinearCredentialUndecryptable):
        linear_crypto.decrypt_credential(broken, tid)
    with pytest.raises(linear_crypto.LinearCredentialUndecryptable):
        linear_crypto.decrypt_credential("not-even-versioned", tid)


def test_two_encryptions_of_the_same_linear_credential_differ():
    tid = "11111111-1111-1111-1111-111111111111"
    assert (linear_crypto.encrypt_credential("lin_x", tid)
           != linear_crypto.encrypt_credential("lin_x", tid))


def test_linear_credential_key_is_independent_of_jira_key():
    """The actual point of giving Linear its own key (linear_crypto.py's
    module docstring): a ciphertext sealed under one integration's key
    must not authenticate under a shape that happens to reuse the other's
    machinery. Proven directly by round-tripping through linear_crypto
    alone — jira_crypto is a structurally different module (different AAD
    namespace, different payload shape) so there is no shared-key path to
    even attempt here, which is exactly the guarantee this test pins down.
    """
    tid = "11111111-1111-1111-1111-111111111111"
    sealed = linear_crypto.encrypt_credential("lin_x", tid)
    assert config.LINEAR_CREDENTIAL_KEY != config.JIRA_CREDENTIAL_KEY
    opened = linear_crypto.decrypt_credential(sealed, tid)
    assert opened == {"api_key": "lin_x"}


# ---------------------------------------------------------------------------
# 2. POST /v1/admin/tenants/{slug}/linear/credentials
# ---------------------------------------------------------------------------

@pytest.fixture
def bare_linear_tenant(client):
    slug = f"linear-cred-{next(_SLUG_COUNTER)}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Linear Cred Test Co"})
    assert r.status_code == 201, r.text
    return r.json()


def test_setting_linear_credentials_requires_admin(client, bare_linear_tenant):
    r = client.post(f"/v1/admin/tenants/{bare_linear_tenant['slug']}/linear/credentials",
                    json={"team_key": "ENG", "api_key": "lin_tok"})
    assert r.status_code == 401


def test_setting_linear_credentials_for_an_unknown_tenant_404s(client):
    r = client.post("/v1/admin/tenants/does-not-exist/linear/credentials", headers=ADMIN,
                    json={"team_key": "ENG", "api_key": "lin_tok"})
    assert r.status_code == 404


def test_setting_linear_credentials_stores_an_encrypted_row_the_endpoint_never_echoes(
        client, bare_linear_tenant):
    slug = bare_linear_tenant["slug"]
    r = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                    json={"team_key": "ENG", "api_key": "lin-super-secret"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["team_key"] == "ENG"
    assert "api_key" not in body and "lin-super-secret" not in str(body)

    with db.tenant_tx(bare_linear_tenant["id"]) as conn:
        row = conn.execute(
            "SELECT i.external_account_id, i.display_name, i.credential_ref, i.revoked_at"
            " FROM integration i JOIN source s ON s.id=i.source_id"
            " WHERE s.name='linear'").fetchone()
    assert row["external_account_id"] == "ENG"
    assert row["display_name"] == "https://api.linear.app"
    assert row["revoked_at"] is None
    assert "lin-super-secret" not in row["credential_ref"]  # encrypted at rest, not plaintext
    decrypted = linear_crypto.decrypt_credential(row["credential_ref"], bare_linear_tenant["id"])
    assert decrypted == {"api_key": "lin-super-secret"}


def test_setting_linear_credentials_twice_for_the_same_team_upserts_in_place(
        client, bare_linear_tenant):
    """A rotated API key must update the SAME integration row (one team =
    one row), not create a second one `_linear_teams` would then ingest
    twice."""
    slug = bare_linear_tenant["slug"]
    first = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                        json={"team_key": "ENG", "api_key": "lin-v1"})
    assert first.status_code == 201, first.text
    second = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                         json={"team_key": "ENG", "api_key": "lin-v2"})
    assert second.status_code == 201, second.text
    assert second.json()["integration_id"] == first.json()["integration_id"]

    with db.tenant_tx(bare_linear_tenant["id"]) as conn:
        rows = conn.execute(
            "SELECT i.credential_ref FROM integration i JOIN source s ON s.id=i.source_id"
            " WHERE s.name='linear' AND i.external_account_id='ENG'").fetchall()
    assert len(rows) == 1, "must UPDATE the existing row, not insert a second one"
    decrypted = linear_crypto.decrypt_credential(rows[0]["credential_ref"], bare_linear_tenant["id"])
    assert decrypted["api_key"] == "lin-v2"


# ---------------------------------------------------------------------------
# 3. ingest_worker.run_one — the real chain, GitHub + Linear together
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


def _team_found():
    return _FakeHTTPResponse(200, json.dumps(
        {"data": {"teams": {"nodes": [{"id": "team-1", "name": "Engineering", "key": "ENG"}]}}}
    ).encode())


def _cycles(state="active"):
    starts = "2026-08-18T00:00:00.000Z" if state != "future" else "2026-09-18T00:00:00.000Z"
    ends = "2026-09-01T00:00:00.000Z" if state != "future" else "2026-10-01T00:00:00.000Z"
    return _FakeHTTPResponse(200, json.dumps(
        {"data": {"team": {"cycles": {"nodes": [
            {"id": 601, "number": 12, "name": "Cycle 12",
             "startsAt": starts, "endsAt": ends, "completedAt": None},
        ]}}}}
    ).encode())


def _cycle_issues(ticket_key="ENG-42"):
    return _FakeHTTPResponse(200, json.dumps(
        {"data": {"team": {"issues": {"nodes": [
            {"id": "issue-1", "identifier": ticket_key, "title": "Fix flaky retry budget",
             "createdAt": "2026-08-01T00:00:00.000Z", "updatedAt": "2026-08-19T00:00:00.000Z",
             "state": {"id": "state-started", "name": "In Progress", "type": "started"},
             "assignee": {"id": "user-amy", "name": "Amy"},
             "labels": {"nodes": []}, "parent": None},
        ], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
    ).encode())


def _backlog_empty():
    return _FakeHTTPResponse(200, json.dumps(
        {"data": {"team": {"issues": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
    ).encode())


def _history_empty():
    return _FakeHTTPResponse(200, json.dumps(
        {"data": {"issue": {"history": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
    ).encode())


def _linear_graphql_rules(ticket_key="ENG-42", cycle_state="active"):
    return {
        "ArgusTeamLookup": _team_found(),
        "ArgusTeamCycles": _cycles(cycle_state),
        "ArgusCycleIssues": _cycle_issues(ticket_key),
        "ArgusBacklogIssues": _backlog_empty(),
        "ArgusIssueHistory": _history_empty(),
    }


def _github_rules(ticket_key="ENG-42"):
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
    }


def _route_combined(url_rules, graphql_rules=None):
    """Dispatches every mocked request this test file sends: GitHub's (and,
    where a combined GitHub+Jira+Linear test needs it, Jira's) REST calls
    are routed by URL substring, exactly like test_jira_live_ingest_
    integration.py's own `_route`. A request to Linear's single GraphQL
    endpoint is routed instead by matching an operation name against the
    POST body — the same technique verify_linear_live_ingest.py's
    `route_by_query` uses, folded into one dispatcher here since a combined
    run genuinely hits both kinds of API in the same test.
    """
    def _fake(req, timeout=None):
        if graphql_rules is not None and "api.linear.app/graphql" in req.full_url:
            body = json.loads(req.data)
            query_text = body.get("query", "")
            for substr, resp in graphql_rules.items():
                if substr in query_text:
                    return resp
            raise AssertionError(f"unrouted GraphQL operation: {query_text[:80]!r}")
        for substr, resp in url_rules.items():
            if substr in req.full_url:
                return resp
        raise AssertionError(f"unrouted URL in test fixture: {req.full_url}")
    return _fake


def _mock_network(url_rules, graphql_rules=None):
    return (
        mock.patch.object(ingest_worker._TOKEN_CACHE, "get",
                          return_value="fake-installation-token"),
        mock.patch("urllib.request.urlopen",
                   side_effect=_route_combined(url_rules, graphql_rules)),
    )


@pytest.fixture
def linear_worker_tenant(client):
    """A tenant with both a claimed GitHub installation and a live Linear
    credential for team ENG — the combination §3.1.5 step e needs proven
    together, same shape `jira_worker_tenant` proves for Jira."""
    n = next(_SLUG_COUNTER)
    slug = f"linear-worker-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Linear Worker Test Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()

    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    assert link.status_code == 201, link.text
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(800000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    cred = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                       json={"team_key": "ENG", "api_key": "lin-real"})
    assert cred.status_code == 201, cred.text
    return tenant


def _insert_running_run(tenant_id):
    with db.tenant_tx(tenant_id) as conn:
        return conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','running',%s) RETURNING id",
            (tenant_id, now_iso())).fetchone()["id"]


def test_a_live_github_pr_and_a_live_linear_ticket_together_produce_a_real_fire(
        client, linear_worker_tenant):
    """THE proof: the frozen, unmodified Phase 6 engine reads a real
    linked, active-cycle Linear ticket and fires — through the actual
    production entry point (`run_one`), not a hand-assembled scratch DB the
    way `verify_linear_live_ingest.py` proves it at the unit level.
    """
    tid = linear_worker_tenant["id"]
    run_id = _insert_running_run(tid)

    token_patch, url_patch = _mock_network(_github_rules(), _linear_graphql_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, linear_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 1
    assert result["linear_teams_seen"] == 1
    assert result["linear_teams_ingested"] == 1
    assert result["linear_teams_failed"] == 0
    assert result["linear_tickets_ingested"] == 1
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


def test_a_ticket_in_a_non_active_cycle_still_suppresses_not_fires(
        client, linear_worker_tenant):
    """The gate is real, not a rubber stamp: the same ticket, linked the
    same way, in a 'future' cycle instead of 'active', must still
    SUPPRESS."""
    tid = linear_worker_tenant["id"]
    run_id = _insert_running_run(tid)

    token_patch, url_patch = _mock_network(
        _github_rules(), _linear_graphql_rules(cycle_state="future"))
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, linear_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["SUPPRESSED"] == 1
    assert result["FIRE"] == 0

    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT outcome, reason FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
    assert alert["outcome"] == "SUPPRESSED"
    assert alert["reason"] == "not_active_sprint_work", alert["reason"]


def test_a_linear_credential_that_fails_to_decrypt_does_not_lose_githubs_data(
        client, linear_worker_tenant):
    """Simulates the exact failure `_linear_teams` is written to isolate: a
    ciphertext that no longer authenticates. GitHub's own real work item
    must still make it all the way to a Postgres alert row."""
    tid = linear_worker_tenant["id"]
    with db.tenant_tx(tid) as conn:
        conn.execute(
            "UPDATE integration SET credential_ref='v1:bm90LXJlYWwtY2lwaGVydGV4dA=='"
            " WHERE tenant_id=%s AND source_id=(SELECT id FROM source WHERE name='linear')",
            (tid,))

    run_id = _insert_running_run(tid)
    token_patch, url_patch = _mock_network(_github_rules(), _linear_graphql_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, linear_worker_tenant["slug"], run_id)

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 1
    assert result["linear_teams_failed"] == 1
    assert result["linear_tickets_ingested"] == 0
    assert result["SUPPRESSED"] == 1

    with db.tenant_tx(tid) as conn:
        alert = conn.execute(
            "SELECT outcome FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
        run_row = conn.execute("SELECT error_detail FROM ingest_run WHERE id=%s",
                               (run_id,)).fetchone()
    assert alert is not None and alert["outcome"] == "SUPPRESSED"
    assert run_row["error_detail"] and "linear:ENG" in run_row["error_detail"]


def test_a_tenant_with_no_linear_credentials_behaves_exactly_as_before(client):
    """The additive-not-required guarantee: a GitHub-only tenant (no Linear
    integration configured at all) runs exactly as 7.4c-b already proved —
    zero linear_teams_seen, SUPPRESSED not FIRE, no regression from this
    session's changes."""
    n = next(_SLUG_COUNTER)
    slug = f"gh-only-linear-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "GitHub Only Co (Linear test)"})
    assert r.status_code == 201, r.text
    tenant = r.json()
    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(810000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    run_id = _insert_running_run(tenant["id"])
    token_patch, url_patch = _mock_network(_github_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tenant["id"], slug, run_id)

    assert result["status"] == "succeeded", result
    assert result["linear_teams_seen"] == 0
    assert result["linear_tickets_ingested"] == 0
    assert result["SUPPRESSED"] == 1
    assert result["FIRE"] == 0

    with db.tenant_tx(tenant["id"]) as conn:
        alert = conn.execute(
            "SELECT outcome, reason FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchone()
    assert alert["outcome"] == "SUPPRESSED"
    assert alert["reason"] == "no_ticket_link", alert["reason"]


def test_github_jira_and_linear_all_connected_to_one_tenant_at_once(client):
    """The genuinely new case relative to 7.4c-d's own test file: a tenant
    with all THREE integrations connected — the exact shape 7.4c-f's pilot
    rehearsal (§3.1.5 step f) will need proven working together, not yet
    exercised by any earlier session. One Jira ticket and one Linear ticket
    both resolve, both land in the same `ticket` index, and the run
    succeeds with both counted correctly — proving the two adapters
    genuinely coexist in one scratch DB rather than only ever being tested
    pairwise against GitHub.
    """
    n = next(_SLUG_COUNTER)
    slug = f"triple-{n}"
    r = client.post("/v1/admin/tenants", headers=ADMIN,
                    json={"slug": slug, "display_name": "Triple Integration Co"})
    assert r.status_code == 201, r.text
    tenant = r.json()
    tid = tenant["id"]

    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    setup = client.get("/v1/github/setup", params={
        "installation_id": str(820000 + n), "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    jira_cred = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                            json={"base_url": "https://acme.atlassian.net", "project_key": "JIR",
                                  "email": "a@acme.com", "api_token": "tok"})
    assert jira_cred.status_code == 201, jira_cred.text
    linear_cred = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                              json={"team_key": "ENG", "api_key": "lin-real"})
    assert linear_cred.status_code == 201, linear_cred.text

    # Two separate GitHub PRs (#42 linked to the Linear ticket, #43 linked
    # to the Jira ticket) so both integrations' tickets get a real link and
    # a real gate check — a single shared PR would only prove one adapter
    # actually mattered to the outcome.
    jira_issue = (
        b'{"key":"JIR-7","fields":{"summary":"Ship the thing",'
        b'"issuetype":{"name":"Story","subtask":false},'
        b'"status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},'
        b'"assignee":{"accountId":"acc-amy","displayName":"Amy","accountType":"atlassian"},'
        b'"created":"2026-08-01T00:00:00.000+0000","updated":"2026-08-19T00:00:00.000+0000"}}'
    )
    url_rules = _github_rules(ticket_key="ENG-42")
    url_rules.update({
        "pilotco/widgets2/pulls?state=open": _FakeHTTPResponse(
            200, b'[{"number":43,"title":"x"}]'),
        "pilotco/widgets2/issues/43/timeline": _FakeHTTPResponse(200, (
            b'[{"event":"review_requested","actor":{"login":"amy"},'
            b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]')),
        "pilotco/widgets2/issues/43/comments": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets2/pulls/43/reviews": _FakeHTTPResponse(200, b'[]'),
        "pilotco/widgets2/pulls/43": _FakeHTTPResponse(
            200, b'{"draft":false,"merged":false,"state":"open","mergeable_state":"clean"}'),
        "pilotco/widgets2/issues/43": _FakeHTTPResponse(200, (
            b'{"number":43,"title":"[JIR-7] Ship the thing",'
            b'"user":{"login":"amy"},"state":"open","created_at":"2026-08-01T00:00:00Z",'
            b'"labels":[],"html_url":"https://github.com/pilotco/widgets2/pull/43",'
            b'"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}')),
        "installation/repositories": _FakeHTTPResponse(
            200, b'{"total_count":2,"repositories":['
                 b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}},'
                 b'{"name":"widgets2","full_name":"pilotco/widgets2","owner":{"login":"pilotco"}}]}'),
        "rest/api/3/project/JIR": _FakeHTTPResponse(200, b'{"key":"JIR","name":"Jirapatha"}'),
        "rest/agile/1.0/board?projectKeyOrId=JIR": _FakeHTTPResponse(
            200, b'{"values":[{"id":20,"name":"JIR board"}]}'),
        "rest/agile/1.0/board/20/sprint": _FakeHTTPResponse(200, (
            b'{"values":[{"id":701,"name":"Sprint 3","state":"active",'
            b'"startDate":"2026-08-18T00:00:00.000Z","endDate":"2026-09-01T00:00:00.000Z"}]}')),
        "rest/agile/1.0/sprint/701/issue": _FakeHTTPResponse(
            200, b'{"issues":[' + jira_issue + b']}'),
        "rest/agile/1.0/board/20/backlog": _FakeHTTPResponse(200, b'{"issues":[]}'),
        "rest/api/3/issue/JIR-7/changelog": _FakeHTTPResponse(200, b'{"histories":[]}'),
    })

    run_id = _insert_running_run(tid)
    token_patch, url_patch = _mock_network(url_rules, _linear_graphql_rules())
    with token_patch, url_patch:
        result = ingest_worker.run_one(tid, slug, run_id)

    assert result["status"] == "succeeded", result
    assert result["work_items_ingested"] == 2, result
    assert result["jira_projects_ingested"] == 1, result
    assert result["jira_tickets_ingested"] == 1, result
    assert result["linear_teams_ingested"] == 1, result
    assert result["linear_tickets_ingested"] == 1, result
    assert result["FIRE"] == 2, result
    assert result["SUPPRESSED"] == 0, result

    with db.tenant_tx(tid) as conn:
        tickets = conn.execute(
            "SELECT source_id, source_key FROM ticket ORDER BY source_key").fetchall()
        alerts = conn.execute(
            "SELECT outcome FROM alert WHERE ingest_run_id=%s", (run_id,)).fetchall()
    assert {t["source_key"] for t in tickets} == {"ENG-42", "JIR-7"}
    assert all(a["outcome"] == "FIRE" for a in alerts)
