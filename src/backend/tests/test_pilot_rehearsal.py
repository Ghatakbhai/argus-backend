"""7.4c-f — the end-to-end pilot rehearsal (§3.1.5 step 6, the last of the
six-step build order): "One fully wired fake tenant, real GitHub + Jira +
Linear, from webhook through to the dashboard showing real rows — the
proof Dirgh actually asked for."

This is deliberately NOT a new code path. Every piece exercised here —
the webhook trigger (7.2), the poller's claim function (7.4c-c, D-162),
GitHub/Jira/Linear live ingestion (7.4c-b/d/e, D-161/D-164/D-165), and the
dashboard endpoints (7.4b/7.4c-f's own D-16x fix) — already has its own
dedicated test file proving its piece in isolation. What none of them
prove alone is the FULL chain, driven the way a real pilot team's night
would actually go: GitHub's servers POST a webhook (not an admin clicking
"run now"), the in-process poller (not a test calling `run_one` directly)
picks it up with no tenant hint, and the dashboard endpoints are called
the same way a pilot's own API key would call them — not read out of
Postgres directly. Every earlier integration test call `run_one` or
`claim_and_run_one` in some more direct way; this file is the one that
walks the whole path in the order a real night would.

Network is mocked throughout (no outbound path to api.github.com,
*.atlassian.net, or api.linear.app exists from either place Claude can run
code — the standing block named in D-161/D-162/D-164/D-165's own
docstrings), and the fake tenant is created through the same admin API
Claude uses for real pilot onboarding, not a hand-assembled fixture.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import unittest.mock as mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import config, db, ingest_worker  # noqa: E402

ADMIN = {"x-admin-key": "dev-admin-secret-change-me"}
_SLUG_COUNTER = iter(range(6000))


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


def _linear_graphql_rules():
    return {
        "ArgusTeamLookup": _FakeHTTPResponse(200, json.dumps(
            {"data": {"teams": {"nodes": [{"id": "team-1", "name": "Engineering", "key": "ENG"}]}}}
        ).encode()),
        "ArgusTeamCycles": _FakeHTTPResponse(200, json.dumps(
            {"data": {"team": {"cycles": {"nodes": [
                {"id": 601, "number": 12, "name": "Cycle 12",
                 "startsAt": "2026-08-18T00:00:00.000Z", "endsAt": "2026-09-01T00:00:00.000Z",
                 "completedAt": None}]}}}}
        ).encode()),
        "ArgusCycleIssues": _FakeHTTPResponse(200, json.dumps(
            {"data": {"team": {"issues": {"nodes": [
                {"id": "issue-eng-77", "identifier": "ENG-77", "title": "Rework the retry queue",
                 "createdAt": "2026-08-01T00:00:00.000Z", "updatedAt": "2026-08-19T00:00:00.000Z",
                 "state": {"id": "state-started", "name": "In Progress", "type": "started"},
                 "assignee": {"id": "user-amy", "name": "Amy"},
                 "labels": {"nodes": []}, "parent": None}],
                "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
        ).encode()),
        "ArgusBacklogIssues": _FakeHTTPResponse(200, json.dumps(
            {"data": {"team": {"issues": {"nodes": [],
                                          "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
        ).encode()),
        "ArgusIssueHistory": _FakeHTTPResponse(200, json.dumps(
            {"data": {"issue": {"history": {"nodes": [],
                                            "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}
        ).encode()),
    }


def _jira_rest_rules():
    jira_issue = (
        b'{"key":"JIR-9","fields":{"summary":"Fix the export timeout",'
        b'"issuetype":{"name":"Bug","subtask":false},'
        b'"status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},'
        b'"assignee":{"accountId":"acc-amy","displayName":"Amy","accountType":"atlassian"},'
        b'"created":"2026-08-01T00:00:00.000+0000","updated":"2026-08-19T00:00:00.000+0000"}}'
    )
    return {
        "rest/api/3/project/JIR": _FakeHTTPResponse(200, b'{"key":"JIR","name":"Jirapatha"}'),
        "rest/agile/1.0/board?projectKeyOrId=JIR": _FakeHTTPResponse(
            200, b'{"values":[{"id":20,"name":"JIR board"}]}'),
        "rest/agile/1.0/board/20/sprint": _FakeHTTPResponse(200, (
            b'{"values":[{"id":701,"name":"Sprint 3","state":"active",'
            b'"startDate":"2026-08-18T00:00:00.000Z","endDate":"2026-09-01T00:00:00.000Z"}]}')),
        "rest/agile/1.0/sprint/701/issue": _FakeHTTPResponse(
            200, b'{"issues":[' + jira_issue + b']}'),
        "rest/agile/1.0/board/20/backlog": _FakeHTTPResponse(200, b'{"issues":[]}'),
        "rest/api/3/issue/JIR-9/changelog": _FakeHTTPResponse(200, b'{"histories":[]}'),
    }


def _github_rest_rules():
    """Three PRs across two repos — one linked to the Jira ticket (title
    carries JIR-9), one linked to the Linear ticket (title carries ENG-77),
    and a third with no ticket key at all, so the rehearsal also proves the
    SUPPRESSED (no_ticket_link) path shows up correctly on the dashboard
    alongside the two FIREs — a pilot's real first night is never 100%
    FIRE, and the dashboard has to be honest about the mix.
    """
    def _pr(number, title, repo, *, merged=False):
        """`merged=True` (Phase 7.4X) produces a pull request GitHub itself
        reports as merged and closed, with no live review request on it —
        the Ghost State Case A shape, driven through the real ingestion path
        rather than written into the database by hand."""
        state = "closed" if merged else "open"
        closed = '"closed_at":"2026-08-05T00:00:00Z",' if merged else ""
        issue = (
            ('{"number":%d,"title":"%s","user":{"login":"amy"},"state":"%s",'
             '"created_at":"2026-08-01T00:00:00Z","labels":[],%s'
             '"html_url":"https://github.com/pilotco/%s/pull/%d",'
             '"updated_at":"2026-08-02T00:00:00Z","pull_request":{},"assignees":[]}'
             % (number, title, state, closed, repo, number)).encode()
        )
        pr = ('{"draft":false,"merged":%s,"state":"%s","mergeable_state":"clean"}'
              % ("true" if merged else "false", state)).encode()
        timeline = (
            b'[]' if merged else
            b'[{"event":"review_requested","actor":{"login":"amy"},'
            b'"requested_reviewer":{"login":"riya"},"created_at":"2026-08-02T00:00:00Z"}]'
        )
        return {
            f"pilotco/{repo}/issues/{number}/timeline": _FakeHTTPResponse(200, timeline),
            f"pilotco/{repo}/issues/{number}/comments": _FakeHTTPResponse(200, b'[]'),
            f"pilotco/{repo}/pulls/{number}/reviews": _FakeHTTPResponse(200, b'[]'),
            f"pilotco/{repo}/pulls/{number}": _FakeHTTPResponse(200, pr),
            f"pilotco/{repo}/issues/{number}": _FakeHTTPResponse(200, issue),
        }

    rules = {
        "installation/repositories": _FakeHTTPResponse(
            200, b'{"total_count":2,"repositories":['
                 b'{"name":"widgets","full_name":"pilotco/widgets","owner":{"login":"pilotco"}},'
                 b'{"name":"gadgets","full_name":"pilotco/gadgets","owner":{"login":"pilotco"}}]}'),
        "pilotco/widgets/pulls?state=open": _FakeHTTPResponse(
            200, b'[{"number":42,"title":"x"},{"number":43,"title":"x"},'
                 b'{"number":44,"title":"x"}]'),
        "pilotco/gadgets/pulls?state=open": _FakeHTTPResponse(
            200, b'[{"number":9,"title":"x"}]'),
    }
    rules.update(_pr(42, "[JIR-9] Fix the export timeout", "widgets"))
    rules.update(_pr(43, "[ENG-77] Rework the retry queue", "widgets"))
    rules.update(_pr(9, "Tidy up the README", "gadgets"))  # no ticket key at all
    # Phase 7.4X, Task 1.4's integration case: merged on 2026-08-05, linked
    # to JIR-9 — which the Jira fixture above still reports as 'In Progress'
    # in the active Sprint 3. Ghost State Case A, end to end.
    rules.update(_pr(44, "[JIR-9] Ship the export fix", "widgets", merged=True))
    return rules


def _route_all(url_rules, graphql_rules):
    def _fake(req, timeout=None):
        if "api.linear.app/graphql" in req.full_url:
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


def _mock_network():
    url_rules = {**_github_rest_rules(), **_jira_rest_rules()}
    return (
        mock.patch.object(ingest_worker._TOKEN_CACHE, "get",
                          return_value="fake-installation-token"),
        mock.patch("urllib.request.urlopen",
                   side_effect=_route_all(url_rules, _linear_graphql_rules())),
    )


def test_one_fully_wired_fake_tenant_webhook_to_dashboard(client):
    """The rehearsal itself, start to finish:

    1. Create a tenant through the real admin API (the same call Claude
       makes onboarding a real pilot).
    2. Connect GitHub via the real install-link + setup claim flow.
    3. Configure Jira and Linear credentials via their real admin
       endpoints.
    4. A GitHub webhook — signed, POSTed to the real endpoint, exactly the
       shape GitHub's own servers send — queues the run. Nothing here
       calls run-now or hand-inserts a 'running' row.
    5. The poller's own claim function drains the queue with no tenant
       hint — the same function a real background loop tick would call.
    6. Every dashboard surface a pilot's own API key can see is checked
       over real HTTP: /v1/alerts, /v1/me, and both digest formats.
    """
    n = next(_SLUG_COUNTER)
    slug = f"rehearsal-{n}"

    # --- 1. tenant creation, the real onboarding call -----------------
    created = client.post("/v1/admin/tenants", headers=ADMIN,
                          json={"slug": slug, "display_name": "Rehearsal Pilot Co"})
    assert created.status_code == 201, created.text
    tenant = created.json()
    tenant_headers = {"Authorization": f"Bearer {tenant['api_key']}"}

    # --- 2. GitHub: install-link + setup claim -------------------------
    link = client.post(f"/v1/admin/tenants/{slug}/github/install-link", headers=ADMIN)
    assert link.status_code == 201, link.text
    installation_id = str(900000 + n)
    setup = client.get("/v1/github/setup", params={
        "installation_id": installation_id, "setup_action": "install",
        "state": link.json()["token"]})
    assert setup.status_code == 200, setup.text

    # --- 3. Jira + Linear credentials, the real admin endpoints --------
    jira_cred = client.post(f"/v1/admin/tenants/{slug}/jira/credentials", headers=ADMIN,
                            json={"base_url": "https://acme.atlassian.net", "project_key": "JIR",
                                  "email": "admin@acme.com", "api_token": "jira-tok-real"})
    assert jira_cred.status_code == 201, jira_cred.text
    linear_cred = client.post(f"/v1/admin/tenants/{slug}/linear/credentials", headers=ADMIN,
                              json={"team_key": "ENG", "api_key": "linear-key-real"})
    assert linear_cred.status_code == 201, linear_cred.text

    # --- 4. a REAL GitHub webhook, signed the way GitHub actually signs
    # it, queues the run — not admin run-now, not a hand-inserted row. ---
    payload = {
        "action": "opened", "number": 42,
        "pull_request": {"number": 42, "title": "x", "state": "open"},
        "repository": {"full_name": "pilotco/widgets"},
        "installation": {"id": int(installation_id),
                         "account": {"login": "pilotco", "type": "Organization"}},
    }
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(config.GITHUB_WEBHOOK_SECRET.encode(), body,
                               hashlib.sha256).hexdigest()
    webhook = client.post("/v1/webhooks/github", content=body, headers={
        "x-github-event": "pull_request", "x-github-delivery": f"d-rehearsal-{n}",
        "x-hub-signature-256": sig, "content-type": "application/json"})
    assert webhook.status_code == 200, webhook.text
    queued_run_id = webhook.json()["ingest_run_id"]
    assert queued_run_id is not None, "a content event must queue a run"

    with db.tenant_tx(tenant["id"]) as conn:
        pre = conn.execute("SELECT status FROM ingest_run WHERE id=%s",
                           (queued_run_id,)).fetchone()
    assert pre["status"] == "queued"

    # --- 5. the poller's own claim function, no tenant hint ------------
    token_patch, url_patch = _mock_network()
    with token_patch, url_patch:
        processed = ingest_worker.claim_and_run_one()
    assert processed is True

    with db.tenant_tx(tenant["id"]) as conn:
        run_rows = conn.execute("SELECT id, status, error_detail FROM ingest_run"
                                " WHERE tenant_id=%s", (tenant["id"],)).fetchall()
    assert len(run_rows) == 1, "the webhook's own row must be the one that finishes"
    assert run_rows[0]["id"] == queued_run_id
    assert run_rows[0]["status"] == "succeeded", run_rows[0]["error_detail"]
    assert run_rows[0]["error_detail"] is None

    # --- 6. the dashboard, over real HTTP, as a pilot's own key sees it -

    # 6a. /v1/alerts: three real rows — two FIRE (Jira-linked, Linear-
    # linked) and one SUPPRESSED (no ticket at all) — every one carrying
    # the item_key/title/url/detail fields D-160 left broken.
    alerts = client.get("/v1/alerts?limit=50", headers=tenant_headers)
    assert alerts.status_code == 200, alerts.text
    rows = alerts.json()
    assert len(rows) == 4, rows
    by_reason = {r["reason"]: r for r in rows}
    fires = [r for r in rows if r["outcome"] == "FIRE"]
    suppressed = [r for r in rows if r["outcome"] == "SUPPRESSED"]
    assert len(fires) == 3, rows
    assert len(suppressed) == 1, rows
    assert suppressed[0]["reason"] == "no_ticket_link"

    fire_keys = {r["item_key"] for r in fires}
    assert fire_keys == {"pilotco/widgets#42", "pilotco/widgets#43",
                         "pilotco/widgets#44"}, fire_keys
    # Phase 7.4X, Task 1.4: the Ghost State detector, proven on the full
    # chain — a real signed GitHub webhook, the real poller, real (mocked-
    # transport) GitHub + Jira ingestion, and the pilot's own API key
    # reading it back over HTTP. Nothing here writes a work_item or a
    # ticket_link by hand.
    ghost = [r for r in fires if r["item_key"] == "pilotco/widgets#44"][0]
    assert ghost["pattern"] == "P3-ghost-state", ghost
    assert "JIR-9" in ghost["detail"] and "In Progress" in ghost["detail"], ghost
    for r in rows:
        assert r["item_key"] and "#" in r["item_key"], r
        assert r["title"], r
        assert r["url"] and r["url"].startswith("https://github.com/"), r
        assert r["detail"], "alert.detail must carry the gate's own evidence sentence"

    # 6b. /v1/me: the human actor(s) ingestion actually saw, not a 500 on
    # a table (`person`) that never existed.
    me = client.get("/v1/me", headers=tenant_headers)
    assert me.status_code == 200, me.text
    me_body = me.json()
    assert me_body["tenant"]["slug"] == slug
    assert isinstance(me_body["members"], list) and len(me_body["members"]) >= 1
    assert any(m["source_key"] == "amy" for m in me_body["members"]), me_body["members"]

    # 6c. /v1/digests/latest?format=json: the full structured envelope,
    # counting a real 3-FIRE, 1-SUPPRESSED night correctly.
    digest_json = client.get("/v1/digests/latest?format=json", headers=tenant_headers)
    assert digest_json.status_code == 200, digest_json.text
    payload_json = digest_json.json()
    assert payload_json["tenant"]["slug"] == slug
    assert payload_json["digest"]["counts"]["fired"] == 3, payload_json["digest"]["counts"]
    assert payload_json["digest"]["counts"]["suppressed"] == 1, payload_json["digest"]["counts"]
    assert payload_json["digest"]["counts"]["items_checked"] == 4

    # Phase 7.4X, Task 3.4: the morning briefing on a live payload read back
    # over HTTP by a pilot's own key. No ARGUS_LLM_API_KEY is configured in
    # this suite, so this is the deterministic path — which is exactly the
    # path a pilot team runs on until Dirgh sets a key, and it must still be
    # a briefing rather than a missing field or a null.
    brief = payload_json["morning_briefing"]
    assert brief["source"] == "deterministic", brief
    assert brief["briefing_summary"], brief
    assert isinstance(brief["healthy_count"], int), brief

    # Milestone 2, Task 6.2: every row carries a `copilot` key (Task 5.1/5.3
    # — the field exists in the real, live-shaped payload, not just in a
    # unit test's hand-built dict). No `ARGUS_LLM_API_KEY` is configured
    # anywhere in this test environment (conftest.py never sets one), so
    # every value is `None` — the Fail-Safe Fallback Invariant, proven here
    # across the FULL multi-tenant pipeline (webhook -> ingest -> detect ->
    # digest -> HTTP), not just inside llm_copilot.py's own unit tests: a
    # missing LLM credential costs nothing, the rehearsal still completes,
    # and every alert still renders exactly as it did before this module
    # existed.
    for row in payload_json["digest"]["rows"]:
        assert "copilot" in row, row
        assert row["copilot"] is None, (
            "no ARGUS_LLM_API_KEY is configured in tests; copilot must fall back to None")

    # 6d. /v1/digests/latest (text): rendered_text present, payload_json
    # genuinely absent — the other half of this session's own dashboard
    # fix, proven the same way over real HTTP.
    digest_text = client.get("/v1/digests/latest", headers=tenant_headers)
    assert digest_text.status_code == 200, digest_text.text
    text_body = digest_text.json()
    assert "rendered_text" in text_body and text_body["rendered_text"]
    assert "payload_json" not in text_body

    # --- Shadow Mode holds throughout: a brand-new tenant is 'shadow' by
    # default, and record_phase6_run() must reflect that in the delivery
    # row even though real alert rows were written — Shadow Mode gates
    # delivery, not detection (§3.1.2 step 7 of the design). ---
    assert me_body["shadow_mode"] is True
    with db.tenant_tx(tenant["id"]) as conn:
        delivery = conn.execute(
            "SELECT status FROM digest_delivery WHERE ingest_run_id=%s",
            (queued_run_id,)).fetchone()
    assert delivery["status"] == "shadow"
