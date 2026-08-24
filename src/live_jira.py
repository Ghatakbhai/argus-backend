"""
ARGUS — Live Jira fetcher (Step 6.9)

`jira_adapter.py` was built at 6.2 as a pure translator by design (D-111):
this sandbox couldn't reach Atlassian's API at all back then, so it only
ever consumed already-fetched JSON, and it still does — nothing in that
file changes here. This module owns exactly one job, the same split
`live_github.py` established a few hours earlier in this same session: call
Jira Cloud's real REST/Agile APIs and assemble a `jira_adapter.JiraProjectBundle`
that hands straight to `jira_adapter.ingest_project`, UNCHANGED — the exact
function 6.2's ten fixture-based checks already proved correct.

Endpoints used, and why each one was checked against CURRENT documentation
rather than trusted from training data (this project's rule since D-111's
Jira field-name bugs, sharpened further by what this module's own research
just caught):

    GET /rest/api/3/project/{key}                     project metadata
    GET /rest/agile/1.0/board?projectKeyOrId={key}     boards for the project
    GET /rest/agile/1.0/board/{id}/sprint              sprints on a board
    GET /rest/agile/1.0/sprint/{id}/issue              issues in one sprint
    GET /rest/agile/1.0/board/{id}/backlog             backlog issues
    GET /rest/api/3/issue/{key}/changelog              one ticket's status history
    GET /rest/api/3/search/jql?jql=...                 fallback bulk issue search

**A real, live catch worth recording plainly.** `GET /rest/api/3/search`
— the endpoint every piece of Jira-integration code written before roughly
2025 uses, the one training data would confidently reach for — now returns
HTTP 410 Gone. Atlassian deprecated and removed it in favour of
`/rest/api/3/search/jql`, with token-based pagination
(`nextPageToken`) replacing the old `startAt` offset. Caught by checking
Atlassian's current developer community documentation directly during 6.9,
not assumed. This is exactly the failure mode D-111 was written to guard
against, just one step later in the project than the two bugs D-111
actually caught. The Agile API endpoints above (board/sprint/backlog) were
separately confirmed still current and unaffected by that deprecation.

Auth: HTTP Basic, `email:api_token`, standard for Jira Cloud (never OAuth
for this kind of server-to-server use). Read by the caller from
`ARGUS_JIRA_EMAIL` / `ARGUS_JIRA_API_TOKEN` / `ARGUS_JIRA_BASE_URL`
environment variables — never hardcoded here.

NOT YET LIVE-TESTED END TO END. A live auth probe against Dirgh's own site
during 6.9 returned HTTP 401 (`X-Seraph-Loginreason: AUTHENTICATED_FAILED`)
— a real credential problem on the account side, not a bug in this module
or a network block (network access itself is confirmed working this
session — see the Slack `auth.test` proof in DECISIONS.md D-120). This
module's pure assembly logic (`_build_bundle`) is verified offline against
realistic canned JSON shaped exactly like Jira's own documented examples,
same standard 6.2 held itself to before a live account existed at all.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from jira_adapter import JiraFetchAttempt, JiraProjectBundle

USER_AGENT = "ARGUS/6.9 (+internal tool, not published)"
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2.0
TIMEOUT_SECONDS = 20


def _auth_header(email: str, token: str) -> str:
    import base64
    return "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()


def _http_get(url: str, email: str, token: str):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": _auth_header(email, token),
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})


def _get_with_retry(fetches: list, url: str, email: str, token: str,
                     purpose: str, requested_at: str) -> Optional[object]:
    """Same retry/logging discipline as live_github.py's `_get_with_retry`,
    adapted for `JiraFetchAttempt` (its `outcome` enum is identical:
    ok/failed/corrupt/empty — see schema.sql's shared `fetch.outcome`
    CHECK, D-119's finding). `fetches` is a plain list the caller owns,
    since JiraProjectBundle (unlike WorkItemBundle) has no `add_fetch`
    method of its own — bundle assembly and fetch logging are kept
    separate here on purpose, so `_build_bundle` (below) stays a pure
    function even though fetching is not.
    """
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            status, body, headers = _http_get(url, email, token)
        except Exception as e:
            last_error = str(e)
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="failed", raw_json=None, error_detail=last_error,
                requested_at=requested_at))
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            continue

        if status == 200:
            try:
                data = json.loads(body)
            except json.JSONDecodeError as e:
                fetches.append(JiraFetchAttempt(
                    url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                    outcome="corrupt", raw_json=None, error_detail=str(e),
                    requested_at=requested_at))
                return None
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="ok", raw_json=data, error_detail=None,
                requested_at=requested_at, http_status=status))
            return data

        if status == 404:
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="empty", raw_json=None, error_detail="HTTP 404",
                requested_at=requested_at, http_status=status))
            return None

        if status == 400:
            # A live catch from 6.9's own real run against Dirgh's site:
            # a "simple"/team-managed board (Jira's default for a newly
            # created project — exactly what a first-time Jira user gets)
            # returns 400 "The board does not support sprints" /
            # "Backlogs are not supported on this board" for the classic
            # Agile-API sprint/backlog endpoints. That's not a transient
            # fault retrying would fix, and it's not really a failure
            # either — it's a real, common board shape this fetcher must
            # handle, not error past. Logged as 'empty' (schema-legal, see
            # D-119's 404 precedent) with Jira's own message preserved, one
            # attempt only. `fetch_project_bundle` below falls back to a
            # JQL search when this happens for every board on the project.
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="empty", raw_json=None,
                error_detail=f"HTTP 400 (unsupported on this board type): {body[:200]!r}",
                requested_at=requested_at, http_status=status))
            return None

        if status == 410:
            # Gone — a deprecated/removed endpoint, not a transient error.
            # Retrying would never help; fail loudly and immediately rather
            # than burn three attempts on something that can't recover.
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="failed", raw_json=None,
                error_detail=f"HTTP 410 Gone (endpoint removed by Atlassian): {body[:200]!r}",
                requested_at=requested_at, http_status=status))
            return None

        if status in (401, 403, 429):
            retry_after = headers.get("Retry-After")
            wait = float(retry_after) if retry_after else RETRY_BACKOFF_SECONDS * attempt * 3
            last_error = f"HTTP {status}: {body[:200]!r}"
            fetches.append(JiraFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_jira",
                outcome="failed", raw_json=None, error_detail=last_error,
                requested_at=requested_at, http_status=status))
            if status == 401:
                # Credentials themselves are wrong — no amount of waiting
                # fixes that. Fail fast rather than burn all 3 attempts.
                return None
            time.sleep(wait)
            continue

        last_error = f"HTTP {status}"
        fetches.append(JiraFetchAttempt(
            url=url, purpose=purpose, attempt=attempt, tool="live_jira",
            outcome="failed", raw_json=None, error_detail=last_error,
            requested_at=requested_at, http_status=status))
        time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    return None


def fetch_project_bundle(base_url: str, project_key: str, email: str, token: str,
                          requested_at: str) -> tuple[JiraProjectBundle, list]:
    """Assemble one JiraProjectBundle from a live Jira Cloud site.

    Returns (bundle, fetches) — fetches is the flat FetchAttempt-style log
    for every call made, so the caller can write it to `fetch` the same
    way `run_full_snapshot.py` does for GitHub, and so a caller can detect
    "everything failed" (e.g. bad credentials) without inspecting bundle
    internals.
    """
    fetches: list = []
    base_url = base_url.rstrip("/")

    proj = _get_with_retry(fetches, f"{base_url}/rest/api/3/project/{project_key}",
                            email, token, "project", requested_at)
    project_name = (proj or {}).get("name", project_key)

    bundle = JiraProjectBundle(project_key=project_key, project_name=project_name,
                                base_url=base_url, observed_at=requested_at)

    if proj is None:
        # Can't even see the project — almost certainly a credentials or
        # project-key problem. Return the empty bundle with the fetch log
        # intact so the caller can report exactly what failed, rather than
        # raising and losing that detail.
        return bundle, fetches

    boards_url = (f"{base_url}/rest/agile/1.0/board"
                  f"?projectKeyOrId={urllib.parse.quote(project_key)}")
    boards = _get_with_retry(fetches, boards_url, email, token, "board_list", requested_at) or {}
    board_ids = [b["id"] for b in boards.get("values", [])]

    for board_id in board_ids:
        sprints = _get_with_retry(
            fetches, f"{base_url}/rest/agile/1.0/board/{board_id}/sprint",
            email, token, "sprint_list", requested_at) or {}
        for sprint in sprints.get("values", []):
            bundle.sprints.append(sprint)
            sprint_id = str(sprint["id"])
            issues = _get_with_retry(
                fetches, f"{base_url}/rest/agile/1.0/sprint/{sprint_id}/issue",
                email, token, "sprint_issues", requested_at) or {}
            bundle.sprint_issues[sprint_id] = issues.get("issues", [])

        backlog = _get_with_retry(
            fetches, f"{base_url}/rest/agile/1.0/board/{board_id}/backlog",
            email, token, "backlog_issues", requested_at) or {}
        bundle.backlog_issues.extend(backlog.get("issues", []))

    if not bundle.sprints and not bundle.backlog_issues and board_ids:
        # Every board on this project rejected the Agile-API sprint/backlog
        # calls (the "simple"/team-managed board case named above) — fall
        # back to a plain JQL search so a real ticket still gets ingested
        # rather than an honest-but-useless empty bundle. Every ticket
        # found this way has no sprint (sprint_id stays NULL downstream),
        # which is schema-legal and matches how `jira_adapter.py` already
        # treats "no sprint" tickets (D-111's backlog design).
        issues, jql_fetches = search_jql(base_url, f"project = {project_key}",
                                          email, token, requested_at)
        fetches.extend(jql_fetches)
        bundle.backlog_issues.extend(issues)

    all_issue_keys = {i["key"] for issues in bundle.sprint_issues.values() for i in issues}
    all_issue_keys |= {i["key"] for i in bundle.backlog_issues}

    for key in sorted(all_issue_keys):
        changelog = _get_with_retry(
            fetches, f"{base_url}/rest/api/3/issue/{key}/changelog",
            email, token, "changelog", requested_at)
        if changelog is not None:
            bundle.changelogs[key] = changelog

    return bundle, fetches


# Everything `jira_adapter.upsert_ticket`/`map_ticket_type`/`propose_status_category`
# actually read off an issue's `fields` object — requested explicitly below.
# A second live catch, found running this against Dirgh's real site at 6.9:
# the new `/search/jql` endpoint returns bare `{"id": ...}` per issue with
# NO `key` and NO `fields` unless `fields=` is passed explicitly — a much
# more minimal default than the old `/search` endpoint ever had. Silently
# omitting this parameter doesn't fail loudly; it just quietly ingests
# nothing (every issue lacks the "key" `jira_adapter.upsert_ticket` requires),
# exactly the kind of "looks fine, is wrong" failure this project's house
# rule about checking current docs exists to catch.
_SEARCH_FIELDS = "summary,issuetype,status,assignee,created,updated"


def search_jql(base_url: str, jql: str, email: str, token: str,
                requested_at: str, max_results: int = 100) -> tuple[list, list]:
    """Fallback bulk issue search via the CURRENT endpoint
    (`/rest/api/3/search/jql` — the old `/rest/api/3/search` returns HTTP
    410 Gone as of this session's check, see module docstring). Not used by
    `fetch_project_bundle` above (which gets its issues from board/sprint
    membership per D-111's design note) UNLESS every board on the project
    rejects the Agile-API sprint/backlog calls (a "simple"/team-managed
    board, confirmed live at 6.9 — see the 400-handling note above), in
    which case this is the fallback that still gets real tickets ingested.
    """
    fetches: list = []
    base_url = base_url.rstrip("/")
    all_issues: list = []
    next_token = None
    while True:
        q = (f"jql={urllib.parse.quote(jql)}&maxResults={max_results}"
             f"&fields={urllib.parse.quote(_SEARCH_FIELDS)}")
        if next_token:
            q += f"&nextPageToken={urllib.parse.quote(next_token)}"
        data = _get_with_retry(fetches, f"{base_url}/rest/api/3/search/jql?{q}",
                                email, token, "ticket_search", requested_at)
        if data is None:
            break
        all_issues.extend(data.get("issues", []))
        next_token = data.get("nextPageToken")
        if not next_token:
            break
    return all_issues, fetches
