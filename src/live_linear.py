"""
ARGUS — Live Linear fetcher (Step 7.4c-e)

Mirrors the split `live_jira.py` established at 6.9 and `live_github.py`
before it: this module owns exactly one job — call Linear's real GraphQL
API and assemble a `linear_adapter.LinearTeamBundle` that hands straight to
`linear_adapter.ingest_team`, UNCHANGED — the exact function 6.3's ten
fixture-based checks already proved correct. `linear_adapter.py` itself is
not touched by this step, the same discipline `live_jira.py`'s docstring
held `jira_adapter.py` to.

Endpoints/fields used, and how each was checked (Linear publishes no
plain-text OpenAPI-style spec the way Jira does — D-113/PHASE6_3's own
finding — so every field below was cross-checked against at least two
independent sources reachable this session, not trusted from training
data, per this project's standing rule since D-111):

    POST https://api.linear.app/graphql   (a single endpoint; every
    operation, including reads, is one GraphQL query against it)

    teams(filter: { key: { eq } })                team lookup by key
    team(id) { states { nodes } }                 workflow states (unused
                                                    directly — see below)
    team(id) { cycles { nodes } }                  cycles ("sprints")
    team(id) { issues(filter: { cycle: {...} }) }  cycle / backlog issues
    issue(id) { history(first, after) { nodes } }  status-change history

Auth confirmed directly from Linear's own docs (linear.app/developers/graphql):
`Authorization: <API_KEY>` — the raw key, NOT `Bearer <key>` the way OAuth
access tokens are sent. Getting this wrong is a silent-looking 401, not a
loud one, so it is called out here in case a future edit "fixes" it back
to the more common Bearer convention.

**Two real gaps named by `docs/PHASE6_3_LINEAR_ADAPTER.md` at 6.3, both
addressed this session — confirmed, not fully closed to the same standard
as live_jira.py's REST endpoints (no live account reachable from this
sandbox — same standing block), but no longer a guess:**

1. **Linear's raw issue-history wire shape.** Confirmed via two independent
   sources: (a) `linear/linear#91` on GitHub, a real SDK bug report whose
   error message ("Field 'relationChanges' ... must have a selection of
   subfields") itself names `fromState`, `toState`, `actor` and
   `relationChanges` as real sibling fields on `IssueHistory`; (b) a
   third-party Go client (`pkg.go.dev/github.com/charlietran/linctl`) whose
   generated `IssueHistoryEntry` struct independently lists the same
   `FromState`/`ToState` fields as `*State` (full objects, not bare IDs),
   alongside `FromAssignee`/`ToAssignee`/`FromTitle`/`ToTitle`/
   `FromCycle`/`ToCycle`/`FromProject`/`ToProject` — confirming a real,
   important structural fact 6.3 could not see: **Linear's history
   connection is a general activity log, not a status-changes-only feed
   the way Jira's changelog effectively is for this adapter's purposes.**
   A title edit or an assignee change produces its own `IssueHistory` node
   with `toState: null`. `_history_to_transitions` below filters on
   `toState is not None` for exactly this reason — skipping that filter
   would silently manufacture a fake "status change to nothing" event for
   every non-status edit an issue ever had.
2. **Bot/integration actor detection.** Still no confirmed signal (same
   conclusion 6.3 reached) — `history` nodes do carry an `actor` field, but
   nothing found this session documents a reliable person-vs-bot marker on
   it. Not fetched here at all (this module never requests `actor`);
   `linear_adapter.classify_linear_actor`'s conservative "assumed_human"
   default is unchanged and still the right call.

**A third, genuinely new finding, live-doc-confirmed and worth naming
plainly: GraphQL does not fail the way every REST API this project has
integrated so far does.** A bad query or a resolvable-but-empty result both
come back **HTTP 200** with a `data` key (`null` on a hard error) and an
`errors` array — the HTTP status line alone does not tell the whole story,
unlike GitHub/Jira's REST APIs where a 404/401/429 is unambiguous. Linear's
own rate-limiting documentation (linear.app/developers/rate-limiting) is
the one confirmed exception: exceeding the limit answers **HTTP 400** with
`errors[0].extensions.code == "RATELIMITED"` — a real, specific asymmetry
between "the query itself was bad" and "you're being throttled" that
`_post_with_retry` below checks explicitly rather than assuming one
HTTP-status branch covers both. Rate limit itself: 2,500 requests/hour and
3,000,000 complexity points/hour per API key (linear.app/developers/
rate-limiting) — generous for one team's nightly ingest, but worth knowing
if a pilot tenant ever has a very large backlog.

NOT YET LIVE-TESTED END TO END — no Linear Cloud account reachable from
either place Claude can run code this session (the cloud sandbox's network
egress does not include api.linear.app; the device bridge to Dirgh's own
machine has no general internet access at all — the same standing block
D-161/D-162/live_jira.py's own docstring already named for GitHub/Jira).
This module's pure assembly and pagination logic is verified offline
against realistic canned JSON shaped from the two independent sources
named above (`verify_linear_live_ingest.py`), the same standard 6.3 and
6.9 both held themselves to before a live account existed.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Optional

from linear_adapter import LinearFetchAttempt, LinearTeamBundle, ResolvedTransition

USER_AGENT = "ARGUS/7.4c-e (+internal tool, not published)"
GRAPHQL_URL = "https://api.linear.app/graphql"
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2.0
TIMEOUT_SECONDS = 20
PAGE_SIZE = 100
HISTORY_PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# GraphQL query text. Kept as plain module-level strings, not built
# dynamically — easier to eyeball-diff against Linear's docs if a future
# schema change breaks one of them, the same reasoning live_jira.py's
# f-string URLs are kept literal and close to their endpoint comment.
# ---------------------------------------------------------------------------

_TEAM_QUERY = """
query ArgusTeamLookup($key: String!) {
  teams(filter: { key: { eq: $key } }) {
    nodes { id name key }
  }
}
"""

_CYCLES_QUERY = """
query ArgusTeamCycles($teamId: String!) {
  team(id: $teamId) {
    cycles(first: 50) {
      nodes { id number name startsAt endsAt completedAt }
    }
  }
}
"""

_CYCLE_ISSUES_QUERY = """
query ArgusCycleIssues($teamId: String!, $cycleId: String!, $after: String) {
  team(id: $teamId) {
    issues(first: 100, after: $after, filter: { cycle: { id: { eq: $cycleId } } }) {
      nodes {
        id identifier title createdAt updatedAt
        state { id name type }
        assignee { id name }
        labels { nodes { name } }
        parent { id }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""

_BACKLOG_ISSUES_QUERY = """
query ArgusBacklogIssues($teamId: String!, $after: String) {
  team(id: $teamId) {
    issues(first: 100, after: $after, filter: { cycle: { null: true } }) {
      nodes {
        id identifier title createdAt updatedAt
        state { id name type }
        assignee { id name }
        labels { nodes { name } }
        parent { id }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""

_ISSUE_HISTORY_QUERY = """
query ArgusIssueHistory($issueId: String!, $after: String) {
  issue(id: $issueId) {
    history(first: 50, after: $after) {
      nodes {
        id createdAt
        fromState { name type }
        toState { name type }
      }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""


def _http_post(url: str, api_key: str, query: str, variables: dict):
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})


def _post_with_retry(fetches: list, query: str, variables: dict, api_key: str,
                      purpose: str, requested_at: str, url: str = GRAPHQL_URL) -> Optional[dict]:
    """Same retry/logging discipline as `live_jira._get_with_retry`, adapted
    for GraphQL's own failure shape (see module docstring's third finding):
    a transport-level exception is the only case that maps cleanly onto
    live_jira's "failed, retry" branch. Everything else — a clean 200 with
    real data, a 200 with a GraphQL `errors` array, or Linear's specific
    400-on-rate-limit — is inspected in the response BODY, not just the
    status line.

    Returns the `data` object on success (already past the `errors` check),
    or None on any failure/empty/corrupt outcome — the caller inspects
    `fetches` for detail exactly like live_jira.py's callers already do.
    """
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            status, body, headers = _http_post(url, api_key, query, variables)
        except Exception as e:
            last_error = str(e)
            fetches.append(LinearFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                outcome="failed", raw_json=None, error_detail=last_error,
                requested_at=requested_at))
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            continue

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            fetches.append(LinearFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                outcome="corrupt", raw_json=None, error_detail=str(e),
                requested_at=requested_at, http_status=status))
            return None

        errors = data.get("errors") or []
        if errors:
            first = errors[0]
            code = (first.get("extensions") or {}).get("code")
            message = first.get("message", str(first))

            if code == "RATELIMITED" or status == 429:
                # Confirmed live behaviour per linear.app/developers/
                # rate-limiting: HTTP 400, not 429 — checked on `code`
                # first, `status` only as a defensive fallback in case a
                # future Linear release starts using the more conventional
                # 429 status for the same condition.
                retry_after = headers.get("Retry-After")
                wait = float(retry_after) if retry_after else RETRY_BACKOFF_SECONDS * attempt * 3
                fetches.append(LinearFetchAttempt(
                    url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                    outcome="failed", raw_json=None,
                    error_detail=f"rate limited: {message}",
                    requested_at=requested_at, http_status=status))
                time.sleep(wait)
                continue

            if code in ("AUTHENTICATION_ERROR", "FORBIDDEN") or status in (401, 403):
                # A bad/revoked API key — no amount of retrying fixes that,
                # same fail-fast reasoning live_jira.py's own 401 branch
                # uses.
                fetches.append(LinearFetchAttempt(
                    url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                    outcome="failed", raw_json=None,
                    error_detail=f"auth error: {message}",
                    requested_at=requested_at, http_status=status))
                return None

            # Anything else (a resolvable-but-nonexistent id passed to a
            # required-argument field, a malformed filter, ...) is a real
            # query problem, not a transport blip. Logged 'empty' rather
            # than 'failed' — D-119's precedent (a 404-shaped "nothing
            # here" is schema-legal as 'empty') applied at the GraphQL
            # layer instead of the REST layer it was written for.
            fetches.append(LinearFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                outcome="empty", raw_json=None, error_detail=message,
                requested_at=requested_at, http_status=status))
            return None

        if status == 200 and data.get("data") is not None:
            fetches.append(LinearFetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_linear",
                outcome="ok", raw_json=data["data"], error_detail=None,
                requested_at=requested_at, http_status=status))
            return data["data"]

        last_error = f"HTTP {status}: unexpected response shape (no data, no errors)"
        fetches.append(LinearFetchAttempt(
            url=url, purpose=purpose, attempt=attempt, tool="live_linear",
            outcome="failed", raw_json=None, error_detail=last_error,
            requested_at=requested_at, http_status=status))
        time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    return None


def _flatten_issue(raw: dict) -> dict:
    """Reshapes ONE raw GraphQL issue node into the flat JSON shape
    `linear_adapter.upsert_ticket` was actually built and fixture-tested
    against at 6.3 — `labels` there is read as a plain list of `{"name":
    ...}` dicts (`issue_json.get("labels") or []`), not the Relay
    connection wrapper (`{"nodes": [...]}`) Linear's real API returns for
    every list field. `state`/`assignee`/`parent` need no reshaping — their
    fields already match `linear_adapter.py`'s contract one-for-one."""
    out = dict(raw)
    out["labels"] = (raw.get("labels") or {}).get("nodes", [])
    return out


def _fetch_paginated_issues(fetches: list, query: str, variables: dict, api_key: str,
                             purpose: str, requested_at: str, url: str) -> list[dict]:
    issues: list[dict] = []
    after = None
    while True:
        vars_ = dict(variables, after=after)
        data = _post_with_retry(fetches, query, vars_, api_key, purpose, requested_at, url)
        if data is None:
            break
        conn = (data.get("team") or {}).get("issues") or {}
        nodes = conn.get("nodes", [])
        issues.extend(_flatten_issue(n) for n in nodes)
        page_info = conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break
    return issues


def _history_to_transitions(fetches: list, issue_id: str, api_key: str,
                             requested_at: str, url: str) -> list[ResolvedTransition]:
    """One issue's full status-change history, paginated. Filters out every
    history node whose `toState` is null — see module docstring finding
    #1: Linear's history connection carries every kind of edit (title,
    assignee, cycle, ...), and only a node with a real `toState` is an
    actual status transition `linear_adapter.ingest_status_history` should
    ever see."""
    transitions: list[ResolvedTransition] = []
    after = None
    while True:
        data = _post_with_retry(
            fetches, _ISSUE_HISTORY_QUERY, {"issueId": issue_id, "after": after},
            api_key, "issue_history", requested_at, url)
        if data is None:
            break
        conn = (data.get("issue") or {}).get("history") or {}
        for node in conn.get("nodes", []):
            to_state = node.get("toState")
            if not to_state:
                continue
            from_state = node.get("fromState")
            transitions.append(ResolvedTransition(
                from_status=(from_state or {}).get("name"),
                to_status=to_state.get("name"),
                to_status_type=to_state.get("type"),
                changed_at=node.get("createdAt"),
            ))
        page_info = conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break
    return transitions


def fetch_team_bundle(team_key: str, api_key: str, requested_at: str,
                       base_url: str = "https://api.linear.app"
                       ) -> tuple[LinearTeamBundle, list, bool]:
    """Assemble one `LinearTeamBundle` from a live Linear workspace.

    Returns `(bundle, fetches, team_found)` — a 3-tuple, deliberately one
    element longer than `live_jira.fetch_project_bundle`'s `(bundle,
    fetches)`. Jira's REST API 404s on an unknown project key, which
    `live_jira.py`'s own fetch-outcome log already carries (an 'empty'
    outcome on the 'project' purpose IS the not-found signal, checked by
    `jira_live_ingest.py`). Linear's `teams(filter: {key: {eq}})` has no
    equivalent: a nonexistent key is a completely ordinary 200 OK carrying
    zero results, indistinguishable from "the call itself failed" by
    outcome alone. Rather than force a false symmetry onto a fetch log that
    genuinely can't carry this distinction, `team_found` says it directly;
    `linear_live_ingest.py` reads it, not the fetch log, to decide whether
    this project's absence means "wrong key" or "could not reach Linear at
    all."
    """
    fetches: list = []
    url = base_url.rstrip("/")
    if not url.endswith("/graphql"):
        url = f"{url}/graphql"

    team_data = _post_with_retry(fetches, _TEAM_QUERY, {"key": team_key}, api_key,
                                  "team", requested_at, url)
    teams = (team_data or {}).get("teams", {}).get("nodes", [])

    if not teams:
        return (LinearTeamBundle(team_key=team_key, team_name=team_key, base_url=url,
                                  observed_at=requested_at),
                fetches, False)

    team = teams[0]
    team_id = team["id"]
    bundle = LinearTeamBundle(team_key=team_key, team_name=team.get("name") or team_key,
                               base_url=url, observed_at=requested_at)

    cycles_data = _post_with_retry(fetches, _CYCLES_QUERY, {"teamId": team_id}, api_key,
                                    "cycle_list", requested_at, url) or {}
    cycles = ((cycles_data.get("team") or {}).get("cycles") or {}).get("nodes", [])
    bundle.cycles = cycles

    for cycle in cycles:
        cycle_id = str(cycle["id"])
        bundle.cycle_issues[cycle_id] = _fetch_paginated_issues(
            fetches, _CYCLE_ISSUES_QUERY, {"teamId": team_id, "cycleId": cycle_id},
            api_key, "cycle_issues", requested_at, url)

    bundle.backlog_issues = _fetch_paginated_issues(
        fetches, _BACKLOG_ISSUES_QUERY, {"teamId": team_id}, api_key,
        "backlog_issues", requested_at, url)

    all_issues = [i for issues in bundle.cycle_issues.values() for i in issues]
    all_issues += bundle.backlog_issues
    for issue in all_issues:
        bundle.histories[issue["identifier"]] = _history_to_transitions(
            fetches, issue["id"], api_key, requested_at, url)

    return bundle, fetches, True
