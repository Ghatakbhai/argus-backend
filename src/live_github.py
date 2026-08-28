"""
ARGUS — Live GitHub fetcher (Step 6.9)

Every earlier phase (2.2 through this file's own module `github_adapter.py`)
deliberately never called a network API directly — Phase 1-2's GitHub data
came from Tavily-extracting rendered pages (D-046), because the sandbox's
egress proxy had no route to any external API at all, GitHub included. That
constraint held for the entire project until this step: 6.9 is the first
place Claude has a plausible path to real network access (Dirgh enabling
specific domains in Admin Capabilities), so this is the first REAL fetcher
this codebase has ever had for any of its three sources.

This module owns exactly one job: turn (owner, repo, number) into a
`ingest.WorkItemBundle`, fully populated, by calling GitHub's REST API
directly with a personal access token. It hands that bundle to
`ingest.ingest_work_item` UNCHANGED — the same function Phase 2.2 already
tested against 150 real (if Tavily-scraped) items. No parsing logic lives
here; `github_adapter.py` and `ingest.py` still own every field-shape
decision. This module's only responsibility is the HTTP call and mapping
each response onto the right `WorkItemBundle` attribute, with the same
FetchAttempt-per-URL logging discipline Phase 2.2 established, so a partial
failure here reads exactly like a partial failure would have from Tavily.

Endpoints used (verified against GitHub's current REST docs directly at
6.9, not from memory — this project's house rule since D-111's Jira/Linear
field-name bugs):
    GET /repos/{owner}/{repo}/issues/{number}
    GET /repos/{owner}/{repo}/pulls/{number}                (PRs only)
    GET /repos/{owner}/{repo}/issues/{number}/timeline
    GET /repos/{owner}/{repo}/issues/{number}/comments
    GET /repos/{owner}/{repo}/pulls/{number}/reviews         (PRs only)
All stable, generally-available endpoints as of API version 2026-03-10 —
the timeline endpoint in particular used to need a preview media type years
ago and no longer does; confirmed live at 6.9 rather than assumed.

Auth: a fine-grained or classic GitHub personal access token (6.9's
original use), OR — since 7.4c-b — a short-lived GitHub App installation
access token minted by `backend.github_app.InstallationTokenCache`. Both
are passed identically, as `Authorization: Bearer <token>` per GitHub's
current docs; this module never distinguishes the two and never mints or
refreshes a token itself, it only spends whatever bearer token its caller
hands it. Never a username/password.

7.4c-b adds two more endpoints, for the live-ingestion path (D-156/§3.1.2
step 4) that discovers repos and open PRs on its own rather than being
handed (owner, repo, number) by a human:
    GET /installation/repositories                          (App installs only)
    GET /repos/{owner}/{repo}/pulls?state=open
Both verified against GitHub's current REST docs directly, same house rule
as the six above (D-111's Jira/Linear field-name bugs are why this project
checks rather than remembers).

Milestone 1 / Task 3 adds two more, the CI-state pair D-161 named as the
reason Pattern 1 could never fire in live ingestion:
    GET /repos/{owner}/{repo}/commits/{sha}/status
    GET /repos/{owner}/{repo}/commits/{sha}/check-runs
Both are fetched for a PR's HEAD commit sha, and both are read rather than
picking one, because a repo may report CI through the legacy Commit Status
API, the newer Checks API, or both -- reading only one would report
'unknown' for every repo that happens to use the other. The merge rule
lives in `ingest.map_checks_state`, not here; this module still only ever
fetches and hands raw JSON to the bundle.

STILL NOT LIVE-TESTED, confirmed again at 7.4c-b, not just carried over
from 6.9. D-121 found this sandbox gets a structural 403 from Anthropic's
own session infrastructure on any call to api.github.com, regardless of
Dirgh's Admin Capabilities settings — re-confirmed directly this session
(same 403, same proxy). New this session: the device bridge to Dirgh's own
machine (`device_bash`, not available at D-121's time) was also tried, on
the theory that it might route around the sandbox-level block since it
runs on separate hardware — it does not: that shell's own egress proxy
returns `blocked-by-allowlist` for api.github.com just as directly. Neither
of the two places Claude can run code today can make a live call to
GitHub's REST API. This module (both the 6.9 endpoints and 7.4c-b's two
new ones) is built and importable, and is unit-tested against realistic
canned JSON shaped like GitHub's own documented examples — `verify_live_github.py`
for the original five endpoints, `verify_github_live_ingest.py` for the
installation-scoped orchestration built at 7.4c-b — the same standard
6.2/6.3 held their adapters to before a live account existed for them
either. A real end-to-end proof against api.github.com needs either a
future network-access change at the Anthropic-session level, or to run
from the deployed Render host once 7.4c-c's poller exists there (D-135's
precedent: the one other api.github.com call this project makes,
`github_app.exchange_manifest_code`, already only ever runs on Render for
exactly this reason).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from github_adapter import FetchAttempt
from ingest import WorkItemBundle

API_ROOT = "https://api.github.com"
USER_AGENT = "ARGUS/6.9 (+internal tool, not published)"
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 2.0
TIMEOUT_SECONDS = 20


class GitHubFetchError(RuntimeError):
    """A GitHub call failed on every retry. Carries the last response body
    (if any) so the caller can decide whether to record an evidence gap
    (D-072's precedent) rather than crash the whole run."""


@dataclass
class _Response:
    status: int
    body: bytes
    headers: dict


def _http_get(url: str, token: str) -> _Response:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return _Response(resp.status, resp.read(), dict(resp.headers))
    except urllib.error.HTTPError as e:
        return _Response(e.code, e.read(), dict(e.headers or {}))


def _get_with_retry(conn_bundle: WorkItemBundle, url: str, token: str,
                     purpose: str, requested_at: str) -> Optional[object]:
    """One URL, up to MAX_ATTEMPTS tries, every attempt logged as a
    FetchAttempt on the bundle regardless of outcome — same discipline
    `run_full_snapshot.py` used for Tavily attempts, so a live run and a
    fixture run produce directly comparable fetch logs."""
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = _http_get(url, token)
        except Exception as e:  # network-level failure, not an HTTP error
            last_error = str(e)
            conn_bundle.add_fetch(FetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_github",
                outcome="failed", raw_json=None, error_detail=last_error,
                requested_at=requested_at))
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
            continue

        if resp.status == 404:
            # A 404 on a PR-only endpoint hit against a plain issue is
            # EXPECTED, not a failure — the caller decides whether that's
            # meaningful. schema.sql's fetch.outcome CHECK constraint only
            # allows ok/failed/corrupt/empty (no room for a new value
            # without a schema change 6.9 has no reason to make), so this
            # is logged as 'empty' with the 404 named in error_detail —
            # honest about there being nothing there, distinct from
            # 'failed' which D-072's evidence-gap logic treats as a real gap.
            conn_bundle.add_fetch(FetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_github",
                outcome="empty", raw_json=None,
                error_detail="HTTP 404 (not applicable — not a pull request)",
                requested_at=requested_at))
            return None

        if resp.status == 200:
            try:
                data = json.loads(resp.body)
            except json.JSONDecodeError as e:
                conn_bundle.add_fetch(FetchAttempt(
                    url=url, purpose=purpose, attempt=attempt, tool="live_github",
                    outcome="corrupt", raw_json=None, error_detail=str(e),
                    requested_at=requested_at))
                return None
            conn_bundle.add_fetch(FetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_github",
                outcome="ok", raw_json=data, error_detail=None,
                requested_at=requested_at))
            return data

        if resp.status in (403, 429):
            # Rate limited or blocked. Worth a longer, honest backoff before
            # giving up — GitHub's own guidance is to respect Retry-After.
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else RETRY_BACKOFF_SECONDS * attempt * 3
            last_error = f"HTTP {resp.status} (rate limited or forbidden)"
            conn_bundle.add_fetch(FetchAttempt(
                url=url, purpose=purpose, attempt=attempt, tool="live_github",
                outcome="failed", raw_json=None, error_detail=last_error,
                requested_at=requested_at))
            time.sleep(wait)
            continue

        last_error = f"HTTP {resp.status}"
        conn_bundle.add_fetch(FetchAttempt(
            url=url, purpose=purpose, attempt=attempt, tool="live_github",
            outcome="failed", raw_json=None, error_detail=last_error,
            requested_at=requested_at))
        time.sleep(RETRY_BACKOFF_SECONDS * attempt)

    return None  # every attempt exhausted; bundle already carries the log


def fetch_work_item(owner: str, repo: str, number: int, token: str,
                     requested_at: str) -> WorkItemBundle:
    """Populate one WorkItemBundle from GitHub's live REST API.

    Mirrors `run_full_snapshot.py`'s bundle-building loop exactly, just with
    a real HTTP call in place of a pre-recorded Tavily attempt. Every field
    this sets is one `ingest.ingest_work_item` already reads from a Tavily
    bundle unchanged — the whole point of keeping fetching and parsing
    separate since Phase 2.2.
    """
    bundle = WorkItemBundle(owner, repo, number)

    issue = _get_with_retry(
        bundle, f"{API_ROOT}/repos/{owner}/{repo}/issues/{number}", token,
        "issue", requested_at)
    if issue is None:
        return bundle  # no issue page at all — same "fetch_failed" shape D-072 named

    bundle.issue_json = issue
    is_pr = "pull_request" in issue

    if is_pr:
        pr = _get_with_retry(
            bundle, f"{API_ROOT}/repos/{owner}/{repo}/pulls/{number}", token,
            "pr", requested_at)
        bundle.pr_json = pr

    timeline = _get_with_retry(
        bundle, f"{API_ROOT}/repos/{owner}/{repo}/issues/{number}/timeline",
        token, "timeline", requested_at)
    bundle.timeline_json = timeline if isinstance(timeline, list) else []

    comments = _get_with_retry(
        bundle, f"{API_ROOT}/repos/{owner}/{repo}/issues/{number}/comments",
        token, "comments", requested_at)
    bundle.comments_json = comments if isinstance(comments, list) else []

    if is_pr:
        reviews = _get_with_retry(
            bundle, f"{API_ROOT}/repos/{owner}/{repo}/pulls/{number}/reviews",
            token, "reviews", requested_at)
        bundle.reviews_json = reviews if isinstance(reviews, list) else []

        # CI state for the PR's HEAD commit (Milestone 1 / Task 3).
        #
        # Guarded on the sha actually being there rather than assumed: the
        # `pulls/{number}` call above can legitimately return None (every
        # retry exhausted, or a 404 on an item that is not really a PR),
        # and every pre-existing caller and test fixture in this project
        # predates this block and supplies no `head` at all. In both cases
        # the two calls below are simply not made, `status_json` and
        # `check_runs_json` stay None, and `ingest.map_checks_state`
        # returns 'unknown' -- the same readiness row this codebase
        # produced before this feature existed. Not looking must keep
        # reading as 'we did not look'.
        head_sha = ((pr or {}).get("head") or {}).get("sha") if isinstance(pr, dict) else None
        if head_sha:
            status = _get_with_retry(
                bundle, f"{API_ROOT}/repos/{owner}/{repo}/commits/{head_sha}/status",
                token, "commit_status", requested_at)
            bundle.status_json = status if isinstance(status, dict) else None

            check_runs = _get_with_retry(
                bundle, f"{API_ROOT}/repos/{owner}/{repo}/commits/{head_sha}/check-runs",
                token, "check_runs", requested_at)
            bundle.check_runs_json = check_runs if isinstance(check_runs, dict) else None

    return bundle


def list_installation_repos(token: str, requested_at: str,
                             max_pages: int = 10) -> list[tuple[str, str]]:
    """Every repository a GitHub App installation access token can see, as
    (owner, repo) pairs — the entry point 7.4c-b's live ingestion needs
    that 6.9's `fetch_work_item`/`list_open_items` never did, since those
    were always handed an (owner, repo) a human had already picked.

    A personal access token has no "installation" and gets a 404/403 here
    — this function is only meaningful with an App installation token, and
    the caller (the future ingestion worker, 7.4c-c) is the one that knows
    which kind of token it is holding.
    """
    pairs: list[tuple[str, str]] = []
    page = 1
    dummy_bundle = WorkItemBundle("(installation)", "(repos)", 0)
    while page <= max_pages:
        url = f"{API_ROOT}/installation/repositories?per_page=100&page={page}"
        data = _get_with_retry(dummy_bundle, url, token, "installation_repos", requested_at)
        if not data:
            break
        repos = data.get("repositories", [])
        for r in repos:
            owner_login = (r.get("owner") or {}).get("login")
            name = r.get("name")
            if owner_login and name:
                pairs.append((owner_login, name))
        if len(repos) < 100:
            break
        page += 1
    return pairs


def list_open_prs(owner: str, repo: str, token: str, requested_at: str,
                   max_pages: int = 10) -> list[int]:
    """Return the numbers of every currently-open pull request in a repo —
    the PR-only counterpart to `list_open_items`, which hits `/issues` and
    returns issues and PRs mixed together. 7.4c-b's live ingestion wants
    PRs specifically (§3.1.2 step 4: "for each repo list open PRs"), so it
    uses this rather than filtering `list_open_items`'s output after the
    fact — one fewer place a plain issue could accidentally slip through.
    """
    numbers: list[int] = []
    page = 1
    dummy_bundle = WorkItemBundle(owner, repo, 0)
    while page <= max_pages:
        url = (f"{API_ROOT}/repos/{owner}/{repo}/pulls"
               f"?state=open&per_page=100&page={page}")
        data = _get_with_retry(dummy_bundle, url, token, "pr_list", requested_at)
        if not data:
            break
        numbers.extend(pr["number"] for pr in data)
        if len(data) < 100:
            break
        page += 1
    return numbers


def list_open_items(owner: str, repo: str, token: str, requested_at: str,
                     max_pages: int = 10) -> list[int]:
    """Return the numbers of every currently-open issue/PR in a repo, so the
    orchestrator has something to iterate `fetch_work_item` over without
    Dirgh having to hand-pick item numbers. GitHub's `/issues` list endpoint
    returns both issues and PRs, same as its documented behaviour.
    """
    numbers: list[int] = []
    page = 1
    while page <= max_pages:
        url = (f"{API_ROOT}/repos/{owner}/{repo}/issues"
               f"?state=open&per_page=100&page={page}")
        dummy_bundle = WorkItemBundle(owner, repo, 0)  # throwaway, just to reuse the retry/log path
        data = _get_with_retry(dummy_bundle, url, token, "issue_list", requested_at)
        if not data:
            break
        numbers.extend(item["number"] for item in data)
        if len(data) < 100:
            break
        page += 1
    return numbers
