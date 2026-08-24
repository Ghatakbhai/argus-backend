"""ARGUS Phase 7.2 — the GitHub App itself: manifest, JWTs, installation
tokens, and webhook signature verification.

Three separate credentials meet in this file and are kept conceptually
distinct throughout, because confusing them is the classic GitHub App bug:

  - The App's own identity (`GITHUB_APP_ID` + its private key) proves
    "requests from ARGUS-the-App" and is used to mint short-lived JWTs.
  - An installation access token proves "ARGUS, acting on the repos ONE
    pilot team installed it on" — minted per-installation, per-hour, using
    the App JWT above. This is what replaces a personal access token.
  - The webhook secret proves "this HTTP request really came from GitHub",
    checked via HMAC-SHA256 over the raw request body (`verify_signature`).

None of these are tenant data. They live in environment variables on the
host (see config.py) and this module is the only place that reads them.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from . import config

GITHUB_API = "https://api.github.com"
CLAIM_NAMESPACE = "argus_claim_"


class GitHubAppNotConfigured(RuntimeError):
    """Raised when a GitHub-App-dependent call is made before the manifest
    flow (step 7.2's `/v1/admin/github/callback`) has ever completed."""


# ---------------------------------------------------------------------------
# 1. The App manifest — what step 7.2 hands to GitHub to create the App.
# ---------------------------------------------------------------------------

def build_manifest(base_url: str) -> dict[str, Any]:
    """The JSON manifest for GitHub's App-creation flow.

    `base_url` is the backend's own public URL (e.g. the Render address) —
    it does not exist until step 7.2's hosting is stood up, which is why
    this is a function and not a static file: the same manifest cannot be
    correct before and after that URL is known.

    Permissions and events are deliberately the minimum that lets ARGUS read
    what `sprint_filter.py`/`detectors.py` already need and nothing more —
    ARGUS reads, it never comments, closes, merges or assigns (a rule carried
    over unchanged from Part I's original scope).
    """
    base_url = base_url.rstrip("/")
    return {
        "name": "ARGUS Stall Radar",
        # GitHub's own confirmation page links this as the App's homepage.
        # A guessed github.com/apps/... slug would 404 until the App exists
        # (if it ever resolves at all) — the backend's own real, live URL is
        # correct immediately and always.
        "url": base_url,
        "hook_attributes": {"url": f"{base_url}/v1/webhooks/github"},
        "redirect_url": f"{base_url}/v1/admin/github/callback",
        "setup_url": f"{base_url}/v1/github/setup",
        "setup_on_update": True,
        "public": False,  # one pilot program's App, not a public marketplace listing (yet)
        "default_permissions": {
            "contents": "read",
            "issues": "read",
            "pull_requests": "read",
            "metadata": "read",
        },
        "default_events": [
            "issues",
            "issue_comment",
            "pull_request",
            "pull_request_review",
            "pull_request_review_comment",
        ],
    }


# ---------------------------------------------------------------------------
# 2. Webhook signature verification (HMAC-SHA256 over the RAW body).
# ---------------------------------------------------------------------------

def verify_signature(secret: str, raw_body: bytes, signature_header: str | None) -> bool:
    """True iff `signature_header` (the `X-Hub-Signature-256` header value)
    is a valid HMAC-SHA256 of `raw_body` keyed by `secret`.

    Must run against the exact bytes GitHub sent — re-serializing the parsed
    JSON before checking is a real, easy-to-make bug, since whitespace or key
    ordering differences change the signature. Callers are responsible for
    reading the body before FastAPI (or anything else) touches it as JSON.
    """
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    provided = signature_header.split("=", 1)[1]
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided)


# ---------------------------------------------------------------------------
# 3. The App's own JWT — proves "this is ARGUS the App", not any installation.
# ---------------------------------------------------------------------------

def make_app_jwt(*, now: int | None = None) -> str:
    """A short-lived (10 minute) RS256 JWT identifying the App itself, per
    GitHub's documented App-authentication scheme. `iat` is backdated by 60
    seconds, which is GitHub's own recommended guard against clock drift
    between this host and GitHub's — a JWT that looks like it was issued in
    the future is rejected outright.
    """
    if not config.GITHUB_APP_ID or not config.GITHUB_APP_PRIVATE_KEY_PEM:
        raise GitHubAppNotConfigured(
            "ARGUS_GITHUB_APP_ID / ARGUS_GITHUB_APP_PRIVATE_KEY not set — "
            "the manifest flow (/v1/admin/github/callback) has not completed yet."
        )
    now = int(time.time()) if now is None else now
    payload = {"iat": now - 60, "exp": now + 600, "iss": config.GITHUB_APP_ID}
    return jwt.encode(payload, config.GITHUB_APP_PRIVATE_KEY_PEM, algorithm="RS256")


# ---------------------------------------------------------------------------
# 4. Installation access tokens — what ARGUS actually calls the GitHub API
#    with, scoped to exactly the repos one pilot team installed it on.
# ---------------------------------------------------------------------------

@dataclass
class _CachedToken:
    token: str
    expires_at: float  # unix seconds


class InstallationTokenCache:
    """One cache entry per installation. GitHub tokens last one hour; this
    refreshes a little early (5 minute margin) rather than racing the clock.

    NOTE ON DEPLOYMENT: this cache is in-process memory. That is correct for
    a single Render web service instance (Phase 7.2's target); it would need
    to move to something shared (Postgres, Redis) the day ARGUS runs more
    than one backend process at once. Named here so it isn't rediscovered
    the hard way later.
    """

    def __init__(self, client: httpx.Client | None = None):
        self._cache: dict[str, _CachedToken] = {}
        self._client = client or httpx.Client(timeout=10.0)

    def get(self, installation_id: str) -> str:
        cached = self._cache.get(installation_id)
        if cached and cached.expires_at - 300 > time.time():
            return cached.token
        token, expires_at = self._fetch(installation_id)
        self._cache[installation_id] = _CachedToken(token, expires_at)
        return token

    def _fetch(self, installation_id: str) -> tuple[str, float]:
        app_jwt = make_app_jwt()
        resp = self._client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        resp.raise_for_status()
        body = resp.json()
        expires_at = time.mktime(time.strptime(body["expires_at"], "%Y-%m-%dT%H:%M:%SZ"))
        return body["token"], expires_at

    def invalidate(self, installation_id: str) -> None:
        self._cache.pop(installation_id, None)


# ---------------------------------------------------------------------------
# 5. The manifest-conversion exchange — the ONE api.github.com call the
#    /v1/admin/github/callback endpoint makes, and the only place in this
#    whole flow where a `code` GitHub hands back becomes real credentials.
# ---------------------------------------------------------------------------

def exchange_manifest_code(code: str, client: httpx.Client | None = None) -> dict[str, Any]:
    """POSTs to GitHub's manifest-conversion endpoint and returns the created
    App's credentials: id, slug, client_id, client_secret, webhook_secret,
    pem (the private key). This is a one-time, one-shot exchange — the `code`
    is single-use and GitHub invalidates it immediately after this call.

    This call runs wherever the deployed backend runs (Render, once step 7.2
    is deployed there) — NOT from Claude's own sandbox, which has no route to
    api.github.com at all (see docs/PHASE7_1_MULTITENANT_BACKEND.md /
    context/DECISIONS.md D-121). Ordering the plan so this exchange happens
    on the already-deployed host is what makes that standing constraint a
    non-issue for this step.
    """
    client = client or httpx.Client(timeout=10.0)
    resp = client.post(
        f"{GITHUB_API}/app-manifests/{code}/conversions",
        headers={"Accept": "application/vnd.github+json"},
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# 6. Install-claim tokens — the one-time link between "an admin created a
#    tenant" and "GitHub tells us an installation_id belongs to it".
# ---------------------------------------------------------------------------

def generate_claim_token() -> tuple[str, str]:
    """Returns (plaintext, sha256-hex). Same shape as auth.generate_key,
    deliberately: a claim token is a bearer secret with the same handling
    rules, even though its lifetime and purpose differ."""
    plaintext = CLAIM_NAMESPACE + secrets.token_urlsafe(24)
    return plaintext, hash_claim_token(plaintext)


def hash_claim_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def install_url(state_token: str) -> str:
    """The link Claude sends a pilot contact: GitHub's own installation page
    for this App, carrying our claim token through as `state` so the
    `/v1/github/setup` redirect can tell us who just installed."""
    if not config.GITHUB_APP_SLUG:
        raise GitHubAppNotConfigured("ARGUS_GITHUB_APP_SLUG not set")
    return f"https://github.com/apps/{config.GITHUB_APP_SLUG}/installations/new?state={state_token}"
