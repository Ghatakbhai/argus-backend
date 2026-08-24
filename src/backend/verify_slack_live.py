"""ARGUS Phase 7.3 — end-to-end proof over real HTTP against a real server.

The pytest suite drives FastAPI through its in-process test client. That
proves the logic. It does not prove the thing that actually breaks on
deployment day: that a real uvicorn process, reading a real request body off a
real socket, computes the same signature Slack does.

7.2 ended with exactly this kind of run (D-138) and it is worth repeating,
because the failure it catches is specific and expensive — a middleware, a
proxy, or a body-reading order that changes the bytes between the wire and
`verify_signature`. That bug is invisible to a test client and fatal in
production.

Run from `src/`, with a uvicorn serving `backend.app:app`:

    python -m backend.verify_slack_live http://127.0.0.1:8099
"""
from __future__ import annotations

import json
import sys
import time
import urllib.parse
import uuid
from typing import Any

import httpx

from . import config, slack_app, slack_crypto

PASS, FAIL = "  PASS", "  FAIL"
_results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    _results.append((ok, label))
    print(f"{PASS if ok else FAIL}  {label}{('  — ' + detail) if detail else ''}")
    return ok


def signed(client: httpx.Client, base: str, path: str, body: bytes,
           content_type: str, *, age: int = 0, break_signature: bool = False):
    ts = str(int(time.time()) - age)
    sig = slack_app.sign_request(config.SLACK_SIGNING_SECRET, body, ts)
    if break_signature:
        sig = "v0=" + "f" * 64
    return client.post(base + path, content=body, headers={
        "content-type": content_type,
        "x-slack-request-timestamp": ts,
        "x-slack-signature": sig})


def main() -> None:
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8099").rstrip("/")
    admin = {"x-admin-key": config.ADMIN_SECRET}
    slug = f"live-{uuid.uuid4().hex[:8]}"
    c = httpx.Client(timeout=20.0, follow_redirects=False)

    print(f"\nARGUS 7.3 live check against {base}\n" + "-" * 64)

    r = c.get(base + "/v1/health")
    check(r.status_code == 200 and r.json().get("phase") == "7.3",
          "service is up and reports phase 7.3", r.text[:80])

    r = c.post(base + "/v1/admin/tenants", headers=admin,
               json={"slug": slug, "display_name": "Live Check Team"})
    check(r.status_code == 201, "tenant created over HTTP", r.text[:120])
    tenant = r.json()

    r = c.post(f"{base}/v1/admin/tenants/{slug}/slack/install-link", headers=admin)
    check(r.status_code == 201, "Slack install link minted", r.text[:120])
    claim = r.json()["token"]

    r = c.get(f"{base}/v1/slack/install?state={claim}")
    loc = r.headers.get("location", "")
    check(r.status_code == 302 and "slack.com/oauth/v2/authorize" in loc,
          "install link redirects to Slack's consent screen")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    check(q.get("scope", [""])[0] == config.SLACK_BOT_SCOPES,
          "the consent screen asks for exactly the configured scopes")

    r = c.get(f"{base}/v1/slack/install?state=argus_slackclaim_bogus")
    check(r.status_code == 400 and "slack.com" not in r.text,
          "a bogus install link is stopped BEFORE anyone reaches Slack")

    # --- signature checks, the whole reason this script exists -------------
    handshake = json.dumps({"type": "url_verification", "challenge": "live-challenge"}).encode()
    r = signed(c, base, "/v1/slack/events", handshake, "application/json")
    check(r.status_code == 200 and r.json().get("challenge") == "live-challenge",
          "a genuinely signed request survives the trip over a real socket",
          r.text[:120])

    r = signed(c, base, "/v1/slack/events", handshake, "application/json",
               break_signature=True)
    check(r.status_code == 401, "a forged signature is refused")

    r = signed(c, base, "/v1/slack/events", handshake, "application/json", age=3600)
    check(r.status_code == 401 and "stale" in r.text,
          "an hour-old request is refused even though its signature is valid")

    r = c.post(base + "/v1/slack/events", json={"type": "url_verification",
                                                "challenge": "x"})
    check(r.status_code == 401, "an unsigned request is refused")

    # A body that parses identically but was signed as different bytes.
    ts = str(int(time.time()))
    sig = slack_app.sign_request(config.SLACK_SIGNING_SECRET, handshake, ts)
    r = c.post(base + "/v1/slack/events",
               content=b'{ "challenge" : "live-challenge" , "type" : "url_verification" }',
               headers={"content-type": "application/json",
                        "x-slack-request-timestamp": ts, "x-slack-signature": sig})
    check(r.status_code == 401,
          "the signature really covers the raw bytes, not the reparsed JSON")

    # --- events for a workspace nobody has installed ------------------------
    body = json.dumps({"type": "event_callback", "team_id": "T_NEVER_SEEN",
                       "event_id": "Ev_live_1",
                       "event": {"type": "app_uninstalled"}}).encode()
    r = signed(c, base, "/v1/slack/events", body, "application/json")
    check(r.status_code == 200 and r.json().get("status") == "unresolved",
          "an event from an unknown workspace is acknowledged and dropped")

    form = urllib.parse.urlencode({"payload": json.dumps(
        {"type": "block_actions", "team": {"id": "T_NEVER_SEEN"},
         "container": {"channel_id": "D1", "message_ts": "1.1"},
         "actions": [{"action_id": slack_app.ACTION_SNOOZE_7D}]})}).encode()
    r = signed(c, base, "/v1/slack/interactions", form,
               "application/x-www-form-urlencoded")
    check(r.status_code == 200,
          "an interaction from an unknown workspace gets a 200, not a red banner "
          "in someone's Slack")

    # --- encryption, exercised through the same code the callback uses -----
    sealed = slack_crypto.encrypt_token("xoxb-live-check", tenant["id"])
    check("xoxb-live-check" not in sealed
          and slack_crypto.decrypt_token(sealed, tenant["id"]) == "xoxb-live-check",
          "a bot token encrypts and decrypts under this host's own key")

    c.post(f"{base}/v1/admin/tenants/{slug}/status?new_status=offboarded", headers=admin)

    print("-" * 64)
    failed = [label for ok, label in _results if not ok]
    print(f"{len(_results) - len(failed)}/{len(_results)} checks passed")
    if failed:
        for label in failed:
            print(f"  FAILED: {label}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
