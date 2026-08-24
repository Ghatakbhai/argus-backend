"""ARGUS Phase 7.3 — the Slack app as a multi-workspace install.

WHAT CHANGED FROM PHASE 6, AND WHY.

Step 6.5 gave ARGUS a Slack identity the only way that made sense at the
time: Dirgh created one app, installed it into one workspace by hand, and
saved three secrets into files on his own laptop. Step 6.6 then read the bot
token out of a file and talked to Slack over **Socket Mode** — a private
outbound connection Slack offers precisely so that an app with no public
server can still receive button clicks. That was the right call in August,
when ARGUS had no server at all.

It does not survive fifteen pilot teams, for two independent reasons:

  1. Socket Mode is not available to a distributed (multi-workspace) Slack
     app. Distribution requires public Request URLs. So the transport had to
     change the moment the pilot did (D-140).
  2. There is one bot token per workspace, issued by Slack at install time.
     Fifteen tokens cannot live in files on a laptop that is not the server.

7.2 removed the blocker for (1) by putting ARGUS on a public URL, and this
module is what fills it in:

  * `oauth_authorize_url` / `exchange_oauth_code` — Slack's OAuth v2
    "add to Slack" flow, carrying an ARGUS install-claim token through as
    `state` so a workspace is bound to exactly one tenant without ever being
    asked to name one (the same construction 7.2 used for GitHub, D-134).
  * `verify_signature` — Slack's own request signing, checked against the RAW
    body, with a replay window. This is what replaces Socket Mode's implicit
    trust.
  * `TenantSlackTransport` — one Slack client per tenant, decrypting that
    tenant's own workspace token on demand.
  * `handle_interaction` — the Postgres port of Phase 6's button/modal
    handling, unchanged in behaviour and deliberately so.

NOTHING IN `src/slack_triage.py` WAS EDITED. Phase 6's engine still runs on
SQLite exactly as it did, the same way 7.1 left the detectors alone. The
constants below are re-declared rather than imported for that reason — and
`test_slack_app.py` reads `slack_triage.py` and asserts every one of them
still matches, so the copy cannot drift silently (D-146).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from . import config, slack_crypto

SLACK_API_BASE = "https://slack.com/api/"
SLACK_AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
CLAIM_NAMESPACE = "argus_slackclaim_"

# --- Constants mirrored from src/slack_triage.py (Phase 6.6) ---------------
# Changing one of these without changing the other means a live button stops
# being recognised. test_slack_app.py asserts they match.
CALLBACK_BLOCKED_ON = "argus_blocked_on_modal"
ACTION_HANDLED_OFFLINE = "argus_handled_offline"
ACTION_BLOCKED_ON = "argus_blocked_on"
ACTION_SNOOZE_7D = "argus_snooze_7d"
BLOCKED_ON_BLOCK_ID = "argus_blocked_on_block"
BLOCKED_ON_ACTION_ID = "argus_blocked_on_input"
ACTION_TO_RESPONSE_TYPE = {
    ACTION_HANDLED_OFFLINE: "handled_offline",
    ACTION_BLOCKED_ON: "blocked_on",
    ACTION_SNOOZE_7D: "snooze_7d",
}
SNOOZE_DAYS = 7

# Events that mean "this workspace is gone". Both are treated the same way
# and both are recorded: 7.8's exit criterion is stated partly as an uninstall
# rate, which is not measurable unless uninstalls are written down when they
# happen.
UNINSTALL_EVENTS = {"app_uninstalled", "tokens_revoked"}


class SlackNotConfigured(RuntimeError):
    """A Slack-dependent call was made before the app's credentials were set
    on this host. Names the missing variable rather than failing vaguely."""


class SlackError(RuntimeError):
    """A Slack API call that returned ok:false, carrying Slack's own error.

    Same shape as `slack_triage.SlackError`, on purpose — the failure
    handling written in Phase 6 reads identically here.
    """

    def __init__(self, method: str, error: str, payload: Optional[dict] = None):
        super().__init__(f"slack {method} failed: {error}")
        self.method = method
        self.error = error
        self.payload = payload or {}


# ===========================================================================
# 0. The app manifest — what Dirgh pastes into Slack, once, to create the app.
# ===========================================================================

def build_manifest(base_url: str) -> dict[str, Any]:
    """The Slack app manifest for this deployment.

    A function rather than a static file for the same reason 7.2's GitHub
    manifest is: three of its fields are this backend's own public URL, which
    did not exist until 7.2 stood the service up. The same manifest cannot be
    correct before and after that.

    Field names confirmed against Slack's published manifest reference rather
    than recalled (D-112's rule), including `settings.event_subscriptions.
    bot_events`, `oauth_config.scopes.bot`, and the three top-level `settings`
    booleans.

    `socket_mode_enabled: false` is the single most consequential line here:
    it is what 7.3 changes about Phase 6 (D-140). Socket Mode is not available
    to a distributed app, and distribution is the whole point of this step.

    Note what is NOT requested: no channel scopes, no message history, no
    ability to read anything a developer did not send ARGUS directly. The
    pilot teams' security reviewers will read this manifest, and the shortest
    possible list is the honest answer as well as the persuasive one.
    """
    base_url = base_url.rstrip("/")
    return {
        "display_information": {
            "name": "ARGUS",
            "description": "Tells you which work is quietly stuck, and asks the one "
                           "person who knows.",
            "background_color": "#14171a",
        },
        "features": {
            "bot_user": {"display_name": "ARGUS", "always_online": False},
            "app_home": {
                # ARGUS talks to people in DMs and nowhere else, so the
                # Messages tab is the only surface it needs.
                "home_tab_enabled": False,
                "messages_tab_enabled": True,
                # Left writable so a developer can reply in words when none of
                # the three buttons fits. Phase 6.6 found that the answer
                # people most want to give is often "it's complicated".
                "messages_tab_read_only_enabled": False,
            },
        },
        "oauth_config": {
            "redirect_urls": [f"{base_url}/v1/slack/oauth/callback"],
            "scopes": {"bot": config.SLACK_BOT_SCOPES.split(",")},
        },
        "settings": {
            "event_subscriptions": {
                "request_url": f"{base_url}/v1/slack/events",
                # Only the two that mean "this workspace is gone". ARGUS does
                # not subscribe to messages: it has no reason to read them,
                # and every event subscribed to is one a pilot team's security
                # review has to be told about.
                "bot_events": ["app_uninstalled", "tokens_revoked"],
            },
            "interactivity": {
                "is_enabled": True,
                "request_url": f"{base_url}/v1/slack/interactions",
            },
            "org_deploy_enabled": False,
            "socket_mode_enabled": False,
            "token_rotation_enabled": False,
        },
    }


# ===========================================================================
# 1. Request signing — what replaces Socket Mode's implicit trust.
# ===========================================================================

def verify_signature(signing_secret: str, raw_body: bytes,
                     timestamp: str | None, signature: str | None,
                     *, now: float | None = None,
                     max_age: int | None = None) -> tuple[bool, str]:
    """True iff this request really came from Slack, and recently.

    Slack's scheme: `v0=` + HMAC-SHA256 over the literal string
    `v0:{timestamp}:{raw body}`, keyed by the app's signing secret.

    Two traps, both of which this project has already paid for once in the
    GitHub webhook (7.2) and both of which are checked here:

      * The signature covers the RAW bytes. Re-serialising parsed JSON — or,
        for interactions, re-encoding the form body — changes whitespace and
        key order and produces a valid-looking mismatch. Callers must read
        the body before anything else parses it.
      * A valid signature is valid forever unless the timestamp is checked.
        Slack's documented window is five minutes; without it, a captured
        request replays indefinitely.

    Returns (ok, reason) rather than a bare bool so the endpoint can record
    WHY a request was refused. "Bad signature" and "five hours old" call for
    very different responses from whoever is looking at the audit log.
    """
    if not signing_secret:
        return False, "no_signing_secret_configured"
    if not timestamp or not signature:
        return False, "missing_signature_headers"
    try:
        ts = int(timestamp)
    except ValueError:
        return False, "unparseable_timestamp"

    now = time.time() if now is None else now
    max_age = config.SLACK_REQUEST_MAX_AGE_SECONDS if max_age is None else max_age
    if abs(now - ts) > max_age:
        return False, "stale_timestamp"

    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + raw_body
    expected = "v0=" + hmac.new(signing_secret.encode("utf-8"), basestring,
                                hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "bad_signature"
    return True, "ok"


def sign_request(signing_secret: str, raw_body: bytes, timestamp: str) -> str:
    """The inverse, used only by the test suite to forge a genuinely valid
    Slack request. Kept beside `verify_signature` deliberately: a test that
    reimplements the signing scheme proves the two implementations agree
    with each other, not that either matches Slack."""
    basestring = b"v0:" + timestamp.encode("utf-8") + b":" + raw_body
    return "v0=" + hmac.new(signing_secret.encode("utf-8"), basestring,
                            hashlib.sha256).hexdigest()


# ===========================================================================
# 2. OAuth v2 — the "add ARGUS to Slack" flow.
# ===========================================================================

def generate_claim_token() -> tuple[str, str]:
    """Returns (plaintext, sha256-hex), same shape and handling rules as
    7.2's GitHub claim token and 7.1's API key. A distinct namespace prefix
    so that a token pasted into the wrong flow is obviously the wrong token
    at a glance, on top of the `provider` column that actually enforces it."""
    import secrets
    plaintext = CLAIM_NAMESPACE + secrets.token_urlsafe(24)
    return plaintext, hash_claim_token(plaintext)


def hash_claim_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def redirect_uri() -> str:
    if not config.PUBLIC_BASE_URL:
        raise SlackNotConfigured("ARGUS_PUBLIC_BASE_URL is not set")
    return f"{config.PUBLIC_BASE_URL}/v1/slack/oauth/callback"


def oauth_authorize_url(state_token: str) -> str:
    """Where /v1/slack/install sends the pilot contact's browser.

    Built server-side rather than handed out as a raw slack.com link so the
    scope list lives in exactly one place (config.SLACK_BOT_SCOPES). A link
    with the scopes baked into it goes stale the moment the list changes, and
    the person holding the stale link is a customer, not us.
    """
    if not config.SLACK_CLIENT_ID:
        raise SlackNotConfigured("ARGUS_SLACK_CLIENT_ID is not set")
    from urllib.parse import urlencode
    return SLACK_AUTHORIZE_URL + "?" + urlencode({
        "client_id": config.SLACK_CLIENT_ID,
        "scope": config.SLACK_BOT_SCOPES,
        # Deliberately empty: ARGUS never acts as the installing user, only as
        # itself. Requesting user scopes would ask for consent we do not need.
        "user_scope": "",
        "redirect_uri": redirect_uri(),
        "state": state_token,
    })


@dataclass(frozen=True)
class SlackInstall:
    """What Slack hands back once a workspace approves the install."""
    access_token: str          # xoxb-..., this workspace's bot token
    team_id: str
    team_name: str
    bot_user_id: str
    app_id: str
    installer_user_id: str
    scopes: str

    @classmethod
    def from_oauth_response(cls, body: dict[str, Any]) -> "SlackInstall":
        team = body.get("team") or {}
        authed = body.get("authed_user") or {}
        return cls(
            access_token=body.get("access_token") or "",
            team_id=team.get("id") or "",
            team_name=team.get("name") or "",
            bot_user_id=body.get("bot_user_id") or "",
            app_id=body.get("app_id") or "",
            installer_user_id=authed.get("id") or "",
            scopes=body.get("scope") or "",
        )


def exchange_oauth_code(code: str, client: httpx.Client | None = None) -> SlackInstall:
    """Trade the one-time `code` from Slack's redirect for a bot token.

    Like 7.2's manifest-code exchange, this call runs wherever the deployed
    backend runs — never in Claude's sandbox, which cannot reach slack.com at
    all (D-115, the same restriction D-111 found for Atlassian and Linear).
    Ordering 7.3 so this only ever executes on the already-public Render host
    is what keeps that a non-issue rather than a blocker, exactly as D-135 did
    for GitHub.

    `oauth.v2.access` is form-encoded, not JSON, and Slack returns HTTP 200
    with `ok:false` on failure — so the status code is not the check.
    """
    if not (config.SLACK_CLIENT_ID and config.SLACK_CLIENT_SECRET):
        raise SlackNotConfigured(
            "ARGUS_SLACK_CLIENT_ID / ARGUS_SLACK_CLIENT_SECRET are not set")
    client = client or httpx.Client(timeout=15.0)
    resp = client.post(
        SLACK_API_BASE + "oauth.v2.access",
        data={
            "client_id": config.SLACK_CLIENT_ID,
            "client_secret": config.SLACK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": redirect_uri(),
        },
    )
    body = resp.json()
    if not body.get("ok"):
        raise SlackError("oauth.v2.access", body.get("error", "unknown_error"), body)
    install = SlackInstall.from_oauth_response(body)
    if not install.access_token.startswith("xoxb-"):
        raise SlackError("oauth.v2.access", "no_bot_token_in_response", body)
    if not install.team_id:
        raise SlackError("oauth.v2.access", "no_team_id_in_response", body)
    return install


# ===========================================================================
# 3. Talking back to one workspace.
# ===========================================================================

class SlackTransport:
    """One method, so the whole of Slack can be faked in a test. Same
    interface as `slack_triage.SlackTransport`."""

    def call(self, method: str, **args: Any) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class TenantSlackTransport(SlackTransport):
    """The real one, holding exactly one workspace's bot token.

    NOT exercised against the live API from this sandbox, for the same reason
    Phase 6's transport never was (D-115): there is no route to slack.com from
    here. Every call site takes a transport as an argument so the test suite
    substitutes a recording fake, and the first real traffic is step 7.5's
    onboarding — which is precisely why the interaction handler below writes
    to Postgres BEFORE it tries to talk to Slack, never after.
    """

    def __init__(self, bot_token: str, base: str = SLACK_API_BASE,
                 client: httpx.Client | None = None, timeout: float = 15.0):
        if not bot_token.startswith("xoxb-"):
            raise ValueError("expected a bot token beginning 'xoxb-'")
        self._token = bot_token
        self._base = base
        self._client = client or httpx.Client(timeout=timeout)

    def call(self, method: str, **args: Any) -> dict:
        try:
            resp = self._client.post(
                self._base + method,
                json={k: v for k, v in args.items() if v is not None},
                headers={"Authorization": f"Bearer {self._token}",
                         "Content-Type": "application/json; charset=utf-8"},
            )
            data = resp.json()
        except httpx.HTTPError as exc:
            raise SlackError(method, f"transport_error: {exc}") from exc
        except ValueError as exc:
            raise SlackError(method, "unparseable_response") from exc
        if not data.get("ok"):
            raise SlackError(method, data.get("error", "unknown_error"), data)
        return data


def transport_for(conn, tenant_id: str, integration_id: int) -> TenantSlackTransport | None:
    """Build a transport for one tenant's workspace, or None if there is no
    live token for it.

    MUST be called inside `db.tenant_tx(tenant_id)`: the SELECT below is
    RLS-scoped, so an unbound connection returns nothing and this returns
    None. That is the intended failure mode — no token, no calls — rather
    than an exception nobody catches at 3am.
    """
    row = conn.execute(
        "SELECT token_ciphertext FROM slack_workspace_token"
        " WHERE integration_id = %s AND revoked_at IS NULL",
        (integration_id,),
    ).fetchone()
    if row is None:
        return None
    return TenantSlackTransport(
        slack_crypto.decrypt_token(row["token_ciphertext"], tenant_id))


# ===========================================================================
# 4. Idempotency keys.
# ===========================================================================

def event_dedup_key(envelope: dict[str, Any]) -> str:
    """Slack stamps every Events API delivery with its own `event_id`, stable
    across the retries it sends when it does not see a 2xx in three seconds.
    Falling back to a hash of the envelope keeps a malformed delivery from
    bypassing dedup entirely."""
    event_id = envelope.get("event_id")
    if event_id:
        return f"event:{event_id}"
    digest = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return f"event:sha256:{digest[:32]}"


def interaction_dedup_key(payload: dict[str, Any]) -> str:
    """Interactions carry no delivery id of any kind, so the key is built from
    what actually identifies the click.

    For a button: the message it was attached to plus which button. That is
    exactly the identity we want — the same person pressing [Snooze 7d] twice
    on the same DM is one answer, and Slack re-delivering one press is also
    one answer, and the two are indistinguishable from here anyway.

    For a modal submission: Slack's own view id, which is unique per opened
    dialog.
    """
    ptype = payload.get("type")
    if ptype == "view_submission":
        view = payload.get("view") or {}
        return f"view:{view.get('id') or view.get('hash') or 'unknown'}"
    container = payload.get("container") or {}
    channel = (payload.get("channel") or {}).get("id") or container.get("channel_id") or "?"
    ts = (payload.get("message") or {}).get("ts") or container.get("message_ts") or "?"
    actions = payload.get("actions") or []
    action_id = (actions[0].get("action_id") if actions else "?") or "?"
    return f"action:{channel}:{ts}:{action_id}"


# ===========================================================================
# 5. Block Kit — mirrored from Phase 6.6, unchanged.
# ===========================================================================

def blocked_on_modal(channel_id: str, message_ts: str, item_key: str) -> dict:
    """The dialog [Blocked on…] opens. `private_metadata` carries the message
    coordinates through the round trip, because a view_submission payload does
    not otherwise say which message it came from."""
    return {
        "type": "modal",
        "callback_id": CALLBACK_BLOCKED_ON,
        "private_metadata": json.dumps({"channel": channel_id, "ts": message_ts},
                                       separators=(",", ":")),
        "title": {"type": "plain_text", "text": "What's it blocked on?"},
        "submit": {"type": "plain_text", "text": "Save"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {"type": "context",
             "elements": [{"type": "mrkdwn", "text": f"*{item_key}*"}]},
            {"type": "input",
             "block_id": BLOCKED_ON_BLOCK_ID,
             "label": {"type": "plain_text", "text": "Blocked on"},
             "element": {"type": "plain_text_input",
                         "action_id": BLOCKED_ON_ACTION_ID,
                         "max_length": 300,
                         "placeholder": {"type": "plain_text",
                                         "text": "e.g. waiting on the infra team for a staging DB"}},
             "hint": {"type": "plain_text",
                      "text": "One line. This is what your tech lead sees in the morning digest."}},
        ],
    }


def compose_answered_blocks(item_key: str, response_type: str,
                            blocked_on_text: Optional[str], answered_at: str,
                            snooze_until: Optional[str]) -> list[dict]:
    """What the DM is rewritten to after a click. The buttons are REMOVED, not
    left in place looking clickable."""
    if response_type == "handled_offline":
        line = (f":white_check_mark: *{item_key}* — you said this is handled offline. "
                "ARGUS will stay quiet about it.")
    elif response_type == "blocked_on":
        line = (f":construction: *{item_key}* — logged as blocked on: "
                f"*{blocked_on_text}*. This goes into the morning digest.")
    else:
        until = (snooze_until or "").replace("T", " ").replace("Z", " UTC")
        line = f":alarm_clock: *{item_key}* — snoozed until {until}."
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": line}},
        {"type": "context",
         "elements": [{"type": "mrkdwn", "text": f"Recorded {answered_at}"}]},
    ]


# ===========================================================================
# 6. Handling one interaction, against Postgres.
# ===========================================================================

@dataclass
class InteractionResult:
    handled: bool
    action: str
    reason: str = ""
    triage_message_id: Optional[int] = None
    response_type: Optional[str] = None
    blocked_on_text: Optional[str] = None
    response_body: Optional[dict] = None   # what to return to Slack over HTTP

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _message_by_coords(conn, channel_id: str, message_ts: str):
    """RLS makes this the tenant-scoped lookup it looks like: the caller is
    inside `tenant_tx`, so a click that arrived for the wrong tenant finds
    nothing rather than someone else's DM."""
    return conn.execute(
        "SELECT id, work_item_id, ticket_id, status, sent_to_actor_id"
        " FROM triage_message WHERE external_channel_id = %s AND external_message_ts = %s",
        (channel_id, message_ts),
    ).fetchone()


def item_key_of(conn, work_item_id: Optional[int]) -> str:
    """'acme/api#4'-style label for the redrawn message.

    Phase 6's `sprint_filter.item_key` does this against SQLite by joining
    project and work_item. Reproduced here in one query rather than importing
    the engine, keeping `backend/` free of Phase 6 imports the way 7.1 and
    7.2 left it.
    """
    if work_item_id is None:
        return "this item"
    row = conn.execute(
        "SELECT p.source_key, w.source_number FROM work_item w"
        " JOIN project p ON p.id = w.project_id AND p.tenant_id = w.tenant_id"
        " WHERE w.id = %s", (work_item_id,)).fetchone()
    if row is None:
        return "this item"
    return f"{row['source_key']}#{row['source_number']}"


def _record_response(conn, transport: Optional[SlackTransport], tenant_id: str,
                     msg_id: int, work_item_id: Optional[int], channel_id: str,
                     message_ts: str, response_type: str,
                     blocked_on_text: Optional[str], now: str,
                     raw_payload: Optional[dict]) -> InteractionResult:
    """Write the click into the model, then rewrite the DM to match.

    Order matters, and it is the same order Phase 6 chose for the same
    reason: the database row is written first, the Slack redraw is
    best-effort. Losing a developer's answer because a cosmetic redraw
    failed would be the worst possible trade — the answer is the entire
    point of this feature and Phase 7.8's only real input.
    """
    snooze_until = None
    if response_type == "snooze_7d":
        from datetime import datetime, timedelta, timezone
        base = datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        snooze_until = (base + timedelta(days=SNOOZE_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn.execute(
        "INSERT INTO triage_response (tenant_id, triage_message_id, response_type,"
        " blocked_on_text, responded_at, raw_payload) VALUES (%s,%s,%s,%s,%s,%s)",
        (tenant_id, msg_id, response_type, blocked_on_text, now,
         json.dumps(raw_payload, separators=(",", ":")) if raw_payload else None),
    )
    conn.execute(
        "UPDATE triage_message SET status='responded', snooze_until=%s WHERE id=%s",
        (snooze_until, msg_id),
    )

    redraw = "message_updated"
    if transport is not None:
        try:
            transport.call(
                "chat.update", channel=channel_id, ts=message_ts,
                text=f"Recorded: {response_type.replace('_', ' ')}",
                blocks=compose_answered_blocks(item_key_of(conn, work_item_id),
                                               response_type, blocked_on_text,
                                               now, snooze_until))
        except SlackError as exc:
            redraw = f"message_update_failed: {exc.error}"
    else:
        redraw = "message_not_updated: no transport"

    return InteractionResult(True, "response_recorded", redraw, triage_message_id=msg_id,
                             response_type=response_type, blocked_on_text=blocked_on_text)


def handle_interaction(conn, tenant_id: str, payload: dict,
                       transport: Optional[SlackTransport], now: str) -> InteractionResult:
    """Handle one Slack interaction payload against Postgres.

    A near-line-for-line port of `slack_triage.handle_interaction`, kept that
    way on purpose: this logic was verified against real Slack traffic in step
    6.9 and the multi-tenant move is not the moment to also redesign it. The
    differences are exactly three — parameter style (%s), an explicit
    `tenant_id` on every INSERT (the schema requires it even though RLS would
    catch its absence), and no `conn.commit()`, because `db.tenant_tx` owns
    the transaction here.
    """
    ptype = payload.get("type")

    # ---- the modal came back ------------------------------------------
    if ptype == "view_submission":
        view = payload.get("view") or {}
        if view.get("callback_id") != CALLBACK_BLOCKED_ON:
            return InteractionResult(False, "ignored",
                                     f"unknown callback_id {view.get('callback_id')!r}")
        try:
            meta = json.loads(view.get("private_metadata") or "{}")
        except json.JSONDecodeError:
            return InteractionResult(False, "ignored", "unparseable private_metadata")
        channel_id, message_ts = meta.get("channel"), meta.get("ts")
        if not channel_id or not message_ts:
            return InteractionResult(False, "ignored",
                                     "private_metadata lost the message coords")

        values = ((view.get("state") or {}).get("values") or {})
        text = (((values.get(BLOCKED_ON_BLOCK_ID) or {}).get(BLOCKED_ON_ACTION_ID) or {})
                .get("value"))
        text = (text or "").strip()

        row = _message_by_coords(conn, channel_id, message_ts)
        if row is None:
            return InteractionResult(False, "ignored", "no triage_message for those coords")
        if row["status"] == "responded":
            return InteractionResult(True, "already_responded",
                                     "a response for this message is already recorded",
                                     triage_message_id=row["id"])
        if not text:
            return InteractionResult(
                False, "validation_error", "blocked_on text was empty",
                triage_message_id=row["id"],
                response_body={"response_action": "errors",
                               "errors": {BLOCKED_ON_BLOCK_ID:
                                          "Please say what it's blocked on."}})
        return _record_response(conn, transport, tenant_id, row["id"], row["work_item_id"],
                                channel_id, message_ts, "blocked_on", text, now, payload)

    # ---- a button was pressed -----------------------------------------
    if ptype != "block_actions":
        return InteractionResult(False, "ignored", f"unhandled payload type {ptype!r}")

    actions = payload.get("actions") or []
    if not actions:
        return InteractionResult(False, "ignored", "block_actions payload with no actions")
    action_id = actions[0].get("action_id")
    if action_id not in ACTION_TO_RESPONSE_TYPE:
        return InteractionResult(False, "ignored", f"not an ARGUS action: {action_id!r}")

    container = payload.get("container") or {}
    channel_id = (payload.get("channel") or {}).get("id") or container.get("channel_id")
    message_ts = (payload.get("message") or {}).get("ts") or container.get("message_ts")
    if not channel_id or not message_ts:
        return InteractionResult(False, "ignored", "payload carried no message coordinates")

    row = _message_by_coords(conn, channel_id, message_ts)
    if row is None:
        return InteractionResult(False, "ignored",
                                 "no triage_message for those coords — not an ARGUS DM, "
                                 "or sent by a different install")
    if row["status"] == "responded":
        return InteractionResult(True, "already_responded",
                                 "a response for this message is already recorded",
                                 triage_message_id=row["id"])

    if action_id == ACTION_BLOCKED_ON:
        trigger_id = payload.get("trigger_id")
        if not trigger_id:
            return InteractionResult(False, "modal_not_opened", "no trigger_id in payload",
                                     triage_message_id=row["id"])
        if transport is None:
            return InteractionResult(False, "modal_not_opened",
                                     "no Slack transport available",
                                     triage_message_id=row["id"])
        try:
            transport.call("views.open", trigger_id=trigger_id,
                           view=blocked_on_modal(channel_id, message_ts,
                                                 item_key_of(conn, row["work_item_id"])))
        except SlackError as exc:
            return InteractionResult(False, "modal_not_opened", f"views.open: {exc.error}",
                                     triage_message_id=row["id"])
        # Nothing recorded yet, deliberately: opening a dialog is not an
        # answer, and a user who cancels it has said nothing.
        return InteractionResult(True, "modal_opened", "awaiting the blocked-on text",
                                 triage_message_id=row["id"])

    return _record_response(conn, transport, tenant_id, row["id"], row["work_item_id"],
                            channel_id, message_ts, ACTION_TO_RESPONSE_TYPE[action_id],
                            None, now, payload)
