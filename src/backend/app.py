"""ARGUS Phase 7.1 — the multi-tenant API.

Two surfaces, deliberately separated:

  /v1/admin/*   the control plane. Gated on ARGUS_ADMIN_SECRET, runs as the
                argus_admin role, creates tenants and issues keys. No pilot
                team ever holds this secret.
  /v1/*         everything a pilot team's own installation talks to. Gated on
                that team's API key, runs as the argus_app role, and every
                statement it makes is inside a tenant-bound transaction.

What 7.1 did NOT do, on purpose: it did not talk to GitHub, Jira or Slack.
Step 7.2 (below, "GitHub App: manifest, install claims, webhooks") is the
first of those — a packaged, installable GitHub App in place of a personal
access token, authenticating real webhook traffic and binding each
installation to exactly one tenant before any of its data is ever touched.
"""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from . import config, db, github_app
from .auth import TenantContext, generate_key, hash_key, now_iso


# --------------------------------------------------------------------------
# Request / response shapes
# --------------------------------------------------------------------------

class TenantCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")
    display_name: str
    shadow_until: str | None = None


class TenantOut(BaseModel):
    id: str
    slug: str
    display_name: str
    status: str
    shadow_until: str | None
    created_at: str


class TenantCreated(TenantOut):
    api_key: str = Field(description="Shown once. Not recoverable — reissue if lost.")


class IngestRunCreate(BaseModel):
    trigger_kind: Literal["scheduled", "manual", "webhook", "backfill"] = "manual"


class IngestRunOut(BaseModel):
    id: int
    trigger_kind: str
    status: str
    started_at: str
    finished_at: str | None
    items_checked: int
    alerts_fired: int
    alerts_suppressed: int
    error_detail: str | None


class AlertOut(BaseModel):
    id: int
    ingest_run_id: int
    pattern: str
    outcome: str
    reason: str
    work_item_id: int | None
    ticket_id: int | None
    decided_at: str
    feedback: str | None = None


class FeedbackIn(BaseModel):
    alert_id: int
    verdict: Literal["useful", "not_useful", "unsure"]
    note: str | None = None


class InstallLinkOut(BaseModel):
    install_url: str
    token: str = Field(description="Shown once; also embedded in install_url.")
    expires_at: str


class DigestOut(BaseModel):
    id: int
    ingest_run_id: int
    channel: str
    status: str
    rendered_text: str
    delivered_at: str


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _audit(conn, tenant_id, actor, action, outcome, detail=None) -> None:
    conn.execute(
        "INSERT INTO audit_log (tenant_id, at, actor, action, detail, outcome)"
        " VALUES (%s,%s,%s,%s,%s,%s)",
        (tenant_id, now_iso(), actor, action, detail, outcome),
    )


def require_tenant(
    authorization: Annotated[str | None, Header()] = None,
) -> TenantContext:
    """Resolve `Authorization: Bearer argus_sk_...` to a tenant, or refuse.

    Note what this does not do: it never trusts a tenant id supplied by the
    caller. There is no header, query parameter or body field anywhere in this
    API that lets a request name the tenant it wants. The key is the only way
    a tenant is chosen, which is why forging one is not a test case that can
    exist.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    presented = authorization.split(" ", 1)[1].strip()
    prefix = presented[: config.KEY_PREFIX_LEN]

    with db.unbound_app_tx() as conn:
        row = conn.execute(
            "SELECT * FROM argus_resolve_api_key(%s, %s)", (prefix, hash_key(presented))
        ).fetchone()

    # The audit write happens in its OWN transaction, deliberately. Writing it
    # alongside the refusal and then raising rolls the audit row back with the
    # transaction -- which is how the first version of this function silently
    # logged nothing at all for exactly the requests most worth logging.
    def deny(code: int, message: str, tenant_id, actor: str, detail: str):
        with db.unbound_app_tx() as audit_conn:
            _audit(audit_conn, tenant_id, actor, "auth", "denied", detail)
        raise HTTPException(code, message)

    if row is None:
        deny(status.HTTP_401_UNAUTHORIZED, "Invalid API key", None, "anonymous",
             f"prefix={prefix[:12]}")
    if row["status"] == "suspended":
        deny(status.HTTP_403_FORBIDDEN, "Tenant suspended", row["tenant_id"],
             f"tenant:{row['slug']}", "suspended")

    with db.unbound_app_tx() as conn:
        conn.execute("SELECT argus_touch_api_key(%s, %s)", (row["key_id"], now_iso()))

    return TenantContext(
        tenant_id=str(row["tenant_id"]), key_id=str(row["key_id"]), slug=row["slug"],
        status=row["status"], shadow_until=row["shadow_until"],
    )


def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> str:
    if x_admin_key != config.ADMIN_SECRET:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid admin key")
    return "admin"


Tenant = Annotated[TenantContext, Depends(require_tenant)]
Admin = Annotated[str, Depends(require_admin)]


# --------------------------------------------------------------------------
# App
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    if config.ENVIRONMENT == "production" and \
            config.ADMIN_SECRET == "dev-admin-secret-change-me":
        raise RuntimeError("Refusing to start in production with the default admin secret")
    # Step 7.2: a from-scratch managed Postgres (Render's) has no schema on
    # it at all yet. This makes that a non-event instead of a manual `psql
    # -f schema_pg.sql` step nobody is supposed to have to run.
    db.bootstrap_schema_if_needed()
    yield
    db.close_pools()


app = FastAPI(title="ARGUS", version="7.2", lifespan=lifespan)


@app.get("/v1/health")
def health() -> dict[str, Any]:
    with db.unbound_app_tx() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "phase": "7.2"}


# --- control plane ---------------------------------------------------------

@app.post("/v1/admin/tenants", response_model=TenantCreated, status_code=201)
def create_tenant(body: TenantCreate, _: Admin) -> TenantCreated:
    plaintext, prefix, key_hash = generate_key()
    with db.admin_tx() as conn:
        existing = conn.execute("SELECT 1 FROM tenant WHERE slug=%s", (body.slug,)).fetchone()
        if existing:
            raise HTTPException(status.HTTP_409_CONFLICT, "Tenant slug already exists")
        t = conn.execute(
            "INSERT INTO tenant (slug, display_name, status, shadow_until, created_at)"
            " VALUES (%s,%s,'shadow',%s,%s) RETURNING *",
            (body.slug, body.display_name, body.shadow_until, now_iso()),
        ).fetchone()
        conn.execute(
            "INSERT INTO tenant_api_key (tenant_id, key_prefix, key_hash, label, created_at)"
            " VALUES (%s,%s,%s,%s,%s)",
            (t["id"], prefix, key_hash, "initial", now_iso()),
        )
        # Every tenant starts with its own `source` rows, so a project row can
        # never be shared between two teams by accident. Done through a
        # SECURITY DEFINER function: the admin role has no standing write path
        # into tenant data and this must not become one.
        conn.execute("SELECT argus_seed_tenant_sources(%s)", (t["id"],))
        _audit(conn, t["id"], "admin", "tenant.create", "ok", body.slug)
    return TenantCreated(id=str(t["id"]), slug=t["slug"], display_name=t["display_name"],
                         status=t["status"], shadow_until=t["shadow_until"],
                         created_at=t["created_at"], api_key=plaintext)


@app.get("/v1/admin/tenants", response_model=list[TenantOut])
def list_tenants(_: Admin) -> list[TenantOut]:
    with db.admin_tx() as conn:
        rows = conn.execute("SELECT * FROM tenant ORDER BY slug").fetchall()
    return [TenantOut(id=str(r["id"]), **{k: r[k] for k in
            ("slug", "display_name", "status", "shadow_until", "created_at")}) for r in rows]


@app.post("/v1/admin/tenants/{slug}/status")
def set_tenant_status(
    slug: str, _: Admin,
    new_status: Annotated[Literal["shadow", "live", "suspended", "offboarded"], Query()],
) -> dict[str, str]:
    """Shadow -> live is step 7.6's graduation, and it is a deliberate admin
    action rather than a timer, so no team starts DMing its developers because
    a date passed while nobody was looking."""
    with db.admin_tx() as conn:
        row = conn.execute(
            "UPDATE tenant SET status=%s,"
            " offboarded_at = CASE WHEN %s='offboarded' THEN %s ELSE offboarded_at END"
            " WHERE slug=%s RETURNING id, status",
            (new_status, new_status, now_iso(), slug),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "No such tenant")
        _audit(conn, row["id"], "admin", "tenant.status", "ok", f"{slug} -> {new_status}")
    return {"slug": slug, "status": row["status"]}


@app.get("/v1/admin/metrics")
def pilot_metrics(_: Admin) -> list[dict[str, Any]]:
    """Step 7.8's number, across every pilot team at once. Admin-only, and
    served by a SECURITY DEFINER function so the app role never gains a
    cross-tenant read path 'just for reporting'."""
    with db.admin_tx() as conn:
        return conn.execute("SELECT * FROM argus_pilot_metrics()").fetchall()


# --- tenant surface --------------------------------------------------------

@app.get("/v1/me")
def whoami(t: Tenant) -> dict[str, Any]:
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute("SELECT slug, display_name, status FROM tenant").fetchall()
    return {"tenant": rows[0] if rows else None, "visible_tenant_rows": len(rows),
            "shadow_mode": not t.may_send_dms, "shadow_until": t.shadow_until}


@app.post("/v1/ingest/runs", response_model=IngestRunOut, status_code=201)
def start_ingest_run(body: IngestRunCreate, t: Tenant) -> IngestRunOut:
    with db.tenant_tx(t.tenant_id) as conn:
        row = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,%s,'queued',%s) RETURNING *",
            (t.tenant_id, body.trigger_kind, now_iso()),
        ).fetchone()
        _audit(conn, t.tenant_id, f"tenant:{t.slug}", "ingest.start", "ok", str(row["id"]))
    return IngestRunOut(**{k: row[k] for k in IngestRunOut.model_fields})


@app.get("/v1/ingest/runs", response_model=list[IngestRunOut])
def list_ingest_runs(t: Tenant, limit: int = 20) -> list[IngestRunOut]:
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute(
            "SELECT * FROM ingest_run ORDER BY started_at DESC, id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    return [IngestRunOut(**{k: r[k] for k in IngestRunOut.model_fields}) for r in rows]


@app.get("/v1/alerts", response_model=list[AlertOut])
def list_alerts(
    t: Tenant,
    outcome: Annotated[Literal["FIRE", "SUPPRESSED", "ABSTAIN"] | None, Query()] = None,
    limit: int = 100,
) -> list[AlertOut]:
    sql = ("SELECT a.*, f.verdict AS feedback FROM alert a"
           " LEFT JOIN alert_feedback f ON f.alert_id = a.id")
    params: list[Any] = []
    if outcome:
        sql += " WHERE a.outcome = %s"
        params.append(outcome)
    sql += " ORDER BY a.decided_at DESC, a.id DESC LIMIT %s"
    params.append(limit)
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [AlertOut(**{k: r[k] for k in AlertOut.model_fields}) for r in rows]


@app.post("/v1/alerts/feedback", status_code=201)
def give_feedback(body: FeedbackIn, t: Tenant) -> dict[str, Any]:
    """Step 7.7's satisfaction response. Upserts, because a developer changing
    their mind about an alert is information, not an error."""
    with db.tenant_tx(t.tenant_id) as conn:
        target = conn.execute("SELECT id FROM alert WHERE id=%s", (body.alert_id,)).fetchone()
        if target is None:
            # RLS already made another tenant's alert invisible; this 404 is
            # what a cross-tenant guess looks like from the outside.
            raise HTTPException(404, "No such alert")
        conn.execute(
            "INSERT INTO alert_feedback (tenant_id, alert_id, verdict, note, given_at)"
            " VALUES (%s,%s,%s,%s,%s)"
            " ON CONFLICT (tenant_id, alert_id) DO UPDATE"
            " SET verdict=EXCLUDED.verdict, note=EXCLUDED.note, given_at=EXCLUDED.given_at",
            (t.tenant_id, body.alert_id, body.verdict, body.note, now_iso()),
        )
    return {"alert_id": body.alert_id, "verdict": body.verdict}


@app.get("/v1/digests", response_model=list[DigestOut])
def list_digests(t: Tenant, limit: int = 14) -> list[DigestOut]:
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute(
            "SELECT * FROM digest_delivery ORDER BY delivered_at DESC, id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    return [DigestOut(**{k: r[k] for k in DigestOut.model_fields}) for r in rows]


@app.get("/v1/digests/latest", response_model=DigestOut)
def latest_digest(t: Tenant) -> DigestOut:
    with db.tenant_tx(t.tenant_id) as conn:
        row = conn.execute(
            "SELECT * FROM digest_delivery ORDER BY delivered_at DESC, id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        raise HTTPException(404, "No digest yet")
    return DigestOut(**{k: row[k] for k in DigestOut.model_fields})


# ============================================================================
# GitHub App: manifest, install claims, webhooks (Phase 7.2)
#
# Three endpoints, three different callers, none of them a pilot team's own
# API key:
#   /v1/admin/github/callback   GitHub's browser redirect, ONE TIME, right
#                               after the manifest flow creates the App.
#   /v1/github/setup            GitHub's browser redirect after a pilot
#                               contact finishes installing the App.
#   /v1/webhooks/github         GitHub's servers, forever after, on every
#                               event the App is subscribed to.
# None of these can carry a normal Authorization/x-admin-key header — GitHub
# is the one making the request — so each is authenticated its own way:
# a setup secret, a one-time claim token, and an HMAC signature respectively.
# ============================================================================

CONTENT_EVENTS = {
    "pull_request", "issues", "issue_comment",
    "pull_request_review", "pull_request_review_comment",
}


@app.get("/v1/admin/github/callback", response_class=HTMLResponse)
def github_manifest_callback(code: str, state: str | None = None) -> HTMLResponse:
    """The ONE api.github.com call this whole flow needs to make from
    wherever this process is actually running — deliberately not from
    Claude's own sandbox, which has no route to api.github.com at all
    (D-121). Deploying the backend BEFORE running the manifest flow, so that
    this exchange happens on the already-public host, is what makes that
    standing constraint a non-issue here rather than a blocker.
    """
    if state != config.GITHUB_SETUP_SECRET:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad setup state")
    if config.GITHUB_APP_ID:
        return HTMLResponse(
            "<h1>Already configured</h1><p>ARGUS_GITHUB_APP_ID is already set on this "
            "deployment. Unset it (and restart) first if you meant to create a "
            "brand-new App.</p>", status_code=409)
    creds = github_app.exchange_manifest_code(code)
    # Displayed once, never written to disk here: the human copies these into
    # this host's own environment variables and restarts the service, the
    # same discipline every other ARGUS credential follows (D-087 and
    # `integration.credential_ref`) — a pointer lives in config.py, the
    # secret itself never does.
    fields = [
        ("ARGUS_GITHUB_APP_ID", str(creds["id"])),
        ("ARGUS_GITHUB_APP_SLUG", creds["slug"]),
        ("ARGUS_GITHUB_WEBHOOK_SECRET", creds["webhook_secret"]),
        ("ARGUS_GITHUB_APP_PRIVATE_KEY", creds["pem"]),
    ]
    rows = "".join(
        f"<tr><td><code>{k}</code></td><td>"
        f"<textarea readonly rows=3 style='width:100%;font-family:monospace'>{v}</textarea>"
        f"</td></tr>" for k, v in fields
    )
    return HTMLResponse(
        "<h1>&#9989; ARGUS Stall Radar App created</h1>"
        "<p>Copy each value below into this host's environment variables, then "
        "restart the service. This page will not show these again — if you lose "
        "them, delete the App on GitHub and run the manifest flow again.</p>"
        f"<table border=1 cellpadding=6>{rows}</table>"
    )


@app.get("/v1/github/setup", response_class=HTMLResponse)
def github_setup(
    installation_id: str,
    setup_action: str = "install",
    state: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """GitHub lands the browser here right after a pilot contact finishes
    installing (or re-configuring) the App. `state` is the one-time claim
    token from their install link — it is what ties `installation_id` to a
    tenant, since nothing else in this request can be trusted to name one.
    """
    if not state:
        return HTMLResponse(
            "<h1>Missing setup token</h1><p>This install link is missing its one-time "
            "token. Ask for a fresh install link rather than reusing an old one.</p>",
            status_code=400)
    token_hash = github_app.hash_claim_token(state)
    at = now_iso()
    with db.unbound_app_tx() as conn:
        row = conn.execute(
            "SELECT * FROM argus_claim_installation(%s,%s,%s,%s,%s,%s)",
            (token_hash, installation_id, "", "", "", at),
        ).fetchone()
    if row is None:
        return HTMLResponse(
            "<h1>This install link is invalid or has expired.</h1>"
            "<p>Install links are single-use. Ask for a fresh one.</p>", status_code=400)
    return HTMLResponse(
        "<h1>&#9989; ARGUS is now connected</h1>"
        "<p>You can close this tab — ARGUS will start watching the "
        f"repositories you selected. (setup_action: {setup_action})</p>")


@app.post("/v1/admin/tenants/{slug}/github/install-link", response_model=InstallLinkOut,
          status_code=201)
def create_github_install_link(slug: str, _: Admin) -> InstallLinkOut:
    """Mints the one-time link an admin hands to a pilot team: 'click this to
    install ARGUS.' The token is single-use and tenant-specific from the
    moment it's created — the pilot team never types in or confirms which
    tenant they are, because nothing about this flow lets them choose.
    """
    plaintext, token_hash = github_app.generate_claim_token()
    created = now_iso()
    expires_at = datetime.fromtimestamp(
        time.time() + config.INSTALL_CLAIM_TTL_SECONDS, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with db.admin_tx() as conn:
            conn.execute(
                "SELECT argus_admin_create_install_claim(%s,%s,%s,%s)",
                (slug, token_hash, created, expires_at),
            )
    except psycopg.errors.RaiseException:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such tenant")
    return InstallLinkOut(install_url=github_app.install_url(plaintext), token=plaintext,
                          expires_at=expires_at)


def _touch_pending_installation(conn, installation_id: str, account_login: str,
                                 account_type: str, event_type: str, action: str | None,
                                 at: str) -> dict[str, Any] | None:
    """Upsert the control-plane install-lifecycle log. Never overwrites a
    real account_login/type with a blank one, and only forces `status` for
    the three actions that unambiguously mean something (deleted / suspend /
    unsuspend) — anything else leaves whatever status was already there
    (in particular: never downgrades 'claimed' back to 'pending')."""
    existing = conn.execute(
        "SELECT status, claimed_tenant_id FROM pending_installation WHERE installation_id=%s",
        (installation_id,),
    ).fetchone()
    if action == "deleted":
        forced_status = "deleted"
    elif action == "suspend":
        forced_status = "suspended"
    elif action == "unsuspend":
        was_claimed = bool(existing and existing["claimed_tenant_id"])
        forced_status = "claimed" if was_claimed else "pending"
    else:
        forced_status = None

    if existing:
        conn.execute(
            "UPDATE pending_installation SET"
            " account_login = COALESCE(NULLIF(%s,''), account_login),"
            " account_type  = COALESCE(NULLIF(%s,''), account_type),"
            " status = COALESCE(%s, status),"
            " last_seen_at=%s, last_event_type=%s, last_event_action=%s"
            " WHERE installation_id=%s",
            (account_login, account_type, forced_status, at, event_type, action,
             installation_id),
        )
    else:
        conn.execute(
            "INSERT INTO pending_installation (installation_id, account_login, account_type,"
            " status, first_seen_at, last_seen_at, last_event_type, last_event_action)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (installation_id, account_login or "(unknown)", account_type or "unknown",
             forced_status or "pending", at, at, event_type, action),
        )
    return existing


@app.post("/v1/webhooks/github")
async def github_webhook(request: Request) -> dict[str, Any]:
    """Every event the App is subscribed to lands here. Three things happen,
    in order, before a single byte of payload is trusted: the signature is
    checked against the RAW body, the event is deduplicated by GitHub's own
    delivery id, and the installation is resolved to exactly one tenant (or
    the event is acknowledged and dropped, never guessed at).

    What this does NOT yet do, by deliberate 7.2 scope decision: parse
    `pull_request`/`issues`/... payloads directly into `work_item`/`event`
    rows. That is a real, separate data-modeling task (webhook JSON has a
    different shape than the REST snapshots `github_adapter.py` parses).
    For now a content event queues a fresh `ingest_run` — "something
    changed, re-check this tenant" — rather than being mapped id.
    """
    raw = await request.body()
    signature = request.headers.get("x-hub-signature-256")
    if not github_app.verify_signature(config.GITHUB_WEBHOOK_SECRET or "", raw, signature):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad signature")

    event_type = request.headers.get("x-github-event", "")
    delivery_id = request.headers.get("x-github-delivery", "")
    try:
        payload = json.loads(raw) if raw else {}
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed JSON body")

    if event_type == "ping":
        return {"status": "ok", "event": "ping", "zen": payload.get("zen")}

    action = payload.get("action")
    installation = payload.get("installation") or {}
    installation_id = str(installation["id"]) if installation.get("id") is not None else None
    if installation_id is None:
        return {"status": "ignored", "reason": "no installation in payload"}

    account = installation.get("account") or {}
    account_login = account.get("login") or ""
    account_type = account.get("type") or ""
    at = now_iso()

    if event_type in ("installation", "installation_repositories"):
        with db.unbound_app_tx() as conn:
            existing = _touch_pending_installation(
                conn, installation_id, account_login, account_type, event_type, action, at)
        # Soft revoke/restore the tenant-side integration row too, if one
        # exists — this is what actually stops a suspended/deleted
        # installation's events from resolving to a tenant going forward.
        if existing and existing["claimed_tenant_id"] and action in ("deleted", "suspend", "unsuspend"):
            claimed_tenant_id = str(existing["claimed_tenant_id"])
            with db.tenant_tx(claimed_tenant_id) as tconn:
                if action in ("deleted", "suspend"):
                    tconn.execute(
                        "UPDATE integration SET revoked_at=%s"
                        " WHERE tenant_id=%s AND external_account_id=%s",
                        (at, claimed_tenant_id, installation_id))
                else:
                    tconn.execute(
                        "UPDATE integration SET revoked_at=NULL"
                        " WHERE tenant_id=%s AND external_account_id=%s",
                        (claimed_tenant_id, installation_id))
        return {"status": "ok", "event": event_type, "action": action}

    # Everything else only means something once an installation is claimed.
    with db.unbound_app_tx() as conn:
        resolved = conn.execute(
            "SELECT * FROM argus_resolve_installation(%s)", (installation_id,)
        ).fetchone()
    if resolved is None:
        return {"status": "unresolved", "reason": "installation not yet claimed by a tenant"}
    if resolved["tenant_status"] == "suspended":
        return {"status": "ignored", "reason": "tenant suspended"}

    tenant_id = str(resolved["tenant_id"])
    with db.tenant_tx(tenant_id) as conn:
        if account_login:
            conn.execute(
                "UPDATE integration SET display_name=%s"
                " WHERE id=%s AND (display_name IS NULL OR display_name IN ('', '(pending)'))",
                (account_login, resolved["integration_id"]),
            )
        dup = conn.execute(
            "SELECT id FROM webhook_delivery WHERE tenant_id=%s AND delivery_id=%s",
            (tenant_id, delivery_id),
        ).fetchone()
        if dup:
            return {"status": "duplicate", "delivery_id": delivery_id}

        ingest_run_id = None
        if event_type in CONTENT_EVENTS:
            run = conn.execute(
                "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
                " VALUES (%s,'webhook','queued',%s) RETURNING id",
                (tenant_id, at),
            ).fetchone()
            ingest_run_id = run["id"]

        conn.execute(
            "INSERT INTO webhook_delivery (tenant_id, installation_id, delivery_id, event_type,"
            " action, received_at, ingest_run_id) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (tenant_id, installation_id, delivery_id, event_type, action, at, ingest_run_id),
        )
        _audit(conn, tenant_id, f"installation:{installation_id}", "webhook.received", "ok",
               f"{event_type}.{action}")
    return {"status": "ok", "event": event_type, "action": action, "ingest_run_id": ingest_run_id}
