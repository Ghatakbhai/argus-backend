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

import asyncio
import contextlib
import html
import json
import time
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from . import (config, db, github_app, ingest_worker, jira_crypto, linear_crypto,
               slack_app, slack_crypto, system_health, web_theme)
from .auth import TenantContext, generate_key, hash_key, now_iso


# --------------------------------------------------------------------------
# The pages a human sees mid-install.
#
# Five of the endpoints below answer a BROWSER, not an API client: GitHub's
# manifest callback, GitHub's post-install redirect, and Slack's install /
# OAuth pair. Everything else in this file returns JSON to something holding
# an API key. Those five used to return bare `<h1>`/`<p>` on the browser's
# default white — which meant a pilot team's very first sight of ARGUS looked
# nothing like the console they were about to open.
#
# `web_theme` is the one stylesheet all of it now shares (see that module's
# docstring). These two helpers are the only thing this file needs from it:
# `_page` for the one page with a table on it, `_status` for the eight
# one-card outcome screens.
# --------------------------------------------------------------------------


def _install_actions(*, slack: bool = False) -> str:
    """The action row at the bottom of a success page. Each button appears
    only if the URL it needs is actually configured — an `[Open Standup
    Radar]` button pointing nowhere is worse than no button."""
    return (web_theme.action_button("Open Standup Radar", config.DASHBOARD_URL, primary=True)
            + (web_theme.action_button("Return to Slack", "slack://open") if slack else ""))


def _status(kind: str, title: str, body: str, status_code: int = 200, *,
            pill: str | None = None, actions: str = "", detail: str = "") -> HTMLResponse:
    return HTMLResponse(
        web_theme.status_page(kind, title, body, pill=pill, actions=actions, detail=detail),
        status_code=status_code)


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
    item_key: str | None = None
    title: str | None = None
    url: str | None = None
    detail: str | None = None


class FeedbackIn(BaseModel):
    alert_id: int
    verdict: Literal["useful", "not_useful", "unsure"]
    note: str | None = None


class InstallLinkOut(BaseModel):
    install_url: str
    token: str = Field(description="Shown once; also embedded in install_url.")
    expires_at: str


class JiraCredentialsIn(BaseModel):
    """7.4c-d/§3.1.4: Jira has no App-install flow like GitHub/Slack, so an
    ARGUS admin enters a pilot's credentials by hand during onboarding
    (docs/PHASE7_5_OPERATIONAL_CHECKLIST.md §5). `base_url` and
    `project_key` are not secret (stored in the clear on `integration`);
    `email`/`api_token` are the real credential and are encrypted at rest
    via `jira_crypto` before they ever reach the database — see that
    module's docstring."""
    base_url: str = Field(description="e.g. https://acme.atlassian.net")
    project_key: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{1,9}$",
                             description="Jira project key, e.g. ENG")
    email: str
    api_token: str


class JiraCredentialsOut(BaseModel):
    integration_id: int
    project_key: str
    base_url: str
    installed_at: str


class LinearCredentialsIn(BaseModel):
    """7.4c-e/§3.1.4: same hand-entered-by-an-admin shape as Jira's
    credentials endpoint, simpler because Linear has a single global API
    endpoint (no per-tenant `base_url` — see `linear_crypto.py`'s module
    docstring) and a single-secret credential (no email, just one API key).
    `team_key` is not secret and is stored in the clear on `integration`;
    `api_key` is the real credential, encrypted at rest via `linear_crypto`
    before it ever reaches the database."""
    team_key: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{0,9}$",
                          description="Linear team key, e.g. ENG")
    api_key: str


class LinearCredentialsOut(BaseModel):
    integration_id: int
    team_key: str
    installed_at: str


class DigestOut(BaseModel):
    id: int
    ingest_run_id: int
    channel: str
    status: str
    rendered_text: str
    delivered_at: str
    payload_json: str | None = None


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
    poller_task = None
    if config.INGEST_POLLER_ENABLED:
        poller_task = asyncio.create_task(ingest_worker.poll_forever())
    yield
    if poller_task is not None:
        poller_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await poller_task
    db.close_pools()


app = FastAPI(title="ARGUS", version="7.5", lifespan=lifespan)


@app.get("/v1/health")
def health() -> dict[str, Any]:
    with db.unbound_app_tx() as conn:
        conn.execute("SELECT 1")
    return {"status": "ok", "phase": "7.5"}


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


@app.post("/v1/admin/tenants/{slug}/ingest/run-now", status_code=201)
def run_ingest_now(slug: str, _: Admin) -> dict[str, Any]:
    """7.4c-c: manual trigger for an ingest run. Runs synchronously and returns
    the result. Inserts row directly as 'running' so poller won't double-claim it."""
    with db.admin_tx() as conn:
        tenant = conn.execute("SELECT id, slug FROM tenant WHERE slug=%s", (slug,)).fetchone()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such tenant")
    tid = str(tenant["id"])
    at = now_iso()
    with db.tenant_tx(tid) as conn:
        run = conn.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at)"
            " VALUES (%s,'manual','running',%s) RETURNING id",
            (tid, at),
        ).fetchone()
        _audit(conn, tid, "admin", "ingest.run_now", "ok", f"run_id={run['id']}")
    res = ingest_worker.run_one(tid, tenant["slug"], run["id"])
    return {
        "status": res["status"],
        "ingest_run_id": run["id"],
        # A real, pre-existing bug found and fixed while testing 7.4c-d, not
        # this step's own change: `run_one` has always returned a FLAT dict
        # (`status`, `work_items_ingested`, ...), never one nested under a
        # `"detail"` key — so `res.get("detail", {})` silently discarded
        # every field the response was supposed to carry, on every call,
        # since 7.4c-c shipped it. `test_run_now_runs_synchronously_and_
        # returns_the_real_outcome` already asserted the correct shape
        # (`body["detail"]["work_items_ingested"]`); nothing in app.py ever
        # matched it. Caught establishing this session's test baseline, not
        # assumed correct because the endpoint returned 201.
        "detail": {k: v for k, v in res.items() if k not in ("status", "run_id")},
    }


@app.post("/v1/admin/tenants/{slug}/jira/credentials", response_model=JiraCredentialsOut,
         status_code=201)
def set_jira_credentials(slug: str, body: JiraCredentialsIn, _: Admin) -> JiraCredentialsOut:
    """7.4c-d/§3.1.4: an ARGUS admin (Claude, during onboarding) configures
    one Jira project's live credentials for a tenant. No install flow to
    redirect through — this endpoint IS the install, same operational
    shape as Blocker 2's hand-entered Slack app secrets.

    Idempotent per (tenant, project): calling again for the same
    `project_key` updates that integration's credential in place (a
    rotated API token, a corrected email) rather than creating a second
    row — `integration`'s own UNIQUE (tenant_id, source_id,
    external_account_id) already enforces this is the right key.
    """
    if not config.JIRA_CREDENTIAL_KEY:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "ARGUS_JIRA_CREDENTIAL_KEY is not configured on this host — "
                            "refusing to store a Jira credential in the clear.")
    with db.admin_tx() as conn:
        tenant = conn.execute("SELECT id FROM tenant WHERE slug=%s", (slug,)).fetchone()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such tenant")
    tid = str(tenant["id"])
    at = now_iso()
    ciphertext = jira_crypto.encrypt_credential(body.email, body.api_token, tid)
    with db.tenant_tx(tid) as conn:
        source = conn.execute("SELECT id FROM source WHERE name='jira'").fetchone()
        if source is None:
            # Every tenant is seeded with a 'jira' source row at creation
            # (argus_seed_tenant_sources, roles.sql) — reaching here would
            # mean that seeding itself regressed, not a normal runtime state.
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                "tenant has no 'jira' source row — seeding regression")
        row = conn.execute(
            """INSERT INTO integration (tenant_id, source_id, external_account_id,
                                        display_name, scope, credential_ref, installed_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, source_id, external_account_id)
               DO UPDATE SET display_name=EXCLUDED.display_name,
                             credential_ref=EXCLUDED.credential_ref,
                             installed_at=EXCLUDED.installed_at,
                             revoked_at=NULL
               RETURNING id, installed_at""",
            (tid, source["id"], body.project_key, body.base_url, "project",
             ciphertext, at),
        ).fetchone()
        _audit(conn, tid, "admin", "jira.credentials", "ok", body.project_key)
    return JiraCredentialsOut(integration_id=row["id"], project_key=body.project_key,
                              base_url=body.base_url, installed_at=row["installed_at"])


@app.post("/v1/admin/tenants/{slug}/linear/credentials", response_model=LinearCredentialsOut,
         status_code=201)
def set_linear_credentials(slug: str, body: LinearCredentialsIn, _: Admin) -> LinearCredentialsOut:
    """7.4c-e/§3.1.4: same operational shape as `set_jira_credentials` above
    — an ARGUS admin configures one Linear team's live API key for a
    tenant, idempotently per (tenant, team). No `base_url` field: Linear
    has one global API endpoint, already seeded onto this tenant's
    `source` row at creation (`argus_seed_tenant_sources`, roles.sql).
    """
    if not config.LINEAR_CREDENTIAL_KEY:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "ARGUS_LINEAR_CREDENTIAL_KEY is not configured on this host — "
                            "refusing to store a Linear credential in the clear.")
    with db.admin_tx() as conn:
        tenant = conn.execute("SELECT id FROM tenant WHERE slug=%s", (slug,)).fetchone()
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such tenant")
    tid = str(tenant["id"])
    at = now_iso()
    ciphertext = linear_crypto.encrypt_credential(body.api_key, tid)
    with db.tenant_tx(tid) as conn:
        source = conn.execute("SELECT id FROM source WHERE name='linear'").fetchone()
        if source is None:
            # Every tenant is seeded with a 'linear' source row at creation
            # (argus_seed_tenant_sources, roles.sql) — reaching here would
            # mean that seeding itself regressed, not a normal runtime state.
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                "tenant has no 'linear' source row — seeding regression")
        row = conn.execute(
            """INSERT INTO integration (tenant_id, source_id, external_account_id,
                                        display_name, scope, credential_ref, installed_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (tenant_id, source_id, external_account_id)
               DO UPDATE SET credential_ref=EXCLUDED.credential_ref,
                             installed_at=EXCLUDED.installed_at,
                             revoked_at=NULL
               RETURNING id, installed_at""",
            (tid, source["id"], body.team_key, "https://api.linear.app", "team",
             ciphertext, at),
        ).fetchone()
        _audit(conn, tid, "admin", "linear.credentials", "ok", body.team_key)
    return LinearCredentialsOut(integration_id=row["id"], team_key=body.team_key,
                                installed_at=row["installed_at"])


# --- tenant surface --------------------------------------------------------

@app.get("/v1/me")
def whoami(t: Tenant) -> dict[str, Any]:
    """7.4c-f fix (D-16x): `person` was never a real table — not here, not
    in the SQLite schema this one was modeled on (`actor.person_id` is a
    documented-unused placeholder for a future cross-source identity
    concept, schema.sql's own comment says so). Reading a table that was
    never created is the actual bug D-160 named at 7.4c-a; the fix is to
    show what this tenant genuinely has — its own `actor` rows classified
    `kind='human'` (real developers ARGUS has seen in ingested GitHub/Jira/
    Linear data), not to invent the never-built `person` table just to make
    the old query succeed. `full_name`/`email`/`is_active` (the old query's
    columns) don't exist on `actor` either — `email` in particular is a
    real, separate, NOT-yet-built gap (Slack DM matching needs it, per
    `config.py`'s own `users:read.email` scope comment) rather than
    something safe to fabricate here.
    """
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute("SELECT slug, display_name, status FROM tenant").fetchall()
        members = conn.execute(
            "SELECT id, display_name, source_key, kind FROM actor"
            " WHERE kind='human' ORDER BY id"
        ).fetchall()
    return {"tenant": rows[0] if rows else None, "visible_tenant_rows": len(rows),
            "shadow_mode": not t.may_send_dms, "shadow_until": t.shadow_until,
            "members": [dict(m) for m in members]}


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
    response: Response,
    outcome: Annotated[Literal["FIRE", "SUPPRESSED", "ABSTAIN"] | None, Query()] = None,
    limit: int = 100,
) -> list[AlertOut]:
    # 7.4c-f fix (D-16x): `w.item_key` was never a real column — neither
    # here nor in the SQLite schema this Postgres one was modeled on.
    # `sprint_filter.item_key()` (Phase 6, unchanged) computes it live from
    # `project.source_key || '#' || work_item.source_number`; this query
    # now does the same computation instead of selecting a column that has
    # never existed, matching the join shape `slack_app.py`'s own
    # `item_key_of` query already uses (`JOIN project p ON p.id =
    # w.project_id AND p.tenant_id = w.tenant_id`).
    sql = ("SELECT a.*, f.verdict AS feedback,"
           " p.source_key || '#' || w.source_number AS item_key,"
           " w.title, w.url, a.detail"
           " FROM alert a"
           " LEFT JOIN alert_feedback f ON f.alert_id = a.id"
           " LEFT JOIN work_item w ON w.id = a.work_item_id AND w.tenant_id = a.tenant_id"
           " LEFT JOIN project p ON p.id = w.project_id AND p.tenant_id = w.tenant_id")
    params: list[Any] = []
    if outcome:
        sql += " WHERE a.outcome = %s"
        params.append(outcome)
    sql += " ORDER BY a.decided_at DESC, a.id DESC LIMIT %s"
    params.append(limit)
    with db.tenant_tx(t.tenant_id) as conn:
        rows = conn.execute(sql, params).fetchall()
        # Milestone 1, Task 5.3: an orthogonal tenant-health signal, not a
        # fourth `outcome` value — see system_health.py's own docstring for
        # why. A header, not a payload key, because this endpoint's body is
        # a JSON array: there is no top-level object to hang a scalar field
        # off without breaking `response_model=list[AlertOut]`.
        health = system_health.compute_system_health(conn, t.tenant_id, now_iso())
    response.headers["X-ARGUS-System-Health"] = health.status
    return [AlertOut(**{k: r[k] for k in AlertOut.model_fields if k in r}) for r in rows]


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
    return [DigestOut(**{k: r[k] for k in DigestOut.model_fields if k in r}) for r in rows]


@app.get("/v1/digests/latest")
def latest_digest(
    t: Tenant,
    response: Response,
    format: Annotated[Literal["text", "json"] | None, Query()] = None,
) -> Any:
    with db.tenant_tx(t.tenant_id) as conn:
        row = conn.execute(
            "SELECT * FROM digest_delivery ORDER BY delivered_at DESC, id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise HTTPException(404, "No digest yet")
        # Milestone 1, Task 5.3. Scoped to the run THIS digest was built
        # from (`ingest_run_id`), not just "whatever is most recent" — a
        # lead reading an older digest (`GET /v1/digests` history, or a
        # slow-to-refresh client) should see the health that digest was
        # actually assembled under, not today's.
        health = system_health.compute_system_health(
            conn, t.tenant_id, now_iso(), run_id=row["ingest_run_id"])
    # A header, not a payload key, on this endpoint too, and deliberately
    # NOT merged into the stored `payload_json` dict: system_health is
    # evaluated fresh on every read (that is the entire point of a
    # staleness/rate-limit signal), while `payload_json` is a frozen
    # snapshot of what was rendered at digest-build time — the same
    # `digest_delivery.payload_json` `test_dashboard_contract.py` asserts
    # is byte-for-byte what a live GET returns. Folding a live-computed
    # field into that dict would make the two disagree by design and break
    # that invariant; the header keeps them separate and both honest.
    response.headers["X-ARGUS-System-Health"] = health.status
    if format == "json":
        if not row.get("payload_json"):
            raise HTTPException(409, "Digest has no structured payload")
        return json.loads(row["payload_json"])
    # 7.4c-f fix (D-16x): a real, separate bug from the item_key/person
    # ones above, only surfaced once `test_dashboard_contract.py`'s
    # skipped tests were unblocked this session (a staged Phase 6 SQLite
    # fixture had never been available before). `DigestOut` declares
    # `payload_json: str | None = None` for the format=json path's own
    # response shape reuse — but returning a `DigestOut` instance here
    # ALWAYS serializes that field (as the real value, or `null`), even
    # though CONTRACT.md's own text-format contract says it must be absent
    # entirely, not merely empty. A plain dict, built the same way but
    # excluding that one key, is what actually keeps the key out of the
    # JSON rather than present-and-null.
    out = {k: row[k] for k in DigestOut.model_fields if k in row and k != "payload_json"}
    out["system_health"] = health.status
    return out


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
        return _status(
            "warn", "Already configured",
            "<p>An App ID is already set on this deployment. Unset "
            "<code>ARGUS_GITHUB_APP_ID</code> and restart first if you meant to create a "
            "brand-new App.</p>",
            409, pill="Already set up")
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
        f'<tr><td class="k"><code>{k}</code></td>'
        f'<td><textarea readonly rows=3 spellcheck="false">{v}</textarea></td></tr>'
        for k, v in fields
    )
    body = (
        '<div class="card card--ok">'
        '<span class="badge badge-ok"><span class="dot"></span>App created</span>'
        '<h1 style="margin-top:var(--s3)">ARGUS Stall Radar App created</h1>'
        "<p>Copy each value below into this host's environment variables, then "
        "restart the service. This page will not show these again &mdash; if you lose "
        "them, delete the App on GitHub and run the manifest flow again.</p>"
        '<div class="warn"><b>Shown once.</b> Nothing on this page is written to disk by '
        "ARGUS; the private key in particular exists here and nowhere else.</div>"
        f"<h2>Environment variables</h2><table>{rows}</table>"
        "</div>"
    )
    return HTMLResponse(web_theme.document("ARGUS Stall Radar App created", body,
                                           tag="setup", wide=True))


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
        return _status(
            "urgent", "Missing setup token",
            "<p>This install link is missing its one-time token. Ask for a fresh install "
            "link rather than reusing an old one &mdash; nothing has been connected.</p>",
            400, pill="Link incomplete")
    token_hash = github_app.hash_claim_token(state)
    at = now_iso()
    with db.unbound_app_tx() as conn:
        row = conn.execute(
            "SELECT * FROM argus_claim_installation(%s,%s,%s,%s,%s,%s)",
            (token_hash, installation_id, "", "", "", at),
        ).fetchone()
    if row is None:
        return _status(
            "urgent", "This install link is invalid or has expired.",
            "<p>Install links are single-use and time-limited. Ask for a fresh one and "
            "click that one instead.</p>",
            400, pill="Link expired")
    return _status(
        "ok", "ARGUS is now connected",
        "<p>You can close this tab &mdash; ARGUS will start watching the repositories "
        "you selected. Nothing is sent to anyone until your team goes live.</p>",
        pill="Connected",
        detail=f"setup_action: {html.escape(setup_action)}",
        actions=_install_actions())


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
                "SELECT argus_admin_mint_install_claim(%s,%s,%s,%s,%s)",
                (slug, token_hash, created, expires_at, "github"),
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


# ============================================================================
# Slack: multi-workspace install, events, interactivity (Phase 7.3)
#
# Five endpoints, and — as with GitHub at 7.2 — not one of them can carry a
# pilot team's API key, because the caller is Slack or a browser mid-install:
#
#   POST /v1/admin/tenants/{slug}/slack/install-link
#                             an ARGUS admin, minting the one-time link.
#   GET  /v1/slack/install    a pilot contact's browser, once. Checks the
#                             claim BEFORE sending them to Slack.
#   GET  /v1/slack/oauth/callback
#                             Slack's redirect back, carrying the code that
#                             becomes that workspace's bot token.
#   POST /v1/slack/events     Slack's servers, forever after.
#   POST /v1/slack/interactions
#                             Slack's servers, on every button and dialog.
#
# The last two are authenticated by Slack's request signature (HMAC over the
# raw body, inside a five-minute window); the middle two by the one-time
# claim token; the first by the admin secret. Same three-way split 7.2 used.
# ============================================================================


def _slack_page(title: str, body: str, status_code: int = 200, *, kind: str = "",
                pill: str | None = None, actions: str = "",
                detail: str = "") -> HTMLResponse:
    """One place that decides what a pilot contact sees mid-install.

    These pages are read by a non-technical person in the middle of setting
    ARGUS up for their team. Every one of them says what happened and what to
    do next, and none of them shows a stack trace, an internal id, or another
    tenant's name. That contract is unchanged; what changed is that they now
    render through `web_theme` in the console's own dark palette, so the tab a
    pilot contact lands on after clicking "Add to Slack" looks like the
    product rather than an unstyled browser default.

    `kind` is inferred from the status code when not given, because every
    existing call site already encodes the outcome there: 2xx is a success
    card, 4xx is the red one, 5xx the amber "not configured yet" one. Callers
    that want a different accent (a 409 that is really a warning, say) pass
    `kind` explicitly.
    """
    if not kind:
        kind = "ok" if status_code < 400 else ("urgent" if status_code < 500 else "warn")
    return HTMLResponse(
        web_theme.status_page(kind, title, f"<p>{body}</p>", pill=pill,
                              actions=actions, detail=detail),
        status_code=status_code)


async def _verified_slack_body(request: Request) -> bytes:
    """Read the raw body and refuse anything Slack did not sign.

    Reads the body FIRST and verifies those exact bytes, because the
    signature covers what was sent, not what a JSON or form parser hands back
    afterwards. Same trap as the GitHub webhook above, and the reason both
    handlers take a `Request` instead of a parsed model.
    """
    raw = await request.body()
    ok, reason = slack_app.verify_signature(
        config.SLACK_SIGNING_SECRET or "", raw,
        request.headers.get("x-slack-request-timestamp"),
        request.headers.get("x-slack-signature"))
    if not ok:
        with db.unbound_app_tx() as conn:
            _audit(conn, None, "slack", "slack.request", "denied", reason)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Slack signature rejected: {reason}")
    return raw


def _record_slack_delivery(conn, tenant_id: str, team_id: str, dedup_key: str,
                           kind: str, event_type: str | None, at: str,
                           outcome: str, detail: str | None = None) -> bool:
    """Insert the delivery ledger row. Returns False if it was already there.

    ON CONFLICT DO NOTHING plus a rowcount check, rather than SELECT-then-
    INSERT: two of Slack's retries can arrive concurrently, and the unique
    index is the only thing that actually settles which one wins.
    """
    cur = conn.execute(
        "INSERT INTO slack_event (tenant_id, team_id, dedup_key, kind, event_type,"
        " received_at, outcome, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)"
        " ON CONFLICT (tenant_id, dedup_key) DO NOTHING",
        (tenant_id, team_id, dedup_key, kind, event_type, at, outcome, detail))
    return cur.rowcount == 1


def _revoke_slack_workspace(conn, tenant_id: str, integration_id: int,
                            at: str, reason: str) -> None:
    """Mark a workspace's install dead on both tables at once.

    `integration.revoked_at` is what stops `argus_resolve_slack_team` treating
    it as live; `slack_workspace_token.revoked_at` is what frees the workspace
    to be claimed by another tenant later (the partial unique index only
    covers live rows). Missing either one leaves a half-uninstalled workspace,
    which is worse than either state on its own.
    """
    conn.execute("UPDATE integration SET revoked_at=%s WHERE id=%s", (at, integration_id))
    conn.execute(
        "UPDATE slack_workspace_token SET revoked_at=%s, revoked_reason=%s"
        " WHERE integration_id=%s AND revoked_at IS NULL", (at, reason, integration_id))


@app.post("/v1/admin/tenants/{slug}/slack/install-link", response_model=InstallLinkOut,
          status_code=201)
def create_slack_install_link(slug: str, _: Admin) -> InstallLinkOut:
    """Mints the one-time 'Add ARGUS to Slack' link for one pilot team.

    Identical construction to 7.2's GitHub install link and for the identical
    reason (D-134): the workspace never gets to say which ARGUS tenant it
    belongs to. The token decides, it is minted by an admin for one tenant,
    and it is single-use.
    """
    plaintext, token_hash = slack_app.generate_claim_token()
    created = now_iso()
    expires_at = datetime.fromtimestamp(
        time.time() + config.INSTALL_CLAIM_TTL_SECONDS, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with db.admin_tx() as conn:
            conn.execute("SELECT argus_admin_mint_install_claim(%s,%s,%s,%s,%s)",
                         (slug, token_hash, created, expires_at, "slack"))
    except psycopg.errors.RaiseException:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such tenant")
    if not config.PUBLIC_BASE_URL:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "ARGUS_PUBLIC_BASE_URL is not set on this host")
    return InstallLinkOut(
        install_url=f"{config.PUBLIC_BASE_URL}/v1/slack/install?state={plaintext}",
        token=plaintext, expires_at=expires_at)


@app.get("/v1/slack/install")
def slack_install(state: str):
    """The link a pilot contact clicks. Checks the claim, then redirects.

    The check is the point. Without it, someone holding a stale link
    authorises ARGUS inside their real workspace, gets bounced back here, and
    only then learns the link expired — having already granted permissions
    for an install that then fails. Checking first means nothing happens in
    their Slack at all and the page just says 'ask for a fresh link'.
    """
    if not (config.SLACK_CLIENT_ID and config.PUBLIC_BASE_URL):
        return _slack_page("Slack install is not configured yet",
                           "This ARGUS deployment has no Slack app credentials set. "
                           "Nothing was sent to Slack.", 503,
                           pill="Not configured")
    with db.unbound_app_tx() as conn:
        tenant_id = conn.execute("SELECT argus_install_claim_tenant(%s,%s,%s) AS t",
                                 (slack_app.hash_claim_token(state), "slack",
                                  now_iso())).fetchone()["t"]
    if tenant_id is None:
        return _slack_page(
            "This install link is invalid or has expired",
            "Install links are single-use and time-limited. Nothing has been changed in "
            "your Slack workspace &mdash; ask for a fresh link and click that one instead.",
            400, pill="Link expired")
    return RedirectResponse(slack_app.oauth_authorize_url(state), status_code=302)


@app.get("/v1/slack/oauth/callback")
def slack_oauth_callback(code: str | None = None, state: str | None = None,
                         error: str | None = None):
    """Slack's redirect back after the workspace approves (or does not).

    The one slack.com call this flow makes runs here, on the deployed host —
    never in Claude's sandbox, which has no route to slack.com (D-115). Same
    ordering trick as D-135 used for api.github.com: put the call somewhere
    that can actually make it, rather than working around where it cannot.
    """
    if error:
        return _slack_page("Install cancelled",
                           "Nothing was connected. You can click your install link again "
                           "whenever you're ready.", 400, kind="muted",
                           pill="Cancelled",
                           detail=f"Slack reported: {html.escape(error)}")
    if not code or not state:
        return _slack_page("Incomplete Slack response",
                           "Slack's redirect was missing its authorisation code. "
                           "Please start again from your install link.", 400,
                           pill="Incomplete")
    if not config.SLACK_TOKEN_KEY:
        # Refusing here rather than storing a live bot token in the clear.
        return _slack_page("Slack install is not configured yet",
                           "This ARGUS deployment cannot store workspace credentials "
                           "securely yet. Nothing was connected.", 503,
                           pill="Not configured")
    try:
        install = slack_app.exchange_oauth_code(code)
    except slack_app.SlackError as exc:
        return _slack_page("Slack refused the install",
                           "Nothing was connected. Ask for a fresh install link and try "
                           "again.", 400, pill="Refused",
                           detail=f"Slack reported: {html.escape(exc.error)}")
    except slack_app.SlackNotConfigured as exc:
        return _slack_page("Slack install is not configured yet", html.escape(str(exc)),
                           503, pill="Not configured")

    at = now_iso()
    token_hash = slack_app.hash_claim_token(state)

    # Learn the tenant BEFORE encrypting, because slack_crypto binds the
    # tenant id into the ciphertext as associated data — a token copied from
    # one tenant's row into another's then fails to authenticate instead of
    # decrypting. This peek does not redeem anything; the claim function
    # below re-checks `redeemed_at IS NULL` atomically, so two callbacks
    # racing on one token still produce exactly one install.
    with db.unbound_app_tx() as conn:
        tenant_id = conn.execute("SELECT argus_install_claim_tenant(%s,%s,%s) AS t",
                                 (token_hash, "slack", at)).fetchone()["t"]
    if tenant_id is None:
        return _slack_page(
            "This install link is invalid or has expired",
            "Install links are single-use. Ask for a fresh one &mdash; nothing has been "
            "connected.", 400, pill="Link expired")
    tenant_id = str(tenant_id)
    ciphertext = slack_crypto.encrypt_token(install.access_token, tenant_id)

    with db.unbound_app_tx() as conn:
        row = conn.execute(
            "SELECT * FROM argus_claim_slack_workspace(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (token_hash, install.team_id, install.team_name, install.bot_user_id,
             install.app_id, install.installer_user_id, install.scopes,
             ciphertext, slack_crypto.KEY_VERSION, at)).fetchone()
        if row["out_status"] == "bad_claim":
            return _slack_page(
                "This install link is invalid or has expired",
                "Install links are single-use. Ask for a fresh one &mdash; nothing has "
                "been connected.", 400, pill="Link expired")
        if row["out_status"] == "team_taken":
            return _slack_page(
                "This Slack workspace is already connected to ARGUS",
                "A workspace can be connected to one ARGUS team at a time. Remove the "
                "existing ARGUS app from this workspace first, then use your install "
                "link again.", 409, kind="warn", pill="Already connected")
        _audit(conn, tenant_id, f"slack:{install.team_id}", "slack.install", "ok",
               install.team_name or install.team_id)
    return _slack_page(
        "ARGUS is now connected to Slack",
        f"Workspace <b>{html.escape(install.team_name or install.team_id)}</b> is "
        "connected. You can close this tab. ARGUS will only ever send direct messages "
        "about work it has flagged &mdash; it cannot read your channels or your message "
        "history.",
        pill="Connected", actions=_install_actions(slack=True))


@app.post("/v1/slack/events")
async def slack_events(request: Request) -> dict[str, Any]:
    """Slack's Events API. Signature, then handshake, then route, then dedup.

    Returns 200 for nearly everything on purpose. Slack retries any delivery
    it does not see a 2xx for, three times, and an event ARGUS legitimately
    does not care about is not a failure — answering 500 to it just produces
    three more copies of the same non-event.
    """
    raw = await _verified_slack_body(request)
    try:
        envelope = json.loads(raw) if raw else {}
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed JSON body")

    # Slack's one-time ownership check when the Request URL is first saved.
    if envelope.get("type") == "url_verification":
        return {"challenge": envelope.get("challenge")}

    if envelope.get("type") != "event_callback":
        return {"status": "ignored", "reason": f"unhandled envelope {envelope.get('type')!r}"}

    team_id = envelope.get("team_id") or ""
    event = envelope.get("event") or {}
    event_type = event.get("type") or ""
    at = now_iso()

    with db.unbound_app_tx() as conn:
        resolved = conn.execute("SELECT * FROM argus_resolve_slack_team(%s)",
                                (team_id,)).fetchone()
    if resolved is None:
        # Unlike GitHub, this is not a normal waiting state: a workspace
        # cannot send ARGUS events without having installed it, and installing
        # requires redeeming a claim. So it is recorded rather than shrugged
        # at — it means a workspace we have no record of is talking to us.
        with db.unbound_app_tx() as conn:
            _audit(conn, None, f"slack:{team_id}", "slack.event", "denied",
                   f"unknown team, event={event_type}")
        return {"status": "unresolved", "reason": "no tenant for this Slack workspace"}
    if resolved["tenant_status"] == "suspended":
        return {"status": "ignored", "reason": "tenant suspended"}

    tenant_id = str(resolved["tenant_id"])
    dedup_key = slack_app.event_dedup_key(envelope)
    with db.tenant_tx(tenant_id) as conn:
        outcome = "uninstalled" if event_type in slack_app.UNINSTALL_EVENTS else "ignored"
        if not _record_slack_delivery(conn, tenant_id, team_id, dedup_key, "event",
                                      event_type, at, outcome):
            return {"status": "duplicate", "event": event_type}
        if event_type in slack_app.UNINSTALL_EVENTS:
            _revoke_slack_workspace(conn, tenant_id, resolved["integration_id"], at,
                                    event_type)
            _audit(conn, tenant_id, f"slack:{team_id}", "slack.uninstall", "ok", event_type)
            return {"status": "ok", "event": event_type, "action": "workspace_revoked"}
    return {"status": "ok", "event": event_type}


@app.post("/v1/slack/interactions")
async def slack_interactions(request: Request) -> Any:
    """Every button press and dialog submission from every pilot workspace.

    Slack posts these as `application/x-www-form-urlencoded` with the real
    payload in a single `payload` field, and signs the raw form body — so the
    body is verified first and only then parsed, same as the events endpoint.

    Slack also gives this endpoint three seconds before it retries. Everything
    below is one resolve, one insert and one update, plus at most one call
    back to Slack (opening the [Blocked on…] dialog, which has to happen
    inside the window by construction — Slack's `trigger_id` expires).
    """
    raw = await _verified_slack_body(request)
    form = urllib.parse.parse_qs(raw.decode("utf-8"))
    payload_raw = (form.get("payload") or [""])[0]
    try:
        payload = json.loads(payload_raw) if payload_raw else {}
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed interaction payload")

    team = payload.get("team") or {}
    team_id = team.get("id") or (payload.get("user") or {}).get("team_id") or ""
    at = now_iso()

    with db.unbound_app_tx() as conn:
        resolved = conn.execute("SELECT * FROM argus_resolve_slack_team(%s)",
                                (team_id,)).fetchone()
    if resolved is None or resolved["revoked_at"] is not None:
        with db.unbound_app_tx() as conn:
            _audit(conn, None, f"slack:{team_id}", "slack.interaction", "denied",
                   "unknown or revoked workspace")
        # 200 rather than 4xx: the person clicking is a developer in someone's
        # Slack, and Slack renders a non-2xx to them as a red error banner.
        # There is nothing they can do about our routing.
        return {"status": "unresolved"}
    if resolved["tenant_status"] == "suspended":
        return {"status": "ignored", "reason": "tenant suspended"}

    tenant_id = str(resolved["tenant_id"])
    dedup_key = slack_app.interaction_dedup_key(payload)
    with db.tenant_tx(tenant_id) as conn:
        if not _record_slack_delivery(conn, tenant_id, team_id, dedup_key, "interaction",
                                      payload.get("type"), at, "pending"):
            return {"status": "duplicate"}
        transport = slack_app.transport_for(conn, tenant_id, resolved["integration_id"])
        result = slack_app.handle_interaction(conn, tenant_id, payload, transport, at)
        conn.execute(
            "UPDATE slack_event SET outcome=%s, detail=%s WHERE tenant_id=%s AND dedup_key=%s",
            (result.action, result.reason[:500], tenant_id, dedup_key))
        if result.handled and result.action == "response_recorded":
            _audit(conn, tenant_id, f"slack:{team_id}", "slack.triage_response", "ok",
                   f"{result.response_type} on triage_message {result.triage_message_id}")
    # A view_submission validation error has to come back as Slack's own
    # response_action shape or the dialog silently closes on an empty answer.
    return result.response_body if result.response_body is not None else {}
