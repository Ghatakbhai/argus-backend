"""ARGUS 7.4c-c — the in-process ingestion poller and the manual admin
run-now trigger.

Everything BEFORE this module already exists and is unchanged: 7.4c-a's
scratch-DB plumbing (`migrate_sqlite.migrate` / `.record_phase6_run`, both
already accepting an open `sqlite3.Connection`, D-160) and 7.4c-b's GitHub
fetch/orchestration layer (`github_live_ingest.build_scratch_db` /
`.ingest_installation`, D-161). This module is the layer §3.1.2/§3.1.5 named
as still missing: the thing that actually decides WHEN those run, for WHICH
tenant, against a real `ingest_run` row — the in-process poller (a background
`asyncio` loop, per D-159's locked decision: no new Render service) and the
manual `POST /v1/admin/tenants/{slug}/ingest/run-now` trigger app.py exposes.

Two entry points into the one real function (`run_one`) below:
  - the poller (`poll_forever` -> `claim_and_run_one`), which finds and
    claims the oldest QUEUED run across every tenant via the
    `argus_claim_next_queued_run` SECURITY DEFINER function
    (`schema_7_4c_ingest_worker.sql`) before calling `run_one`.
  - the run-now endpoint (app.py), which already knows which tenant and
    inserts its own 'running' row directly, then calls `run_one` the same
    way.

`run_one` itself is synchronous, deliberately: it is a live GitHub fetch plus
sqlite plus Postgres, none of it `async`-native in this codebase (the same
shape `migrate_sqlite`/`github_live_ingest` already are). The poller runs it
via `asyncio.to_thread` so it never blocks the event loop other requests
share; the run-now endpoint gets this for free because FastAPI already runs a
sync `def` endpoint in its own worker thread.
"""
from __future__ import annotations

import asyncio
import logging

from . import config, db, github_app, migrate_sqlite
from .auth import now_iso

# `github_live_ingest` and the frozen Phase 6 engine it calls into
# (`digest`/`sprint_filter`) live one directory up, in src/ — the same layout
# every other backend module that reaches into src/ relies on.
# `migrate_sqlite` (imported above) already puts that directory on
# `sys.path` as a side effect of its own module-level `from . import
# dashboard_payload` (see dashboard_payload.py's docstring); importing it
# before this module's own `import github_live_ingest` below is what makes
# that import resolve regardless of which module a caller imports first.
import github_live_ingest as GLI  # noqa: E402

logger = logging.getLogger("argus.ingest_worker")

# One cache for the whole process, not one per run: installation tokens last
# an hour and are shared across every tenant's runs, exactly the usage
# `github_app.InstallationTokenCache`'s own docstring describes. A module-
# level singleton here is the same pattern `db.py` uses for its connection
# pools (`_app_pool` / `_admin_pool`).
_TOKEN_CACHE = github_app.InstallationTokenCache()


class NoGitHubInstallation(RuntimeError):
    """Raised when a tenant has no live (unrevoked) GitHub integration to
    ingest from — a real, expected state (a tenant mid-onboarding, or one
    whose only integration was uninstalled), not a bug. `run_one` catches
    this the same as any other failure and records it on the run row rather
    than letting it propagate."""


def _github_installation_id(conn, tenant_id: str) -> str | None:
    """The installation id (GitHub's, stored as `integration.
    external_account_id` by the `/v1/github/setup` claim flow, D-134) for
    this tenant's live GitHub connection, or None if it has none. Reads
    inside the caller's own `tenant_tx` — ordinary tenant-scoped RLS, no
    cross-tenant reach needed here, unlike the claim function below."""
    row = conn.execute(
        "SELECT i.external_account_id FROM integration i"
        " JOIN source s ON s.id = i.source_id AND s.tenant_id = i.tenant_id"
        " WHERE s.name = 'github' AND i.revoked_at IS NULL"
        " ORDER BY i.installed_at LIMIT 1"
    ).fetchone()
    return row["external_account_id"] if row else None


def run_one(tenant_id: str, tenant_slug: str, run_id: int) -> dict:
    """Runs §3.1.2 steps 2-6 to completion for one already-'running'
    `ingest_run` row, and always leaves that row in a terminal state
    ('succeeded' or 'failed') before returning — never 'running' forever.

    Caller's responsibility, not this function's: the row must already exist
    and already be 'running' (the poller does this atomically at claim time;
    the run-now endpoint inserts it as 'running' directly, since it never
    shares that row with anything else that could also claim it). This
    function does not itself flip 'queued' -> 'running' — doing that here
    too would be a second, redundant place that decision is made.
    """
    at = now_iso()
    try:
        with db.tenant_tx(tenant_id) as conn:
            installation_id = _github_installation_id(conn, tenant_id)
        if installation_id is None:
            raise NoGitHubInstallation(
                f"tenant {tenant_slug!r} has no active (unrevoked) GitHub installation")

        token = _TOKEN_CACHE.get(installation_id)

        sconn = GLI.build_scratch_db()
        try:
            summary = GLI.ingest_installation(sconn, token, at)
            migrated = migrate_sqlite.migrate(sconn, tenant_slug)
            result = migrate_sqlite.record_phase6_run(
                sconn, tenant_slug, migrated["idmap"]["work_item"],
                existing_run_id=run_id)
        finally:
            sconn.close()

        if summary.repo_errors:
            # A repo-level failure is not a run-level failure (7.4c-b's
            # isolation guarantee: "one repo's bad night must never wedge
            # the poller for the other fourteen") — the run still succeeded
            # for every repo that DID work. But it is worth recording, not
            # silently dropped just because it didn't reach the severity of
            # failing the whole run.
            detail = "; ".join(f"{repo}: {err}" for repo, err in summary.repo_errors.items())
            with db.tenant_tx(tenant_id) as conn:
                conn.execute("UPDATE ingest_run SET error_detail=%s WHERE id=%s",
                             (detail[:2000], run_id))

        return {
            "status": "succeeded", "run_id": run_id,
            "repos_seen": summary.repos_seen, "repos_failed": summary.repos_failed,
            "prs_seen": summary.prs_seen,
            "work_items_ingested": summary.work_items_ingested,
            "work_items_failed": summary.work_items_failed,
            "FIRE": result["FIRE"], "SUPPRESSED": result["SUPPRESSED"],
            "ABSTAIN": result["ABSTAIN"],
        }
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}"
        logger.warning("ingest_run %s (tenant %s) failed: %s", run_id, tenant_slug, detail)
        with db.tenant_tx(tenant_id) as conn:
            conn.execute(
                "UPDATE ingest_run SET status='failed', finished_at=%s, error_detail=%s"
                " WHERE id=%s", (now_iso(), detail[:2000], run_id))
        return {"status": "failed", "run_id": run_id, "error": detail}


def claim_and_run_one() -> bool:
    """Claims and fully processes the single oldest queued `ingest_run`, if
    any exists, across every tenant. Returns True if it found and processed
    one, False if the queue was empty — the poller uses this to decide
    whether to check again immediately (drain a burst) or sleep (nothing to
    do).
    """
    with db.admin_tx() as conn:
        claimed = conn.execute(
            "SELECT * FROM argus_claim_next_queued_run(%s)", (now_iso(),)
        ).fetchone()
    if claimed is None or claimed["out_run_id"] is None:
        return False
    run_one(str(claimed["out_tenant_id"]), claimed["out_tenant_slug"], claimed["out_run_id"])
    return True


async def poll_forever(interval_seconds: float | None = None) -> None:
    """The background loop `app.py`'s `lifespan` starts as an `asyncio.Task`
    when `config.INGEST_POLLER_ENABLED` is set (D-159: in-process, no new
    Render service). Runs until cancelled — `lifespan` cancels it on
    shutdown and awaits the cancellation, so a restart never leaves a run
    half-claimed by a task nobody is tracking anymore.

    Each tick's actual work (`claim_and_run_one`, a live GitHub fetch plus
    sqlite plus Postgres) runs in a thread via `asyncio.to_thread` so it
    never blocks the event loop every other request on this process shares —
    the same reason `require_tenant`'s DB calls are the only other blocking
    calls this app makes directly on the loop, and those are fast, in-process
    pool checkouts; this is not.
    """
    interval = config.INGEST_POLL_INTERVAL_SECONDS if interval_seconds is None else interval_seconds
    logger.info("ingest poller starting (interval=%ss)", interval)
    try:
        while True:
            try:
                processed = await asyncio.to_thread(claim_and_run_one)
            except Exception:
                # A tick failing outright (a Postgres blip, the claim
                # function itself erroring) must not kill the loop — the
                # same "one bad night must not wedge everyone else" rule
                # `github_live_ingest.py` already applies one level down,
                # applied here one level up.
                logger.exception("ingest poller tick failed unexpectedly")
                processed = False
            if not processed:
                await asyncio.sleep(interval)
            # else: check again immediately — draining a burst of queued
            # webhook-triggered runs back-to-back, not one per interval.
    except asyncio.CancelledError:
        logger.info("ingest poller stopping")
        raise
