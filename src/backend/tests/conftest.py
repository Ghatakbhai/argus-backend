"""Shared fixtures. Every test run starts from an empty database and builds two
pilot tenants — 'acme' and 'globex' — with identically shaped data. Identical
shape matters: it means a test that passes because it read the *wrong* tenant's
row would still see plausible-looking data, so the assertions have to check
identity, not just non-emptiness.
"""
import os
import subprocess
import sys

import pytest

# tests live at src/backend/tests/, so the import root is src/
BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BACKEND))

# Phase 7.2: config.py reads these at import time, so they must be set before
# `from backend import config` below ever runs. A real (throwaway) RSA key is
# generated once per test session rather than checked in anywhere — it never
# needs to verify against a real GitHub install, only against the JWTs this
# test suite itself mints and decodes.
if "ARGUS_GITHUB_APP_PRIVATE_KEY" not in os.environ:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    _test_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    os.environ["ARGUS_GITHUB_APP_PRIVATE_KEY"] = _test_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
os.environ.setdefault("ARGUS_GITHUB_APP_ID", "999999")
os.environ.setdefault("ARGUS_GITHUB_APP_SLUG", "argus-stall-radar-test")
os.environ.setdefault("ARGUS_GITHUB_WEBHOOK_SECRET", "test-webhook-secret-for-ci")
os.environ.setdefault("ARGUS_GITHUB_SETUP_SECRET", "test-setup-secret-for-ci")

# Phase 7.3: the Slack app's credentials, same read-at-import-time rule.
os.environ.setdefault("ARGUS_SLACK_CLIENT_ID", "1234567890.0987654321")
os.environ.setdefault("ARGUS_SLACK_CLIENT_SECRET", "test-slack-client-secret")
os.environ.setdefault("ARGUS_SLACK_SIGNING_SECRET", "test-slack-signing-secret")
os.environ.setdefault("ARGUS_SLACK_TOKEN_KEY", "test-slack-token-key-any-string-works")
os.environ.setdefault("ARGUS_PUBLIC_BASE_URL", "https://argus-test.example.com")

# Phase 7.4c-d: Jira credential encryption, same read-at-import-time rule.
os.environ.setdefault("ARGUS_JIRA_CREDENTIAL_KEY", "test-jira-credential-key-any-string-works")

# Phase 7.4c-e: Linear credential encryption, same read-at-import-time rule.
# Deliberately a DIFFERENT string from the Jira key above — see
# linear_crypto.py's module docstring for why this is its own key, not a
# reuse of ARGUS_JIRA_CREDENTIAL_KEY.
os.environ.setdefault("ARGUS_LINEAR_CREDENTIAL_KEY", "test-linear-credential-key-any-string-works")

from fastapi.testclient import TestClient  # noqa: E402

from backend import config, db  # noqa: E402
from backend.app import app  # noqa: E402
from backend.auth import now_iso  # noqa: E402

ADMIN_HEADERS = {"x-admin-key": config.ADMIN_SECRET}


CI_OWNER = "argus_owner_ci"
CI_OWNER_PASSWORD = "ci-owner-pw-not-a-real-secret"


@pytest.fixture(scope="session", autouse=True)
def clean_database():
    """Rebuild the schema from the migration files, so the tests are testing the
    migration too and not a database somebody hand-patched.

    D-149: migrations are applied as a role that is deliberately NOT a
    superuser and does NOT have BYPASSRLS — matching Render's actual managed-
    Postgres owner role, which has neither. Before D-149 this fixture applied
    everything as `postgres`, a superuser, which bypasses row-level security
    unconditionally regardless of FORCE ROW LEVEL SECURITY — so every
    SECURITY DEFINER function in this schema tested clean here while being
    silently broken on the one database that actually matters. Applying as a
    role shaped like Render's is what makes this suite able to catch that
    class of bug again, rather than needing a live 500 to find it.

    argus_app and argus_admin are dropped and recreated here too, not just
    CI_OWNER — found the hard way. `bootstrap_schema_if_needed()`'s password
    sync (ALTER ROLE ... WITH PASSWORD) needs the connecting owner role to
    hold ADMIN OPTION on argus_app/argus_admin, which Postgres grants
    automatically to whichever role's CREATE ROLE actually created them.
    CI_OWNER is dropped and recreated every session, so a second local
    pytest run — with argus_app/argus_admin still standing from the first
    run's CI_OWNER, itself long gone — leaves the new CI_OWNER with no
    admin claim on roles it never created, and roles.sql's `IF NOT EXISTS`
    guard skips recreating them. Render never hits this: its owner role is
    never dropped and recreated out from under itself the way this fixture
    intentionally does CI_OWNER, so it creates argus_app/argus_admin exactly
    once and keeps ADMIN OPTION on them for the life of the database. This
    fixture drops all three roles together so every local run — not just
    the first one against a virgin cluster — actually exercises that path,
    instead of passing by accident of leftover state.
    """
    env = {**os.environ, "PGHOST": config.PGHOST}
    subprocess.run(["psql", "-U", "postgres", "-q",
                    "-c", "DROP DATABASE IF EXISTS argus;",
                    "-c", "DROP DATABASE IF EXISTS argus_upgrade_test;",
                    "-c", f"DROP ROLE IF EXISTS {CI_OWNER};",
                    "-c", "DROP ROLE IF EXISTS argus_app;",
                    "-c", "DROP ROLE IF EXISTS argus_admin;",
                    "-c", f"CREATE ROLE {CI_OWNER} LOGIN NOSUPERUSER NOBYPASSRLS "
                          f"CREATEDB CREATEROLE PASSWORD '{CI_OWNER_PASSWORD}';",
                    "-c", f"CREATE DATABASE argus OWNER {CI_OWNER};"],
                   check=True, env=env)
    owner_env = {**env, "PGPASSWORD": CI_OWNER_PASSWORD}
    # The order matches db.INCREMENTAL_MIGRATIONS exactly (the one-time pair,
    # then every incremental file in the order the deployed service applies
    # them) — so the tests exercise the real migration path, not a
    # hand-assembled one.
    for f in ("schema_pg.sql", "roles.sql", *db.INCREMENTAL_MIGRATIONS):
        subprocess.run(["psql", "-h", config.PGHOST, "-U", CI_OWNER, "-d", "argus",
                        "-v", "ON_ERROR_STOP=1", "-q", "-f", os.path.join(BACKEND, f)],
                       check=True, env=owner_env)
    yield
    db.close_pools()


@pytest.fixture(scope="session")
def client(clean_database):
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def tenants(client):
    """Create both tenants and seed one identical work item + alert into each."""
    out = {}
    for slug, name in (("acme", "Acme Rockets"), ("globex", "Globex Corp")):
        r = client.post("/v1/admin/tenants", headers=ADMIN_HEADERS,
                        json={"slug": slug, "display_name": name})
        assert r.status_code == 201, r.text
        out[slug] = r.json()
        out[slug]["headers"] = {"Authorization": f"Bearer {r.json()['api_key']}"}

    for slug in ("acme", "globex"):
        tid = out[slug]["id"]
        with db.tenant_tx(tid) as conn:
            src = conn.execute("SELECT id FROM source WHERE name='github'").fetchone()["id"]
            proj = conn.execute(
                "INSERT INTO project (tenant_id, source_id, source_key, display_name)"
                " VALUES (%s,%s,%s,%s) RETURNING id",
                (tid, src, f"{slug}/api", f"{slug}/api")).fetchone()["id"]
            snap = conn.execute(
                "INSERT INTO snapshot (tenant_id, source_id, project_id, observed_at,"
                " started_at, is_complete) VALUES (%s,%s,%s,%s,%s,1) RETURNING id",
                (tid, src, proj, "2026-08-24T00:00:00Z", "2026-08-24T00:00:00Z")).fetchone()["id"]
            actor = conn.execute(
                "INSERT INTO actor (tenant_id, source_id, source_key, kind, kind_reason)"
                " VALUES (%s,%s,%s,'human','assumed_human') RETURNING id",
                (tid, src, f"dev-{slug}")).fetchone()["id"]
            item = conn.execute(
                "INSERT INTO work_item (tenant_id, snapshot_id, project_id, source_number,"
                " kind, title, state, author_id, created_at, url)"
                " VALUES (%s,%s,%s,4,'change_request',%s,'open',%s,%s,%s) RETURNING id",
                (tid, snap, proj, f"[{slug.upper()}-3] secret internal work", actor,
                 "2026-08-20T00:00:00Z", f"https://github.com/{slug}/api/pull/4")).fetchone()["id"]
            conn.execute(
                "INSERT INTO event (tenant_id, snapshot_id, work_item_id, type, actor_id,"
                " occurred_at, counts_as_human, human_reason)"
                " VALUES (%s,%s,%s,'commented',%s,%s,1,'human')",
                (tid, snap, item, actor, "2026-08-21T00:00:00Z"))
            run = conn.execute(
                "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at,"
                " items_checked, alerts_fired, alerts_suppressed)"
                " VALUES (%s,'manual','succeeded',%s,5,1,1) RETURNING id",
                (tid, "2026-08-24T01:00:00Z")).fetchone()["id"]
            alert = conn.execute(
                "INSERT INTO alert (tenant_id, ingest_run_id, work_item_id, pattern,"
                " outcome, reason, subject_actor_id, decided_at)"
                " VALUES (%s,%s,%s,'P2-review-ghosted','FIRE','ghosted_past_48h',%s,%s)"
                " RETURNING id", (tid, run, item, actor, "2026-08-24T01:00:05Z")).fetchone()["id"]
            conn.execute(
                "INSERT INTO digest_delivery (tenant_id, ingest_run_id, channel, status,"
                " rendered_text, delivered_at) VALUES (%s,%s,'slack_dm','delivered',%s,%s)",
                (tid, run, f"{slug} standup digest: 1 flagged", "2026-08-24T01:00:10Z"))
        out[slug].update(project_id=proj, snapshot_id=snap, actor_id=actor,
                         work_item_id=item, ingest_run_id=run, alert_id=alert,
                         source_id=src)
    return out
