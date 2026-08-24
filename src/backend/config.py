"""ARGUS Phase 7.1 — configuration.

Every value is an environment variable with a development default, because the
one thing this file must never do is hold a real credential. Same discipline as
D-087 and as `integration.credential_ref` in the schema: pointers, not secrets.
"""
import os

PGHOST = os.environ.get("ARGUS_PGHOST", "/var/run/postgresql")
PGPORT = os.environ.get("ARGUS_PGPORT", "5432")
PGDATABASE = os.environ.get("ARGUS_PGDATABASE", "argus")
# "prefer" is a no-op over a local unix socket (the sandbox/local-dev case)
# and negotiates TLS over TCP to a remote host (Render's managed Postgres)
# without Dirgh having to know what sslmode means.
PGSSLMODE = os.environ.get("ARGUS_PGSSLMODE", "prefer")

# roles.sql creates argus_app/argus_admin with these exact literal passwords
# — harmless on a local sandbox nobody outside this container can reach, a
# real problem the moment bootstrap_schema_if_needed() runs against a
# database with a public IP (step 7.2). Setting ARGUS_APP_DB_PASSWORD /
# ARGUS_ADMIN_DB_PASSWORD (Render's "Generate Value" needs no typing from
# Dirgh at all) means bootstrap immediately ALTERs both roles to a real
# random password on first boot — the values below are the local-dev
# fallback only, never what actually protects a deployed database.
APP_DB_PASSWORD = os.environ.get("ARGUS_APP_DB_PASSWORD", "app_dev_password")
ADMIN_DB_PASSWORD = os.environ.get("ARGUS_ADMIN_DB_PASSWORD", "admin_dev_password")

# The API process authenticates as argus_app. It is deliberately a different,
# weaker role than the one the /v1/admin endpoints use.
APP_DSN = os.environ.get(
    "ARGUS_APP_DSN",
    f"host={PGHOST} port={PGPORT} dbname={PGDATABASE} user=argus_app"
    f" password={APP_DB_PASSWORD} sslmode={PGSSLMODE}",
)
ADMIN_DSN = os.environ.get(
    "ARGUS_ADMIN_DSN",
    f"host={PGHOST} port={PGPORT} dbname={PGDATABASE} user=argus_admin"
    f" password={ADMIN_DB_PASSWORD} sslmode={PGSSLMODE}",
)

# Step 7.2 only: a full-privilege connection string, used exactly once per
# database (db.bootstrap_schema_if_needed) to apply schema_pg.sql and
# roles.sql to a brand-new managed Postgres with no manual `psql -f` step.
# On Render this is the connection string Render itself generates when the
# Postgres instance is created — never a credential ARGUS invents. Left
# unset, bootstrap is skipped entirely (local dev already migrates via
# conftest.py / a superuser psql session directly).
OWNER_DSN = os.environ.get("ARGUS_OWNER_DSN")

# The admin secret gates tenant creation and key issuance. No pilot team ever
# receives it. In production this comes from the host's secret store; the
# default below exists so the test suite can run, and the app refuses to start
# in production mode while it is still set.
ADMIN_SECRET = os.environ.get("ARGUS_ADMIN_SECRET", "dev-admin-secret-change-me")
ENVIRONMENT = os.environ.get("ARGUS_ENV", "development")

KEY_PREFIX_LEN = 20

# --- Phase 7.2: the GitHub App's own credentials ---------------------------
# ONE App, shared by every pilot tenant's installation of it — not per-tenant
# data, so (same discipline as ADMIN_SECRET) these live only in environment
# variables on the host, never in Postgres and never in a tracked file. All
# five are unset until step 7.2's manifest flow has actually run once; the
# webhook and JWT helpers in github_app.py raise a clear error naming which
# one is missing rather than silently doing nothing.
GITHUB_APP_ID = os.environ.get("ARGUS_GITHUB_APP_ID")
GITHUB_APP_SLUG = os.environ.get("ARGUS_GITHUB_APP_SLUG")  # for building install links
GITHUB_APP_PRIVATE_KEY_PEM = os.environ.get("ARGUS_GITHUB_APP_PRIVATE_KEY")
GITHUB_WEBHOOK_SECRET = os.environ.get("ARGUS_GITHUB_WEBHOOK_SECRET")

# Guards the one-time manifest-conversion callback (/v1/admin/github/callback),
# which GitHub's browser redirect hits directly and which therefore cannot
# carry the normal x-admin-key header. Only needed for the single session that
# creates the App; safe to leave set afterwards since the callback also
# refuses to run again once GITHUB_APP_ID is already configured.
GITHUB_SETUP_SECRET = os.environ.get("ARGUS_GITHUB_SETUP_SECRET", "dev-setup-secret-change-me")

# How long a pilot team's install-link claim token stays valid before an
# admin has to reissue it. Generous, because it is a one-click link Claude
# hands to a non-technical pilot contact, not a live session.
INSTALL_CLAIM_TTL_SECONDS = int(os.environ.get("ARGUS_INSTALL_CLAIM_TTL_SECONDS", str(7 * 24 * 3600)))
