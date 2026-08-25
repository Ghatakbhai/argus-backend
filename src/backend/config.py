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

# --- Phase 7.3: the Slack app's own credentials ---------------------------
# ONE Slack app, installed by N pilot workspaces (Slack calls this
# "distribution"). Exactly like the GitHub App above, these are deployment
# credentials rather than tenant data, so they live in the host environment
# and never in Postgres. What DOES go in Postgres is each workspace's own bot
# token, encrypted — see slack_crypto.py and D-143.
SLACK_CLIENT_ID = os.environ.get("ARGUS_SLACK_CLIENT_ID")
SLACK_CLIENT_SECRET = os.environ.get("ARGUS_SLACK_CLIENT_SECRET")
SLACK_SIGNING_SECRET = os.environ.get("ARGUS_SLACK_SIGNING_SECRET")

# The key that encrypts every workspace bot token at rest. Any string works —
# slack_crypto derives a 32-byte AES key from it by SHA-256 — so Render's
# "Generate Value" can produce it with no typing and no format rules for a
# non-technical owner to get wrong. Losing it means every pilot workspace has
# to reinstall; it does NOT mean anyone else can read the tokens.
SLACK_TOKEN_KEY = os.environ.get("ARGUS_SLACK_TOKEN_KEY")

# This service's own public URL. Slack requires the OAuth redirect_uri to
# match the one registered on the app exactly, so it cannot be inferred from
# the incoming request (a proxy, a custom domain, or a stray trailing slash
# would each silently break the exchange).
PUBLIC_BASE_URL = os.environ.get("ARGUS_PUBLIC_BASE_URL", "").rstrip("/")

# Every scope the pilot needs, requested once at install.
#
# 6.5 took the opposite approach deliberately — request only what the current
# step uses, add more later — and that was right for one hand-installed
# workspace. It is wrong for a distributed app: Slack has no way to add a
# scope to an existing install, so every widening forces all fifteen pilot
# teams to reinstall. The 6.7 presence scope (`users.profile:read`), which 6.5
# consciously left out and planned to add later, is included here for exactly
# that reason (D-145).
SLACK_BOT_SCOPES = ",".join([
    "chat:write",            # send the triage DM
    "im:write",              # open a DM conversation with someone
    "users:read",            # look up a Slack account
    "users:read.email",      # match that account to a GitHub/Jira identity
    "users.profile:read",    # step 6.7's out-of-office suppression
])

# Slack's own documented replay window for signed requests.
SLACK_REQUEST_MAX_AGE_SECONDS = int(
    os.environ.get("ARGUS_SLACK_REQUEST_MAX_AGE_SECONDS", "300"))

# --- Phase 7.4c-c: the in-process ingestion poller -------------------------
# Enabled only when explicitly requested (e.g. on Render with
# ARGUS_INGEST_POLLER_ENABLED=1). Off by default so tests and dev environments
# don't run an un-mocked background loop against live api.github.com.
INGEST_POLLER_ENABLED = bool(int(os.environ.get("ARGUS_INGEST_POLLER_ENABLED", "0")))
INGEST_POLL_INTERVAL_SECONDS = float(
    os.environ.get("ARGUS_INGEST_POLL_INTERVAL_SECONDS", "30.0"))

# --- Phase 7.4c-d: Jira credential storage (§3.1.4) -------------------------
# Jira has no App-install flow the way GitHub/Slack do — Blocker 4's design
# (docs/PHASE7_5_OPERATIONAL_CHECKLIST.md §3.1.4) calls for generalizing
# slack_crypto.py's proven AES-256-GCM-at-rest pattern rather than inventing
# a second scheme. Deliberately a SEPARATE key from ARGUS_SLACK_TOKEN_KEY,
# not reused: the two secrets protect different tenants' data end to end
# (a Jira email+API-token pair vs. a Slack bot token) and rotating one must
# never require touching the other. Same non-technical-owner-friendly rule
# as SLACK_TOKEN_KEY — any string works, Render's "Generate Value" needs no
# format knowledge — and the same consequence of losing it: every pilot's
# Jira credentials would need re-entering, nothing else is compromised.
JIRA_CREDENTIAL_KEY = os.environ.get("ARGUS_JIRA_CREDENTIAL_KEY")

# --- Phase 7.4c-e: Linear credential storage (§3.1.4) -----------------------
# Same reasoning as JIRA_CREDENTIAL_KEY immediately above, and deliberately
# its own separate key rather than reused — see linear_crypto.py's module
# docstring for why this session chose not to share ARGUS_JIRA_CREDENTIAL_KEY
# despite jira_crypto.py's own docstring floating that as an option.
LINEAR_CREDENTIAL_KEY = os.environ.get("ARGUS_LINEAR_CREDENTIAL_KEY")
