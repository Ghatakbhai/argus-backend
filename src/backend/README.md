# `src/backend/` — the multi-tenant backend (Phases 7.1 – 7.3)

Everything here is new at step 7.1, 7.2 or 7.3, and nothing outside this folder
was modified: the Phase 6 engine (`src/detectors.py`, `src/sprint_filter.py`,
`src/digest.py`, the adapters) is untouched and still runs on SQLite exactly
as it did.

| File | What it is |
|---|---|
| `schema_pg.sql` | The whole PostgreSQL database, including the tenant plumbing (7.1) and the GitHub App installation lifecycle (7.2). Applying it fails loudly if any table escaped row-level security. |
| `roles.sql` | The three database accounts and precisely what each may do. |
| `config.py` | Settings, all environment variables. No credential is written here. |
| `db.py` | The one place a tenant is bound to a request (`tenant_tx()`). Also: `bootstrap_schema_if_needed()` — self-migrates a brand-new database on first boot (7.2). |
| `auth.py` | API key generation and hashing. |
| `github_app.py` | The GitHub App itself (7.2): manifest, webhook HMAC verification, App JWTs, installation tokens, install-claim tokens. |
| `schema_7_3_slack.sql` | Everything 7.3 adds to the database. Re-applied on EVERY boot, safely — see `db.INCREMENTAL_MIGRATIONS` and D-141. This is the file a future phase adds to; `schema_pg.sql` only ever runs against an empty database, which the live one no longer is. |
| `slack_app.py` | The Slack app (7.3): app manifest, OAuth v2 install flow, request-signature verification, per-workspace Slack client, and the Postgres port of Phase 6.6's button/modal handling. |
| `slack_crypto.py` | Encrypts each workspace's bot token at rest (7.3, D-143). The key lives only in the host environment. |
| `make_slack_app_page.py` | Generates `docs/CREATE_ARGUS_SLACK_APP.html`, the page Dirgh uses to create the Slack app. Unlike the GitHub one, it contains no secret. |
| `verify_slack_live.py` | 14 checks over real HTTP against a running server — catches what a test client structurally cannot. |
| `app.py` | The FastAPI service. |
| `migrate_sqlite.py` | Loads an existing Phase 6 SQLite database into one tenant. |
| `requirements.txt`, `render.yaml` | Deployment for Render's $0 tier. Verified live at D-139 — this is the blueprint the running service was built from. |
| `tests/` | 133 checks: 44 from 7.1 (19 adversarial isolation, 19 over HTTP, 6 against Phase 6's real live database), 23 from 7.2 (webhooks, install-claim flow, manifest callback, self-migration), and 66 from 7.3 (58 on the Slack surface, 8 on the upgrade path). The 7 that need Phase 6's saved SQLite database skip unless it is present. |

Full write-up: `docs/PHASE7_1_MULTITENANT_BACKEND.md` (D-124–D-132),
`docs/PHASE7_2_GITHUB_APP.md` (D-133–D-139) and
`docs/PHASE7_3_SLACK_APP.md` (D-140–D-147).

## Running it (for a future session, not for Dirgh)

```
createdb argus
psql -d argus -v ON_ERROR_STOP=1 -f schema_pg.sql
psql -d argus -v ON_ERROR_STOP=1 -f roles.sql
python -m pytest src/backend/tests -q
python -m uvicorn backend.app:app
```

Core environment variables: `ARGUS_APP_DSN`, `ARGUS_ADMIN_DSN`,
`ARGUS_ADMIN_SECRET`, `ARGUS_ENV`. The service refuses to start with
`ARGUS_ENV=production` while the admin secret is still the development
default.

Phase 7.2 adds: `ARGUS_OWNER_DSN` (self-migration, see `db.py`),
`ARGUS_APP_DB_PASSWORD` / `ARGUS_ADMIN_DB_PASSWORD` (rotate the two roles'
real passwords away from the literals in `roles.sql` — set these on any
deployment with a public IP), `ARGUS_PUBLIC_BASE_URL`,
`ARGUS_GITHUB_SETUP_SECRET`, and — only once the manifest flow has run —
`ARGUS_GITHUB_APP_ID` / `ARGUS_GITHUB_APP_SLUG` / `ARGUS_GITHUB_WEBHOOK_SECRET`
/ `ARGUS_GITHUB_APP_PRIVATE_KEY`.

Phase 7.3 adds: `ARGUS_SLACK_CLIENT_ID`, `ARGUS_SLACK_CLIENT_SECRET`,
`ARGUS_SLACK_SIGNING_SECRET` (all three from the Slack app's Basic
Information page, once it exists) and `ARGUS_SLACK_TOKEN_KEY` — any random
string; it is what encrypts every workspace's bot token before storage. With
none of them set the service starts normally, GitHub is unaffected, and every
Slack endpoint refuses politely. That state has its own tests.

`ARGUS_PUBLIC_BASE_URL` becomes load-bearing at 7.3: Slack requires the OAuth
redirect URL to match exactly, so it cannot be inferred from the request.
