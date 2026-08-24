# `src/backend/` — the multi-tenant backend (Phases 7.1 + 7.2)

Everything here is new at step 7.1 or 7.2, and nothing outside this folder
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
| `app.py` | The FastAPI service. |
| `migrate_sqlite.py` | Loads an existing Phase 6 SQLite database into one tenant. |
| `requirements.txt`, `render.yaml` | Deployment prep for step 7.2's hosting (Render, $0 tier). `render.yaml` has not been verified against a live Render account. |
| `tests/` | 67 checks: the 44 from 7.1 (19 adversarial isolation, 19 over HTTP, 6 against Phase 6's real live database), plus 23 new for 7.2 (webhooks, install-claim flow, manifest callback, self-migration). |

Full write-up: `docs/PHASE7_1_MULTITENANT_BACKEND.md` (D-124–D-132) and
`docs/PHASE7_2_GITHUB_APP.md` (D-133–D-138).

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
