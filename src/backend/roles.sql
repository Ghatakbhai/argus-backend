-- ===========================================================================
-- ARGUS Phase 7.1 — database roles (D-130)
--
-- Three roles, because "the app can do anything" is how tenant data leaks:
--
--   argus_owner  owns the schema and runs migrations. The API never uses it.
--   argus_admin  the control plane: create a tenant, issue and revoke keys.
--                Used only by the /v1/admin/* endpoints, which are gated on a
--                separate admin secret that no pilot team ever receives.
--   argus_app    everything else. Reads and writes tenant data, and CANNOT:
--                  - bypass row-level security (no BYPASSRLS)
--                  - read the API key table at all (no grant on it)
--                  - create a tenant or issue itself a key
--                A total compromise of the API process therefore exposes the
--                data of whichever tenants it was already serving, and no
--                more. That is a claim the isolation suite actually tests.
-- ===========================================================================

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='argus_app') THEN
        CREATE ROLE argus_app LOGIN PASSWORD 'app_dev_password' NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='argus_admin') THEN
        CREATE ROLE argus_admin LOGIN PASSWORD 'admin_dev_password' NOBYPASSRLS;
    END IF;
END
$roles$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO argus_app, argus_admin;

-- --- argus_app -------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO argus_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO argus_app;

-- ...then take back the control plane. These four REVOKEs are the whole
-- point of having a separate app role.
REVOKE ALL ON tenant_api_key FROM argus_app;
REVOKE INSERT, UPDATE, DELETE ON tenant FROM argus_app;
GRANT  SELECT ON tenant TO argus_app;          -- needs to read its own row for /v1/me
GRANT  INSERT ON audit_log TO argus_app;
-- append-only AND write-only for the app: it has no reason to read the audit
-- trail, and audit_log is not RLS-protected (an anonymous auth failure has no
-- tenant to key on), so a SELECT grant here would be a cross-tenant read path.
REVOKE SELECT, UPDATE, DELETE ON audit_log FROM argus_app;

GRANT EXECUTE ON FUNCTION argus_resolve_api_key(text, text) TO argus_app;
GRANT EXECUTE ON FUNCTION argus_current_tenant() TO argus_app;

-- Phase 7.2: `install_claim` holds a hash of a one-time bearer token, same
-- sensitivity class as tenant_api_key, so it gets the same treatment — no
-- standing grant, everything through the SECURITY DEFINER functions below.
REVOKE ALL ON install_claim FROM argus_app;
-- (argus_resolve_installation / argus_claim_installation are GRANTed to
-- argus_app further down, right after they're defined — a GRANT can't
-- name a function that doesn't exist yet.)
-- pending_installation has no tenant_id and no RLS (there is no tenant yet
-- for an installation nobody has claimed) — argus_app writes to it directly,
-- the same way it writes to audit_log.

-- --- argus_admin -----------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant, tenant_api_key, audit_log TO argus_admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO argus_admin;
GRANT EXECUTE ON FUNCTION argus_resolve_api_key(text, text) TO argus_admin;

-- Cross-tenant aggregate metrics (step 7.8) are an admin capability and are
-- served by this function, so the app role never needs a way to read across
-- tenants "just for reporting" — the classic hole in a shared-database design.
CREATE OR REPLACE FUNCTION argus_pilot_metrics()
    RETURNS TABLE (
        tenant_slug text, tenant_status text,
        runs bigint, fired bigint, suppressed bigint, abstained bigint,
        feedback_given bigint, feedback_useful bigint,
        satisfaction_pct numeric
    )
    LANGUAGE sql SECURITY DEFINER STABLE
    AS $fn$
        SELECT t.slug, t.status,
               (SELECT count(*) FROM ingest_run r WHERE r.tenant_id = t.id),
               count(*) FILTER (WHERE a.outcome = 'FIRE'),
               count(*) FILTER (WHERE a.outcome = 'SUPPRESSED'),
               count(*) FILTER (WHERE a.outcome = 'ABSTAIN'),
               count(f.id),
               count(f.id) FILTER (WHERE f.verdict = 'useful'),
               CASE WHEN count(f.id) = 0 THEN NULL
                    ELSE round(100.0 * count(f.id) FILTER (WHERE f.verdict='useful')
                               / count(f.id), 1) END
        FROM tenant t
        LEFT JOIN alert a ON a.tenant_id = t.id
        LEFT JOIN alert_feedback f ON f.alert_id = a.id AND f.tenant_id = t.id
        GROUP BY t.id, t.slug, t.status
        ORDER BY t.slug
    $fn$;
REVOKE ALL ON FUNCTION argus_pilot_metrics() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_pilot_metrics() TO argus_admin;

-- Recording a key's last use needs UPDATE on a table argus_app cannot see.
CREATE OR REPLACE FUNCTION argus_touch_api_key(p_key_id uuid, p_at text)
    RETURNS void LANGUAGE sql SECURITY DEFINER
    AS $fn$ UPDATE tenant_api_key SET last_used_at = p_at WHERE id = p_key_id $fn$;
REVOKE ALL ON FUNCTION argus_touch_api_key(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_touch_api_key(uuid, text) TO argus_app, argus_admin;

-- --- the admin role's exact reach -----------------------------------------
-- argus_admin manages the control plane and nothing else. `tenant` is now
-- RLS-protected, so admin needs an explicit role-scoped policy to see it;
-- note that no equivalent policy is created on any data table. An admin-secret
-- compromise therefore exposes the tenant LIST and lets keys be reissued — it
-- does not hand over a single pilot team's code metadata. The isolation suite
-- asserts that.
CREATE POLICY tenant_admin ON tenant TO argus_admin USING (true) WITH CHECK (true);

-- Seeding a new tenant's four `source` rows is the one data write the tenant
-- creation flow needs. It goes through a SECURITY DEFINER function so it stays
-- inside the same transaction as the tenant row without granting argus_admin a
-- standing write path into tenant data.
CREATE OR REPLACE FUNCTION argus_seed_tenant_sources(p_tenant uuid)
    RETURNS void LANGUAGE sql SECURITY DEFINER
    AS $fn$
        INSERT INTO source (tenant_id, name, base_url) VALUES
            (p_tenant, 'github', 'https://api.github.com'),
            (p_tenant, 'jira',   'https://api.atlassian.com'),
            (p_tenant, 'linear', 'https://api.linear.app'),
            (p_tenant, 'slack',  'https://slack.com/api')
    $fn$;
REVOKE ALL ON FUNCTION argus_seed_tenant_sources(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_seed_tenant_sources(uuid) TO argus_admin;

-- ===========================================================================
-- Phase 7.2 — GitHub App installation lifecycle (D-133+).
--
-- Same shape as the API-key resolver above: a caller that does not yet have
-- (or does not yet get to name) a tenant reaches one narrow, purpose-built
-- SECURITY DEFINER function instead of a standing grant on tenant data.
-- ===========================================================================

-- Admin mints a one-time claim token FOR a specific tenant (by slug, so the
-- admin never has to know or guess a tenant's UUID). Only argus_admin can
-- call this; it is how a pilot team's install link gets tied to their tenant
-- before any installation exists.
CREATE OR REPLACE FUNCTION argus_admin_create_install_claim(
        p_tenant_slug text, p_token_hash text, p_created_at text, p_expires_at text)
    RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
    AS $fn$
    DECLARE v_tenant uuid;
    BEGIN
        SELECT id INTO v_tenant FROM tenant WHERE slug = p_tenant_slug;
        IF v_tenant IS NULL THEN
            RAISE EXCEPTION 'No such tenant: %', p_tenant_slug;
        END IF;
        INSERT INTO install_claim (tenant_id, token_hash, created_at, expires_at)
        VALUES (v_tenant, p_token_hash, p_created_at, p_expires_at);
        RETURN v_tenant;
    END;
    $fn$;
REVOKE ALL ON FUNCTION argus_admin_create_install_claim(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_admin_create_install_claim(text, text, text, text) TO argus_admin;

-- The webhook endpoint's very first move: given an installation id off an
-- incoming payload, which tenant (if any) does it belong to? Runs with no
-- tenant bound yet, so it has to look across all of them — the one place in
-- this design that is deliberately allowed to.
CREATE OR REPLACE FUNCTION argus_resolve_installation(p_installation_id text)
    RETURNS TABLE (tenant_id uuid, integration_id bigint, tenant_status text)
    LANGUAGE sql SECURITY DEFINER STABLE
    AS $fn$
        SELECT i.tenant_id, i.id, t.status
        FROM integration i
        JOIN tenant t ON t.id = i.tenant_id
        JOIN source s ON s.id = i.source_id AND s.tenant_id = i.tenant_id
        WHERE s.name = 'github'
          AND i.external_account_id = p_installation_id
          AND i.revoked_at IS NULL
          AND t.status <> 'offboarded'
    $fn$;
REVOKE ALL ON FUNCTION argus_resolve_installation(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_resolve_installation(text) TO argus_app;

-- Redeems a claim token: finds the tenant it was minted for, creates (or
-- updates, on a re-auth) that tenant's `integration` row for this
-- installation, marks the claim spent, and reflects the outcome in the
-- control-plane `pending_installation` log. One-time by construction —
-- `redeemed_at IS NULL` in the WHERE clause is the whole guard, no separate
-- locking needed because this runs inside its caller's own transaction.
CREATE OR REPLACE FUNCTION argus_claim_installation(
        p_token_hash text, p_installation_id text, p_account_login text,
        p_account_type text, p_scope text, p_at text)
    -- Named out_* rather than tenant_id/integration_id: in a plpgsql
    -- function, OUT parameters become variables in scope for the whole
    -- body, and a name that also matches a real column (tenant_id appears
    -- on nearly every table here) makes every bare reference to that column
    -- — including inside an ON CONFLICT target list — ambiguous. Cost one
    -- session of confusing errors to learn; not paying it twice.
    RETURNS TABLE (out_tenant_id uuid, out_integration_id bigint)
    LANGUAGE plpgsql SECURITY DEFINER
    AS $fn$
    DECLARE v_tenant uuid; v_source bigint; v_integration bigint;
    BEGIN
        SELECT c.tenant_id INTO v_tenant FROM install_claim c
            WHERE c.token_hash = p_token_hash
              AND c.redeemed_at IS NULL
              AND c.expires_at > p_at;
        IF v_tenant IS NULL THEN
            RETURN;  -- unknown, already-used, or expired token: no rows back
        END IF;

        SELECT s.id INTO v_source FROM source s
            WHERE s.tenant_id = v_tenant AND s.name = 'github';

        INSERT INTO integration (tenant_id, source_id, external_account_id,
                                  display_name, scope, credential_ref, installed_at)
        VALUES (v_tenant, v_source, p_installation_id, p_account_login,
                p_scope, 'github_app_installation', p_at)
        ON CONFLICT (tenant_id, source_id, external_account_id) DO UPDATE
            SET display_name = EXCLUDED.display_name,
                scope        = EXCLUDED.scope,
                revoked_at   = NULL
        RETURNING id INTO v_integration;

        UPDATE install_claim SET redeemed_at = p_at WHERE token_hash = p_token_hash;

        -- account_login/account_type are frequently unknown here — GitHub's
        -- setup redirect carries only installation_id and our own state
        -- token, not the account name; that arrives (maybe already has, if
        -- the `installation` webhook beat this redirect there, which is
        -- common) via the webhook handler instead. So: fill them in on
        -- first sight, but never clobber a real value with a placeholder.
        INSERT INTO pending_installation (installation_id, account_login, account_type,
                                           status, claimed_tenant_id, first_seen_at,
                                           last_seen_at, last_event_type, last_event_action)
        VALUES (p_installation_id, COALESCE(NULLIF(p_account_login, ''), '(pending)'),
                COALESCE(NULLIF(p_account_type, ''), 'unknown'), 'claimed',
                v_tenant, p_at, p_at, 'setup_redirect', 'claimed')
        ON CONFLICT (installation_id) DO UPDATE
            SET status = 'claimed', claimed_tenant_id = v_tenant, last_seen_at = p_at,
                last_event_type = 'setup_redirect', last_event_action = 'claimed';

        RETURN QUERY SELECT v_tenant, v_integration;
    END;
    $fn$;
REVOKE ALL ON FUNCTION argus_claim_installation(text, text, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_claim_installation(text, text, text, text, text, text) TO argus_app;
