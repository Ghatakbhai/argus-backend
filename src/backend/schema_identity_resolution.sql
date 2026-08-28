-- ===========================================================================
-- ARGUS — Pre-Milestone 2: the Identity Resolution slice (D-171)
--
-- WHAT THIS CLOSES.
--
-- `slack_dispatcher.py`'s own docstring has named this gap since Milestone 1
-- Task 2: `email_for_login` is a caller-supplied contract, and nothing in
-- this codebase has ever implemented one. `ingest_worker.run_one()` wires
-- `dispatch_tenant_triage_dms()` in but passes `email_for_login=None`
-- (D-170) — every identity resolves 'unresolved' and no live DM can ever
-- reach a real person. This file adds the two pieces of storage a real
-- resolver needs; `slack_dispatcher.build_email_resolver()` (Python side,
-- same session) is the resolver itself.
--
-- THE THREE-TIER POLICY THIS STORAGE SUPPORTS (see build_email_resolver's
-- own docstring for the authoritative statement — this is the schema, not
-- the policy):
--   1. `tenant_identity_map` — an explicit, human-confirmed
--      github_login -> email row. Most trustworthy: a person said so.
--   2. `tenant.email_domain` — a per-tenant heuristic guess,
--      `{github_login}@{email_domain}`, for the common case where a
--      company's GitHub logins already match their email's local part.
--   3. Neither present -> unresolved. Not a failure: `triage_message.status`
--      gains 'suppressed_unresolved_identity' below so that outcome is
--      recorded and auditable, the same discipline 'suppressed_presence'
--      already holds itself to, rather than silently dropped as it is
--      today (slack_dispatcher.dispatch_one's FAILED-with-no-row path).
--
-- Idempotent, applied on every boot — same discipline as every other file
-- in INCREMENTAL_MIGRATIONS (D-141): ADD COLUMN IF NOT EXISTS, CREATE TABLE
-- IF NOT EXISTS, and a guarded DO block for the CHECK constraint widening,
-- because Postgres has no ADD CONSTRAINT IF NOT EXISTS.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. Tier 2: the per-tenant domain guess.
-- ---------------------------------------------------------------------------
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS email_domain TEXT;

-- ---------------------------------------------------------------------------
-- 2. Tier 1: explicit, human-confirmed mappings.
--
-- One row per (tenant, github_login) — a login means one email for a given
-- tenant, by construction of the primary key. `email` is NOT NULL: a row
-- that exists but maps to nothing would be a confusing way to spell "no
-- mapping" when simply having no row already means that.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_identity_map (
    tenant_id       UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    github_login    TEXT NOT NULL,
    email           TEXT NOT NULL,
    PRIMARY KEY (tenant_id, github_login)
);

-- ---------------------------------------------------------------------------
-- 3. RLS on the new table — same explicit shape schema_7_3_slack.sql §4
-- uses, not the generic loop in schema_pg.sql (already ran, once, on the
-- live database — D-140's own note applies here too).
-- ---------------------------------------------------------------------------
DO $rls$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'public' AND c.relname = 'tenant_identity_map'
                     AND c.relrowsecurity) THEN
        ALTER TABLE tenant_identity_map ENABLE ROW LEVEL SECURITY;
        ALTER TABLE tenant_identity_map FORCE ROW LEVEL SECURITY;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies
                   WHERE schemaname = 'public' AND tablename = 'tenant_identity_map'
                     AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON tenant_identity_map
            USING (tenant_id = argus_current_tenant())
            WITH CHECK (tenant_id = argus_current_tenant());
    END IF;
END
$rls$;

-- The owner role's own bypass (schema_owner_rls_bypass.sql's generic loop
-- already ran once, before this table existed — D-149's fix does not
-- retroactively cover a table created in a later migration file). Added
-- proactively here rather than waiting for the next boot's re-run of that
-- file, so this table is never, even briefly, invisible to a SECURITY
-- DEFINER function that might need it.
DO $owner$
DECLARE owner_role text := current_user;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies
                   WHERE schemaname = 'public' AND tablename = 'tenant_identity_map'
                     AND policyname = 'owner_bypass') THEN
        EXECUTE format(
            'CREATE POLICY owner_bypass ON tenant_identity_map TO %I USING (true) WITH CHECK (true)',
            owner_role);
    END IF;
END
$owner$;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_identity_map TO argus_app;

-- ---------------------------------------------------------------------------
-- 4. Tier 3's audit trail: widen triage_message.status — and the SECOND,
-- easy-to-miss constraint that names 'suppressed_presence' explicitly.
--
-- schema_pg.sql's `triage_message` definition carries TWO relevant CHECKs,
-- both written inline with no explicit name (auto-named
-- `triage_message_status_check` and `triage_message_check1` by Postgres's
-- table-position convention, confirmed by querying `pg_get_constraintdef`
-- directly rather than assumed):
--   1. `status IN (...)` — the vocabulary itself.
--   2. `status = 'suppressed_presence' OR (external_channel_id IS NOT NULL
--      AND external_message_ts IS NOT NULL)` — every OTHER status requires
--      a real Slack message to point at. A row recording "we suppressed
--      this because the identity never resolved" has neither (no DM was
--      ever composed, let alone sent) and would violate constraint 2 even
--      after constraint 1 is widened to allow the new status. Both are
--      widened here, together, or the new status could never actually be
--      written.
--
-- Found by walking every CHECK constraint on the table rather than a single
-- assumed name, so this file does not silently no-op if either naming
-- convention or constraint text ever changes; each is only dropped and
-- re-added if it does not already mention the new status literal
-- (idempotent across repeated boots, same as every other guarded ALTER in
-- this project's incremental migrations).
-- ---------------------------------------------------------------------------
DO $ck$
DECLARE con RECORD; found_status_ck boolean := false; found_presence_ck boolean := false;
BEGIN
    FOR con IN
        SELECT conname, pg_get_constraintdef(oid) AS def
        FROM pg_constraint
        WHERE conrelid = 'triage_message'::regclass AND contype = 'c'
    LOOP
        IF con.def LIKE '%suppressed_unresolved_identity%' THEN
            IF con.def LIKE '%sent%' THEN found_status_ck := true; END IF;
            IF con.def LIKE '%external_channel_id%' THEN found_presence_ck := true; END IF;
            CONTINUE;
        END IF;

        IF con.def LIKE '%''sent''%' AND con.def LIKE '%''failed''%' THEN
            -- Constraint 1: the vocabulary itself.
            EXECUTE format('ALTER TABLE triage_message DROP CONSTRAINT %I', con.conname);
            ALTER TABLE triage_message ADD CONSTRAINT triage_message_status_check
                CHECK (status IN
                    ('sent','responded','expired','suppressed_presence','failed',
                     'suppressed_unresolved_identity'));
            found_status_ck := true;
        ELSIF con.def LIKE '%suppressed_presence%' AND con.def LIKE '%external_channel_id%' THEN
            -- Constraint 2: which statuses are exempt from needing a real
            -- Slack message recorded against them.
            EXECUTE format('ALTER TABLE triage_message DROP CONSTRAINT %I', con.conname);
            ALTER TABLE triage_message ADD CONSTRAINT triage_message_check1
                CHECK (status IN ('suppressed_presence', 'suppressed_unresolved_identity')
                       OR (external_channel_id IS NOT NULL AND external_message_ts IS NOT NULL));
            found_presence_ck := true;
        END IF;
    END LOOP;

    IF NOT found_status_ck THEN
        RAISE EXCEPTION 'could not find/widen triage_message''s status-vocabulary CHECK';
    END IF;
    IF NOT found_presence_ck THEN
        RAISE EXCEPTION 'could not find/widen triage_message''s suppressed-presence CHECK';
    END IF;
END
$ck$;

-- ===========================================================================
-- 5. The same verification every incremental migration file ends with.
-- ===========================================================================
DO $verify$
DECLARE missing text;
BEGIN
    SELECT string_agg(c.relname, ', ') INTO missing
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r'
      AND c.relname NOT IN ('tenant_api_key', 'audit_log', 'pending_installation')
      AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'RLS not forced on: %', missing;
    END IF;
END
$verify$;
