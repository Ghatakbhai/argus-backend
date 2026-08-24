-- ===========================================================================
-- ARGUS — the owner role needs its own bypass of row-level security (D-149)
--
-- WHAT WAS BROKEN.
--
-- Every SECURITY DEFINER function in this schema — argus_resolve_api_key,
-- argus_seed_tenant_sources, argus_claim_installation, argus_resolve_slack_team,
-- and every other one built at 7.1/7.2/7.3 — executes with the privileges of
-- whoever OWNS the function: the role that ran schema_pg.sql / roles.sql, via
-- ARGUS_OWNER_DSN. This project's entire local test suite applies those files
-- as the Postgres superuser, and a superuser always bypasses row-level
-- security regardless of FORCE ROW LEVEL SECURITY. Render's managed Postgres
-- does not hand out a superuser connection — its owner role has neither
-- SUPERUSER nor BYPASSRLS — so on the ONE database that actually matters,
-- every one of those functions has been silently non-functional since the day
-- 7.1 first deployed a schema with FORCE RLS on it (D-125). It went
-- undetected through 7.1's and 7.2's entire live-verification passes (D-139)
-- because neither ever actually created a tenant against the live database —
-- every probe used was a GET-based, query-string-authenticated endpoint. The
-- first real POST /v1/admin/tenants against the live deployment, in session
-- 41, is what surfaced it: a 500 with no detail (production hides tracebacks
-- by design), reproduced exactly and confirmed locally by standing up a
-- non-superuser, non-BYPASSRLS owner role and replaying the same calls —
-- creating a tenant raised "new row violates row-level security policy for
-- table source", and resolving a freshly-issued, correctly-hashed API key
-- silently returned zero rows. The second one is the more dangerous of the
-- two: it does not error, so nothing would have looked broken until a real
-- pilot team's very first request quietly failed to authenticate.
--
-- THE FIX, AND WHY IT IS SHAPED THIS WAY.
--
-- BYPASSRLS cannot be granted here: a role that lacks it cannot grant it to
-- itself or anyone else — only a role that already has it (or is superuser)
-- can, and that is exactly the privilege the owner role is missing. Instead,
-- the owner role gets its own explicit PERMISSIVE policy on every
-- row-level-secured table — the same construction D-130 already used to give
-- argus_admin cross-tenant access to `tenant` (the `tenant_admin` policy),
-- extended to cover the owner role and every table its SECURITY DEFINER
-- functions actually touch.
--
-- The role name is captured dynamically via CURRENT_USER, never hardcoded:
-- this file runs via ARGUS_OWNER_DSN on every boot (see db.py,
-- INCREMENTAL_MIGRATIONS, D-141), so CURRENT_USER at that moment IS whichever
-- role Render generated for this database — unknown in advance, and not
-- something this file should ever need to be told.
--
-- WHAT THIS DOES NOT CHANGE. Neither argus_app nor argus_admin is granted
-- anything here — this policy names only the owner role, which no
-- pilot-facing request ever connects as. The tenant-isolation guarantee this
-- project's whole design rests on (D-125, D-130) was re-verified after this
-- fix, the same way it always has been: argus_app bound to one tenant still
-- sees zero rows of another tenant's `source`, and zero rows of anything with
-- no tenant bound at all. Only the owner's own cross-tenant reach — which the
-- SECURITY DEFINER functions were always DESIGNED to have and documented as
-- having ("the one query in the whole design that is deliberately allowed to
-- look across tenants") — now actually works.
--
-- Applied via the same table-loop pattern schema_pg.sql's RLS block uses, so
-- it automatically covers every table with RLS enabled, present or future —
-- not a hand-maintained list that a later phase can forget to extend.
-- Idempotent: skips a table that already has the policy, so a restart never
-- errors on it.
-- ===========================================================================

DO $owner_bypass$
DECLARE
    owner_role text := current_user;
    t text;
BEGIN
    FOR t IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = 'public' AND tablename = t AND policyname = 'owner_bypass'
        ) THEN
            EXECUTE format(
                'CREATE POLICY owner_bypass ON %I TO %I USING (true) WITH CHECK (true)',
                t, owner_role);
        END IF;
    END LOOP;
END
$owner_bypass$;

-- Confirm the fix actually did something, rather than trusting the loop ran.
-- Fails the boot loudly if even one RLS-protected table is missing the
-- owner's policy — the same "don't let this become invisible again"
-- discipline schema_pg.sql's own closing assertion uses.
DO $verify$
DECLARE missing text;
BEGIN
    SELECT string_agg(c.relname, ', ') INTO missing
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relrowsecurity
      AND NOT EXISTS (
          SELECT 1 FROM pg_policies p
          WHERE p.schemaname = 'public' AND p.tablename = c.relname
            AND p.policyname = 'owner_bypass'
      );
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'owner_bypass policy missing on: %', missing;
    END IF;
END
$verify$;
