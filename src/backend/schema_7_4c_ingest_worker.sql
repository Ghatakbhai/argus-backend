-- ===========================================================================
-- ARGUS 7.4c-c — the cross-tenant claim function the in-process ingestion
-- poller needs.
--
-- `ingest_run` is a normal row-level-secured, per-tenant table: argus_app can
-- only ever see and write the rows of whatever tenant its current
-- transaction is bound to (db.tenant_tx). That is exactly right for every
-- existing caller (POST /v1/ingest/runs, the GitHub webhook handler) — each
-- of those already knows which tenant it is acting for.
--
-- The poller is different in kind: it must find the single oldest QUEUED run
-- across every pilot tenant at once, with no tenant bound yet (finding out
-- which tenant it is is the whole point of the query). That is a genuine
-- cross-tenant read — the same shape argus_pilot_metrics() (roles.sql,
-- step 7.8) already has, for the same reason: a SECURITY DEFINER function is
-- the one door for it, not a widened grant on argus_app. This one also
-- WRITES (queued -> running) inside the same statement, so a background poll
-- tick and a person's manual "run it now" click (or two poll ticks a restart
-- happens to overlap) can never both claim the same row — FOR UPDATE SKIP
-- LOCKED means a claim already in flight is invisible to a concurrent one,
-- not something it waits on and then double-processes.
--
-- Runs as the owner role (SECURITY DEFINER + the ARGUS_OWNER_DSN connection
-- schema_pg.sql/roles.sql/this file are all applied through), which already
-- holds the `owner_bypass` RLS policy on every row-level-secured table,
-- `ingest_run` included — that policy was created once, generically, by
-- schema_owner_rls_bypass.sql's loop over every RLS table "present or
-- future" (D-149), so nothing further is needed here to make the owner's
-- read/write actually see every tenant's rows.
-- ===========================================================================

CREATE OR REPLACE FUNCTION argus_claim_next_queued_run(p_now text)
    RETURNS TABLE (out_run_id bigint, out_tenant_id uuid, out_tenant_slug text)
    LANGUAGE plpgsql SECURITY DEFINER
    AS $fn$
    -- Named out_* for the same reason argus_claim_installation's OUT
    -- parameters are (roles.sql): a plpgsql OUT parameter is in scope for the
    -- whole function body, and tenant_id/id both collide with real column
    -- names on ingest_run, making a bare reference to either ambiguous.
    DECLARE v_run_id bigint; v_tenant_id uuid;
    BEGIN
        SELECT r.id, r.tenant_id INTO v_run_id, v_tenant_id
        FROM ingest_run r
        WHERE r.status = 'queued'
        ORDER BY r.started_at ASC, r.id ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1;

        IF v_run_id IS NULL THEN
            RETURN;  -- empty queue: zero rows back, not an error
        END IF;

        -- p_now is passed in rather than computed here (now_iso() on the
        -- Python side) so every timestamp this project writes stays in the
        -- one format/clock db.py's callers already use, not a second,
        -- possibly-drifted source of "now" living inside the database.
        UPDATE ingest_run SET status = 'running' WHERE id = v_run_id;

        RETURN QUERY
        SELECT v_run_id, v_tenant_id, t.slug FROM tenant t WHERE t.id = v_tenant_id;
    END;
    $fn$;
REVOKE ALL ON FUNCTION argus_claim_next_queued_run(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION argus_claim_next_queued_run(text) TO argus_admin;
