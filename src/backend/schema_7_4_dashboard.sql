-- ===========================================================================
-- ARGUS — Phase 7.4b: closes src/dashboard/CONTRACT.md's data-contract gap
--
-- Two columns, both additive and both idempotent (D-141 — this file is
-- re-applied on every boot, against a database that is not empty):
--
--   1. digest_delivery.payload_json — the structured shape
--      src/digest.py's own Digest.as_dict() already produces, wrapped in the
--      dashboard's envelope (tenant/freshness/suppressed_items/clusters).
--      Written at the same moment rendered_text is, from the same source, so
--      the two can never disagree (CONTRACT.md §2).
--
--   2. alert.detail — the gate's own human-readable line. It was never
--      dropped by sprint_filter.py (GateResult.detail is already folded into
--      FilterResult.evidence at _apply_gate()) — it was dropped at the
--      Postgres boundary, because record_phase6_run() only ever persisted
--      FilterResult.reason (the machine token), never FilterResult.evidence
--      (the sentence a human reads). This column, and the write this file's
--      companion change makes in migrate_sqlite.py, closes that (CONTRACT.md
--      "Owed" table, row 2).
--
-- Neither column is backfilled for rows that already exist: an old digest
-- delivered before this migration ran has no payload_json, and
-- GET /v1/digests/latest?format=json says so explicitly (404) rather than
-- inventing a payload for a digest that was never assembled with one.
-- ===========================================================================

ALTER TABLE digest_delivery ADD COLUMN IF NOT EXISTS payload_json TEXT;
ALTER TABLE alert            ADD COLUMN IF NOT EXISTS detail TEXT;

-- ===========================================================================
-- The same verification schema_pg.sql ends with, re-run here. Two ALTER
-- TABLE ... ADD COLUMN statements cannot themselves break RLS — no new
-- table, no new row — but the assertion costs nothing and keeps every
-- incremental migration file honest the same way, rather than trusting
-- "this one is obviously safe" to stay true if this file is ever edited.
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
