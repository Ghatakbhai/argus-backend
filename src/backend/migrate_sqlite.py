"""Load a Phase 6 SQLite database into one tenant of the Phase 7 Postgres.

Three jobs now — the third added at Phase 7.4b:

  1. Copy the entity model across, remapping every integer id. Ids in SQLite
     are per-file; ids in Postgres are global across all pilot teams, so a
     straight copy of two teams' databases would collide. Every foreign key is
     rewritten through a per-table id map as the copy proceeds.

  2. Re-run Phase 6's own `sprint_filter.run_pipeline` against the ORIGINAL
     SQLite file and record its verdicts into the new `alert` table. This is
     the check that matters: the Phase 7 pilot record has to be able to hold
     what the Phase 6 engine actually produces, including the awkward parts
     (a NULL pattern, a 'P2-shaped' pattern, a reason string nobody enumerated),
     rather than a tidied-up version of it.

  3. Run `digest.collect` over the SAME results and store a real
     `digest_delivery` row — `rendered_text` (the HTML report) and
     `payload_json` (`dashboard_payload.build_dashboard_payload`'s envelope),
     from the same `Digest`, so the two can never disagree. This is what
     `src/dashboard/CONTRACT.md` named as owed and closes it for every tenant
     this function has ever been used to seed — see D-155 in
     `context/DECISIONS.md` for what this does and does not prove about a
     REAL pilot team's live data (nothing yet — see that decision).

**7.4c-a (D-156's build, step a of f):** `migrate()` and `record_phase6_run()`
now accept EITHER a path to a SQLite file on disk (original behavior,
unchanged: opened read-only here, closed here) OR an already-open
`sqlite3.Connection` (new: the caller opened it — typically an in-memory
scratch database it just populated from a live GitHub/Jira/Linear fetch —
and keeps owning its lifecycle; this module never closes a connection it did
not open). This is the one piece of plumbing the live ingestion consumer
(D-156) needs from this module: build a fresh scratch DB, populate it live,
then hand the same open connection to both functions below — no temp file
ever touches disk. Nothing about the file-path path changed; see D-160.

Usage:
    python -m backend.migrate_sqlite <sqlite-path> <tenant-slug>
"""
from __future__ import annotations

import json
import sqlite3
import sys

from . import dashboard_payload, db
from .auth import now_iso


def _open_source(source: str | sqlite3.Connection) -> tuple[sqlite3.Connection, bool]:
    """Normalizes `migrate()`/`record_phase6_run()`'s first argument.

    `source` is either a path to a SQLite file — opened read-only here, same
    as always — or an already-open `sqlite3.Connection`, which is used as-is.
    Returns `(connection, owns_it)`: `owns_it` is True only when THIS
    function opened the connection, so the caller (`migrate`/
    `record_phase6_run`) closes only what it opened. A connection handed in
    by our caller is theirs to close, not ours — closing someone else's
    in-memory scratch DB out from under them would be a real bug the moment
    the live ingestion consumer starts reusing one connection across both
    `migrate()` and `record_phase6_run()` in the same run (D-156).
    """
    if isinstance(source, sqlite3.Connection):
        source.row_factory = sqlite3.Row
        return source, False
    conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn, True

# (table, {column: table-it-points-at}). Order is dependency order: a table
# never appears before something it references.
TABLES: list[tuple[str, dict[str, str]]] = [
    ("project", {"source_id": "source"}),
    ("snapshot", {"source_id": "source", "project_id": "project"}),
    ("fetch", {"snapshot_id": "snapshot"}),
    ("actor", {"source_id": "source"}),
    ("milestone", {"project_id": "project"}),
    ("work_item", {"snapshot_id": "snapshot", "project_id": "project",
                   "author_id": "actor", "fetch_id": "fetch",
                   "milestone_id": "milestone"}),
    ("event", {"snapshot_id": "snapshot", "work_item_id": "work_item",
               "actor_id": "actor", "subject_actor_id": "actor", "fetch_id": "fetch"}),
    ("comment", {"event_id": "event", "work_item_id": "work_item", "actor_id": "actor"}),
    ("mention", {"comment_id": "comment", "work_item_id": "work_item",
                 "mentioned_actor_id": "actor"}),
    ("review", {"event_id": "event", "work_item_id": "work_item", "actor_id": "actor"}),
    ("review_request", {"work_item_id": "work_item", "actor_id": "actor",
                        "requested_by": "actor"}),
    ("assignment", {"work_item_id": "work_item", "actor_id": "actor",
                    "assigned_by": "actor"}),
    ("label", {"project_id": "project"}),
    ("work_item_label", {"work_item_id": "work_item", "label_id": "label",
                         "applied_by": "actor"}),
    ("reference", {"from_work_item_id": "work_item", "to_work_item_id": "work_item"}),
    ("readiness", {"work_item_id": "work_item"}),
    ("evidence_gap", {"snapshot_id": "snapshot", "work_item_id": "work_item"}),
    ("sprint", {"project_id": "project"}),
    ("ticket", {"source_id": "source", "project_id": "project", "sprint_id": "sprint",
                "assignee_actor_id": "actor", "fetch_id": "fetch"}),
    ("ticket_status_event", {"ticket_id": "ticket", "fetch_id": "fetch"}),
    ("ticket_link", {"ticket_id": "ticket", "work_item_id": "work_item"}),
    ("integration", {"source_id": "source", "project_id": "project"}),
    ("slack_identity", {"integration_id": "integration", "actor_id": "actor"}),
    ("presence", {"actor_id": "actor"}),
    ("triage_message", {"integration_id": "integration", "work_item_id": "work_item",
                        "ticket_id": "ticket", "sent_to_actor_id": "actor"}),
    ("triage_response", {"triage_message_id": "triage_message"}),
]

# Tables whose primary key is not called `id`.
PK = {"readiness": "work_item_id"}
RESERVED = {"fetch"}          # quoted in Postgres; FETCH is a reserved word


def q(table: str) -> str:
    return f'"{table}"' if table in RESERVED else table


def sqlite_tables(sconn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in sconn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def migrate(sqlite_source: str | sqlite3.Connection, tenant_slug: str) -> dict:
    sconn, owns_sconn = _open_source(sqlite_source)
    present = sqlite_tables(sconn)

    with db.admin_tx() as conn:
        row = conn.execute("SELECT id FROM tenant WHERE slug=%s", (tenant_slug,)).fetchone()
        if row is None:
            raise SystemExit(f"No tenant with slug {tenant_slug!r}")
        tenant_id = str(row["id"])

    # old id -> new id, per table
    idmap: dict[str, dict[int, int]] = {t: {} for t, _ in TABLES}
    counts: dict[str, int] = {}

    with db.tenant_tx(tenant_id) as pg:
        # `source` is special: create_tenant already seeded the four rows, so
        # match on name rather than inserting duplicates.
        idmap["source"] = {}
        if "source" in present:
            existing = {r["name"]: r["id"] for r in
                        pg.execute("SELECT id, name FROM source").fetchall()}
            for r in sconn.execute("SELECT * FROM source"):
                name = r["name"]
                if name in existing:
                    idmap["source"][r["id"]] = existing[name]
                else:
                    new = pg.execute(
                        "INSERT INTO source (tenant_id, name, base_url)"
                        " VALUES (%s,%s,%s) RETURNING id",
                        (tenant_id, name, r["base_url"])).fetchone()["id"]
                    idmap["source"][r["id"]] = new
            counts["source"] = len(idmap["source"])

        for table, fks in TABLES:
            if table not in present:
                continue
            cols = [c[1] for c in sconn.execute(f'PRAGMA table_info("{table}")')]
            pk = PK.get(table, "id")
            payload_cols = [c for c in cols if c != pk or table in PK]
            n = 0
            for src in sconn.execute(f'SELECT * FROM "{table}"'):
                values, names = [], []
                for c in payload_cols:
                    v = src[c]
                    if c in fks and v is not None:
                        mapped = idmap[fks[c]].get(v)
                        if mapped is None:
                            # A dangling reference in the source file. Carry it
                            # across as NULL rather than inventing a target or
                            # failing the whole migration.
                            v = None
                        else:
                            v = mapped
                    names.append(c)
                    values.append(v)
                names.append("tenant_id")
                values.append(tenant_id)
                placeholders = ",".join(["%s"] * len(values))
                collist = ",".join(f'"{c}"' for c in names)
                sql = (f"INSERT INTO {q(table)} ({collist}) VALUES ({placeholders})"
                       f" RETURNING {pk}")
                new_id = pg.execute(sql, values).fetchone()[pk]
                if table not in PK:
                    idmap[table][src[pk]] = new_id
                n += 1
            counts[table] = n
    if owns_sconn:
        sconn.close()
    return {"tenant_id": tenant_id, "counts": counts, "idmap": idmap}


def record_phase6_run(sqlite_source: str | sqlite3.Connection, tenant_slug: str,
                      work_item_map: dict[int, int], *,
                      existing_run_id: int | None = None) -> dict[str, int]:
    """Run Phase 6's own filter over the source data and store its verdicts —
    and, since Phase 7.4b, a real `digest_delivery` row assembled from the
    SAME results, so `alert` and the digest can never disagree.

    `sconn` (the SQLite connection) stays open through the digest build, not
    just the filter run: `dashboard_payload.build_dashboard_payload` and
    `digest.collect` both read `event`/`presence`/`triage_message`/
    `readiness` off it, the same tables the filter itself reads. It is only
    closed here if this function is the one that opened it (`sqlite_source`
    was a path) — see `_open_source()` and D-160.

    **7.4c-c (D-162's build, step c of f):** `existing_run_id`, new and
    optional. Every caller before the live ingestion poller wanted a NEW
    `ingest_run` row (a one-off backfill against a file someone handed us —
    the original, still-default behavior, unchanged: INSERT, trigger_kind
    'backfill', status 'succeeded'). The poller is different: a real
    `ingest_run` row already exists for the run it is finishing — created
    'queued' by the GitHub webhook handler or the admin run-now endpoint,
    then flipped to 'running' at claim time (`argus_claim_next_queued_run` /
    the run-now endpoint itself) — and inserting a second row here would
    silently duplicate it, leaving the original stuck at 'running' forever
    and every `alert`/`digest_delivery` row pointing at the wrong run.
    Passing `existing_run_id` makes this function UPDATE that row in place
    instead of inserting a new one; every other caller is completely
    unaffected; see D-162.
    """
    # `digest`/`sprint_filter` live in src/, one directory above src/backend/.
    # `dashboard_payload` (imported at module level, above) already put that
    # directory on sys.path when IT was first imported — its own docstring
    # notes this is computed from its own file location, not from anything
    # path-shaped about our caller's arguments, which is exactly why this can
    # stay a plain import even when `sqlite_source` is a connection with no
    # path behind it at all.
    import digest  # noqa: E402  — Phase 6's code, unmodified
    import sprint_filter  # noqa: E402

    sconn, owns_sconn = _open_source(sqlite_source)
    results = sprint_filter.run_pipeline(sconn)
    summary = sprint_filter.summarise(results)

    with db.admin_tx() as conn:
        trow = conn.execute("SELECT id, display_name FROM tenant WHERE slug=%s",
                            (tenant_slug,)).fetchone()
        tenant_id, team_label = str(trow["id"]), trow["display_name"]

    now = now_iso()
    member_count = sconn.execute(
        "SELECT COUNT(DISTINCT id) FROM actor WHERE kind='human'").fetchone()[0]
    dig = digest.collect(sconn, results, now, team_label=team_label or tenant_slug)
    rendered_text = digest.render_html(dig)
    payload = dashboard_payload.build_dashboard_payload(
        sconn, results, now, tenant_slug=tenant_slug, team_label=team_label or tenant_slug,
        tenant_members=member_count, dig=dig,
    )
    if owns_sconn:
        sconn.close()

    with db.tenant_tx(tenant_id) as pg:
        if existing_run_id is None:
            run_id = pg.execute(
                "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at,"
                " finished_at, items_checked, alerts_fired, alerts_suppressed)"
                " VALUES (%s,'backfill','succeeded',%s,%s,%s,%s,%s) RETURNING id",
                (tenant_id, now, now, len(results),
                 summary.get("FIRE", 0), summary.get("SUPPRESSED", 0))).fetchone()["id"]
        else:
            updated = pg.execute(
                "UPDATE ingest_run SET status='succeeded', finished_at=%s,"
                " items_checked=%s, alerts_fired=%s, alerts_suppressed=%s"
                " WHERE id=%s RETURNING id",
                (now, len(results), summary.get("FIRE", 0), summary.get("SUPPRESSED", 0),
                 existing_run_id)).fetchone()
            if updated is None:
                raise ValueError(
                    f"no ingest_run {existing_run_id!r} for tenant {tenant_slug!r} to update"
                    " — existing_run_id must name a row already belonging to this tenant")
            run_id = updated["id"]
        for r in results:
            pg.execute(
                "INSERT INTO alert (tenant_id, ingest_run_id, work_item_id, pattern,"
                " outcome, reason, detail, decided_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                (tenant_id, run_id, work_item_map.get(r.work_item_id), r.pattern,
                 r.outcome, r.reason, r.evidence, now))
        pg.execute(
            "INSERT INTO digest_delivery (tenant_id, ingest_run_id, channel, status,"
            " rendered_text, payload_json, delivered_at) VALUES (%s,%s,'dashboard','shadow',%s,%s,%s)",
            (tenant_id, run_id, rendered_text, json.dumps(payload), now))
    return {"ingest_run_id": run_id, "results": len(results),
            "FIRE": summary.get("FIRE", 0), "SUPPRESSED": summary.get("SUPPRESSED", 0),
            "ABSTAIN": summary.get("ABSTAIN", 0)}


if __name__ == "__main__":
    path, slug = sys.argv[1], sys.argv[2]
    print(migrate(path, slug))
