"""Load a Phase 6 SQLite database into one tenant of the Phase 7 Postgres.

Two jobs, and the second is the interesting one:

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

Usage:
    python -m backend.migrate_sqlite <sqlite-path> <tenant-slug>
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from . import db
from .auth import now_iso

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


def migrate(sqlite_path: str, tenant_slug: str) -> dict:
    sconn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    sconn.row_factory = sqlite3.Row
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
    sconn.close()
    return {"tenant_id": tenant_id, "counts": counts, "idmap": idmap}


def record_phase6_run(sqlite_path: str, tenant_slug: str, work_item_map: dict[int, int]
                      ) -> dict[str, int]:
    """Run Phase 6's own filter over the source file and store its verdicts."""
    sys.path.insert(0, str(Path(sqlite_path).resolve().parent.parent / "src"))
    import sprint_filter  # noqa: E402  — Phase 6's code, unmodified

    sconn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    sconn.row_factory = sqlite3.Row
    results = sprint_filter.run_pipeline(sconn)
    summary = sprint_filter.summarise(results)
    sconn.close()

    with db.admin_tx() as conn:
        tenant_id = str(conn.execute("SELECT id FROM tenant WHERE slug=%s",
                                     (tenant_slug,)).fetchone()["id"])
    with db.tenant_tx(tenant_id) as pg:
        run_id = pg.execute(
            "INSERT INTO ingest_run (tenant_id, trigger_kind, status, started_at,"
            " finished_at, items_checked, alerts_fired, alerts_suppressed)"
            " VALUES (%s,'backfill','succeeded',%s,%s,%s,%s,%s) RETURNING id",
            (tenant_id, now_iso(), now_iso(), len(results),
             summary.get("FIRE", 0), summary.get("SUPPRESSED", 0))).fetchone()["id"]
        for r in results:
            pg.execute(
                "INSERT INTO alert (tenant_id, ingest_run_id, work_item_id, pattern,"
                " outcome, reason, decided_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (tenant_id, run_id, work_item_map.get(r.work_item_id), r.pattern,
                 r.outcome, r.reason, now_iso()))
    return {"ingest_run_id": run_id, "results": len(results),
            "FIRE": summary.get("FIRE", 0), "SUPPRESSED": summary.get("SUPPRESSED", 0),
            "ABSTAIN": summary.get("ABSTAIN", 0)}


if __name__ == "__main__":
    path, slug = sys.argv[1], sys.argv[2]
    print(migrate(path, slug))
