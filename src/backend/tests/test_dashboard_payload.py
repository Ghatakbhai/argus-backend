"""Unit-level proof for `dashboard_payload.py`, independent of Postgres: a
small, hand-built sqlite world (not a real snapshot — none of the three saved
Phase 6 databases contain a FIRE result, per
docs/PHASE7_1_MULTITENANT_BACKEND.md's "gap in Phase 6's evidence") that
exercises every code path the real snapshots can't: two rows sharing an
identical typed blocker (clustering), evidence_detail's ci/presence/timeline,
a suppressed item, and someone out of office.
"""
import json
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from backend import dashboard_payload as DP  # noqa: E402
import sprint_filter as SF  # noqa: E402

NOW = "2026-08-24T09:00:00Z"
SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def world():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(os.path.join(SRC, "schema.sql")) as f:
        conn.executescript(f.read())

    conn.execute("INSERT INTO source (id, name, base_url) VALUES (1,'github','https://github.com')")
    conn.execute("INSERT INTO project (id, source_id, source_key, display_name)"
                " VALUES (1,1,'acme/api','acme/api')")
    conn.execute("INSERT INTO snapshot (id, source_id, project_id, observed_at, started_at,"
                " is_complete) VALUES (1,1,1,?,?,1)", (NOW, NOW))
    conn.execute("INSERT INTO actor (id, source_id, source_key, kind, kind_reason)"
                " VALUES (1,1,'maya-r','human','assumed_human')")
    conn.execute("INSERT INTO actor (id, source_id, source_key, kind, kind_reason)"
                " VALUES (2,1,'tomasz-w','human','assumed_human')")
    conn.execute("INSERT INTO actor (id, source_id, source_key, kind, kind_reason)"
                " VALUES (3,1,'dana-k','human','assumed_human')")
    conn.execute("INSERT INTO integration (id, source_id, external_account_id,"
                " credential_ref, installed_at) VALUES (1,1,'12345','ref',?)", (NOW,))

    for wid, num, title, author in ((1, 401, "Rotate signing keys", 1),
                                    (2, 402, "Fix retries", 2)):
        conn.execute(
            "INSERT INTO work_item (id, snapshot_id, project_id, source_number, kind, title,"
            " state, author_id, created_at, url) VALUES (?,1,1,?,'change_request',?,'open',?,?,?)",
            (wid, num, title, author, "2026-08-18T00:00:00Z",
             f"https://github.com/acme/api/pull/{num}"))
        conn.execute(
            "INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,"
            " counts_as_human, human_reason) VALUES (1,?,'review_submitted',?,?,1,'human')",
            (wid, 3, "2026-08-18T11:00:00Z"))
        conn.execute(
            "INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,"
            " counts_as_human, human_reason, detail) VALUES (1,?,'committed',?,?,1,'human',?)",
            (wid, author, "2026-08-18T11:15:00Z", "final review fixes"))
        conn.execute("INSERT INTO readiness (work_item_id, checks_state) VALUES (?,'clean')", (wid,))
        msg = conn.execute(
            "INSERT INTO triage_message (integration_id, work_item_id, sent_to_actor_id,"
            " external_channel_id, external_message_ts, sent_at, status)"
            " VALUES (1,?,?,?,?,?,'responded')",
            (wid, author, f"D{wid}", f"{wid}.001", "2026-08-18T14:00:00Z")).lastrowid
        conn.execute(
            "INSERT INTO triage_response (triage_message_id, response_type, blocked_on_text,"
            " responded_at) VALUES (?,'blocked_on',?,?)",
            (msg, "Legal has not countersigned the DPA amendment", "2026-08-18T15:00:00Z"))

    conn.execute(
        "INSERT INTO work_item (id, snapshot_id, project_id, source_number, kind, title,"
        " state, author_id, created_at, url) VALUES (3,1,1,403,'change_request',"
        "'Backlog copy tweak','open',1,?,?)",
        ("2026-08-20T00:00:00Z", "https://github.com/acme/api/pull/403"))
    conn.execute("INSERT INTO presence (actor_id, status, detected_via, effective_from,"
                " detected_at) VALUES (3,'out_of_office','manual',?,?)",
                ("2026-08-15T00:00:00Z", NOW))
    conn.commit()

    results = [
        SF.FilterResult(work_item_id=1, item_key="acme/api#401", outcome=SF.FIRE, pattern="S-01",
                        reason="active_sprint", next_actor="maya-r", hours_idle=147.0,
                        evidence="approved 6 days ago, CI green; NW-1 is 'In Review'",
                        ticket_keys=["NW-1"], ticket_status="In Review", sprint_name="Sprint 1",
                        sprint_state="active", link_confidence="high", confidence="high"),
        SF.FilterResult(work_item_id=2, item_key="acme/api#402", outcome=SF.FIRE, pattern="S-01",
                        reason="active_sprint", next_actor="tomasz-w", hours_idle=100.0,
                        evidence="approved 4 days ago, CI green; NW-2 is 'In Review'",
                        ticket_keys=["NW-2"], ticket_status="In Review", sprint_name="Sprint 1",
                        sprint_state="active", link_confidence="high", confidence="high"),
        SF.FilterResult(work_item_id=3, item_key="acme/api#403", outcome=SF.SUPPRESSED,
                        pattern="S-01", reason="not_active_sprint_work", next_actor=None,
                        hours_idle=50.0, evidence="GRW-9 is 'Backlog' (backlog)",
                        confidence="high"),
    ]
    return conn, results


def _row(payload, item_key):
    return next(r for r in payload["digest"]["rows"] if r["item_key"] == item_key)


def test_counts_and_shape(world):
    conn, results = world
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    assert payload["digest"]["counts"]["fired"] == 2
    assert payload["digest"]["counts"]["suppressed"] == 1
    assert json.dumps(payload)  # round-trips through json with no surprises


def test_clustering_groups_identical_typed_blockers_only(world):
    conn, results = world
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    assert len(payload["clusters"]) == 1, payload["clusters"]
    cluster = payload["clusters"][0]
    assert set(cluster["member_keys"]) == {"acme/api#401", "acme/api#402"}
    assert cluster["tickets"] == ["NW-1", "NW-2"]
    assert _row(payload, "acme/api#401")["cluster"] == cluster["id"]
    assert _row(payload, "acme/api#402")["cluster"] == cluster["id"]


def test_evidence_detail_carries_ci_presence_timeline(world):
    conn, results = world
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    ed = _row(payload, "acme/api#401")["evidence_detail"]
    assert ed["ci"] == "green"                       # readiness.checks_state, real
    assert ed["presence"] is None or "maya-r" in ed["presence"]
    kinds = [t["what"] for t in ed["timeline"]]
    assert any("Blocked on" in k for k in kinds)      # the triage_response answer
    assert any(t["hot"] for t in ed["timeline"])
    assert ed["ticket_keys"] == ["NW-1"]               # straight from FilterResult


def test_suppressed_items_have_title_url_and_the_gates_own_sentence(world):
    conn, results = world
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    assert len(payload["suppressed_items"]) == 1
    item = payload["suppressed_items"][0]
    assert item["item_key"] == "acme/api#403"
    assert item["title"] == "Backlog copy tweak"
    assert item["url"].startswith("https://")
    assert item["detail"] == "GRW-9 is 'Backlog' (backlog)"


def test_people_out_and_freshness(world):
    conn, results = world
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    assert len(payload["people_out"]) == 1
    assert payload["people_out"][0]["login"] == "dana-k"
    assert payload["freshness"]["delivery_blockers"] == 2
    assert payload["freshness"]["state"] == "action_required"
    assert payload["freshness"]["verified_at"] is None  # never guessed — see module docstring


def test_no_shared_blocker_text_means_no_cluster(world):
    """D-152's own consequence, checked directly: change one of the two typed
    blockers and the cluster must disappear rather than fuzzy-match."""
    conn, results = world
    conn.execute("UPDATE triage_response SET blocked_on_text = 'A different blocker entirely'"
                " WHERE triage_message_id = 2")
    payload = DP.build_dashboard_payload(
        conn, results, NOW, tenant_slug="acme", team_label="Acme Rockets",
        tenant_members=4, shadow_until=None)
    assert payload["clusters"] == []
