"""
ARGUS — Phase 6.4 verification: run the sprint filter and the narrow
2-pattern pipeline against fixture data and check every result against
what a human reading the same fixtures would expect.

Same discipline as verify_jira_adapter.py (D-112) and
verify_linear_adapter.py (D-113): every assertion fails loudly, nothing
passes silently, and the fixtures are realistic rather than convenient.

What makes this one different from the previous two is that the ticket
side is NOT hand-built here. The Jira and Linear fixtures from steps 6.2
and 6.3 are ingested through the real adapters into the same database,
so every sprint/status combination the gate is tested against is one
those verified adapters actually produce. Only the GitHub side is
scaffolded (see load_github_fixture below), because 6.4 is a test of the
filter, not of ingestion — src/ingest.py's real-payload path was already
verified end to end in Phase 2 (D-061..D-075).
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
import jira_adapter as J
import linear_adapter as L
import sprint_filter as SF
import verify_jira_adapter as VJ
import verify_linear_adapter as VL

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
SCHEMA = os.path.join(HERE, "schema.sql")

GH_FIXTURE = os.path.join(FIXTURES, "phase6_4_github_items.json")


# ---------------------------------------------------------------------------
# Test scaffolding: load the GitHub-side fixture straight into the schema
# ---------------------------------------------------------------------------

def load_github_fixture(conn: sqlite3.Connection, spec: dict) -> dict:
    """Write the fixture's items into the real Phase 2 tables.

    This is TEST SCAFFOLDING, not production ingestion — it is here so
    every case in phase6_4_github_items.json can be read as a plain
    statement of a situation. It writes only into columns the real
    ingestion writes, and it invents no values the filter then reads
    back: readiness defaults to ('unknown','unknown') exactly as the
    schema does when ingestion cannot see a state.
    """
    cur = conn.execute("INSERT INTO source (name, base_url) VALUES ('github','https://github.com')")
    source_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO project (source_id, source_key, display_name) VALUES (?,?,?)",
        (source_id, spec["project_key"], spec["project_name"]),
    )
    project_id = cur.lastrowid
    obs = spec["observed_at"]
    cur = conn.execute(
        """INSERT INTO snapshot (source_id, project_id, observed_at, started_at,
                                  completed_at, is_complete, tool_version)
           VALUES (?,?,?,?,?,1,'phase6.4-verify')""",
        (source_id, project_id, obs, obs, obs),
    )
    snapshot_id = cur.lastrowid

    actors: dict[str, int] = {}
    for a in spec["actors"]:
        cur = conn.execute(
            """INSERT INTO actor (source_id, source_key, display_name, kind, kind_reason)
               VALUES (?,?,?,?,?)""",
            (source_id, a["login"], a["login"], a["kind"],
             "assumed_human" if a["kind"] == "human" else "known_bot_list"),
        )
        actors[a["login"]] = cur.lastrowid

    def add_event(work_item_id, etype, actor_login, occurred_at, subject_login=None):
        actor_id = actors.get(actor_login)
        is_human = 1 if actor_login and spec_kind(spec, actor_login) == "human" else 0
        conn.execute(
            """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, subject_actor_id,
                                   occurred_at, date_precision, counts_as_human, human_reason)
               VALUES (?,?,?,?,?,?, 'exact', ?, ?)""",
            (snapshot_id, work_item_id, etype, actor_id,
             actors.get(subject_login) if subject_login else None,
             occurred_at, is_human, "human" if is_human else "bot_account"),
        )

    ids: dict[int, int] = {}
    for it in spec["items"]:
        payload = json.dumps({"head": {"ref": it["branch"]}}) if it.get("branch") else None
        cur = conn.execute(
            """INSERT INTO work_item (snapshot_id, project_id, source_number, kind, title,
                                       state, is_draft, author_id, created_at, closed_at,
                                       url, source_payload)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (snapshot_id, project_id, it["number"], it["kind"], it["title"], it["state"],
             it.get("is_draft", 0), actors.get(it.get("author")), it["created_at"],
             it.get("closed_at"),
             f"https://github.com/{spec['project_key']}/pull/{it['number']}", payload),
        )
        wid = cur.lastrowid
        ids[it["number"]] = wid

        add_event(wid, "opened", it.get("author"), it["created_at"])

        rd = it.get("readiness")
        if rd:
            conn.execute(
                """INSERT INTO readiness (work_item_id, merge_state, checks_state, cla_state)
                   VALUES (?,?,?, 'unknown')""",
                (wid, rd.get("merge_state", "unknown"), rd.get("checks_state", "unknown")),
            )

        for rv in it.get("reviews", []):
            conn.execute(
                """INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,
                                       date_precision, counts_as_human, human_reason)
                   VALUES (?,?, 'review_submitted', ?, ?, 'exact', 1, 'human')""",
                (snapshot_id, wid, actors[rv["actor"]], rv["submitted_at"]),
            )
            event_id = conn.execute("SELECT MAX(id) FROM event").fetchone()[0]
            conn.execute(
                """INSERT INTO review (event_id, work_item_id, actor_id, state, submitted_at)
                   VALUES (?,?,?,?,?)""",
                (event_id, wid, actors[rv["actor"]], rv["state"], rv["submitted_at"]),
            )

        for rr in it.get("review_requests", []):
            conn.execute(
                """INSERT INTO review_request (work_item_id, actor_id, requested_by,
                                                requested_at, removed_at, origin)
                   VALUES (?,?,?,?,?,?)""",
                (wid, actors[rr["actor"]], actors.get(rr.get("requested_by")),
                 rr["requested_at"], rr.get("removed_at"), rr.get("origin", "manual")),
            )
            add_event(wid, "review_requested", rr.get("requested_by"),
                      rr["requested_at"], subject_login=rr["actor"])

        for ev in it.get("events", []):
            add_event(wid, ev["type"], ev.get("actor"), ev["occurred_at"])

    conn.commit()
    return {"snapshot_id": snapshot_id, "project_id": project_id, "ids": ids, "actors": actors}


def spec_kind(spec: dict, login: str) -> str:
    for a in spec["actors"]:
        if a["login"] == login:
            return a["kind"]
    return "unknown"


# ---------------------------------------------------------------------------
# Build the combined Part II database: GitHub + Jira + Linear
# ---------------------------------------------------------------------------

def build_db() -> tuple[sqlite3.Connection, dict, dict]:
    conn = sqlite3.connect(":memory:")
    with open(SCHEMA) as f:
        conn.executescript(f.read())

    with open(GH_FIXTURE) as f:
        spec = json.load(f)
    gh = load_github_fixture(conn, spec)

    # --- the real Jira adapter, on step 6.2's own verified fixtures ---------
    jb = VJ.build_bundle()
    jsid = J.get_or_create_jira_source(conn, jb.base_url)
    jpid = J.get_or_create_project(conn, jsid, jb.project_key, jb.project_name)
    cur = conn.execute(
        """INSERT INTO snapshot (source_id, project_id, observed_at, started_at,
                                  completed_at, is_complete, tool_version)
           VALUES (?,?,?,?,?,1,'phase6.4-verify-jira')""",
        (jsid, jpid, jb.observed_at, jb.observed_at, jb.observed_at),
    )
    J.ingest_project(conn, cur.lastrowid, jb)

    # --- the real Linear adapter, on step 6.3's own verified fixtures ------
    lb = VL.build_bundle()
    lsid = L.get_or_create_linear_source(conn, lb.base_url)
    lpid = L.get_or_create_project(conn, lsid, lb.team_key, lb.team_name)
    cur = conn.execute(
        """INSERT INTO snapshot (source_id, project_id, observed_at, started_at,
                                  completed_at, is_complete, tool_version)
           VALUES (?,?,?,?,?,1,'phase6.4-verify-linear')""",
        (lsid, lpid, lb.observed_at, lb.observed_at, lb.observed_at),
    )
    L.ingest_team(conn, cur.lastrowid, lb)

    conn.commit()
    return conn, spec, gh


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

def run():
    conn, spec, gh = build_db()
    ids = gh["ids"]
    checks = 0

    def wid(n):
        return ids[n]

    # =====================================================================
    # A. Ticket-key extraction — the false-link class this design guards
    # =====================================================================
    assert SF.extract_ticket_keys("Fix ENG-123 and PROJ-45") == ["ENG-123", "PROJ-45"]
    assert SF.extract_ticket_keys("feature/eng-102-empty-input") == ["ENG-102"]
    assert SF.extract_ticket_keys("bump UTF-8 / SHA-256 / AES-256 / ISO-8601") == \
        ["UTF-8", "SHA-256", "AES-256", "ISO-8601"], \
        "these must still be EXTRACTED as candidates; resolution is what rejects them"
    assert SF.extract_ticket_keys("released 2026-08-21, see v1.2-3") == [], \
        "a date and a version string must not look like ticket keys"
    assert SF.extract_ticket_keys("ENG-123abc") == [], "must not bite into a longer token"
    assert SF.extract_ticket_keys("ENG-123 again ENG-123") == ["ENG-123"], "deduplicated"
    assert SF.extract_ticket_keys(None) == [] and SF.extract_ticket_keys("") == []
    checks += 1
    print("  check 1  ticket-key regex: real keys found, technical tokens still only candidates")

    # =====================================================================
    # B. Linking: candidates only become links when the ticket exists
    # =====================================================================
    src = SF.link_sources_from_db(conn, wid(414))
    out = SF.propose_links(conn, src)
    assert out.proposed == [], out.proposed
    assert set(out.unresolved_keys) == {"UTF-8", "SHA-256"}, out.unresolved_keys
    checks += 1
    print("  check 2  UTF-8 / SHA-256 resolve to no ticket and produce no link")

    src = SF.link_sources_from_db(conn, wid(401))
    out = SF.propose_links(conn, src)
    assert [p.ticket_key for p in out.proposed] == ["ENG-102"], out.proposed
    assert out.proposed[0].link_method == "branch_name"
    assert out.proposed[0].confidence == "high"
    checks += 1
    print("  check 3  a lower-case branch key resolves to its ticket at high confidence")

    src = SF.link_sources_from_db(conn, wid(403))
    out = SF.propose_links(conn, src)
    assert [p.ticket_key for p in out.proposed] == ["APP-190"], out.proposed
    assert out.proposed[0].link_method == "pr_title_key"
    assert out.proposed[0].confidence == "medium"
    checks += 1
    print("  check 4  a title-only key links at medium confidence, not high")

    # Missing sources are named, not silently treated as empty text.
    src = SF.link_sources_from_db(conn, wid(403))
    assert "branch_name" in src.missing and "commit_messages" in src.missing, src.missing
    src = SF.link_sources_from_db(conn, wid(401))
    assert "branch_name" not in src.missing and "commit_messages" in src.missing, src.missing
    checks += 1
    print("  check 5  unavailable text sources are reported as missing, not as absent keys")

    # The commit-message route, which no column can supply today, works when
    # a caller supplies it under the LinkTextSources contract.
    hand = SF.LinkTextSources(work_item_id=wid(414), title="Bump UTF-8 handling",
                              commit_messages=["ENG-103 wire up the queue", "fix typo"])
    out = SF.propose_links(conn, hand)
    assert [(p.ticket_key, p.link_method, p.confidence) for p in out.proposed] == \
        [("ENG-103", "smart_commit", "high")], out.proposed
    checks += 1
    print("  check 6  the commit-message (smart_commit) route links at high confidence")

    # =====================================================================
    # C. Writing ticket_link: idempotent, and upgrades rather than downgrades
    # =====================================================================
    all_sources = [SF.link_sources_from_db(conn, i) for i in ids.values()]
    stats1 = SF.ingest_ticket_links(conn, all_sources, "2026-08-21T12:00:00Z")
    total_links = conn.execute("SELECT COUNT(*) FROM ticket_link").fetchone()[0]
    assert stats1["inserted"] == total_links, (stats1, total_links)
    assert stats1["upgraded"] == 0 and stats1["unchanged"] == 0, stats1
    assert stats1["unresolved_keys"] >= 2, stats1

    stats2 = SF.ingest_ticket_links(conn, all_sources, "2026-08-21T12:00:00Z")
    assert stats2["inserted"] == 0 and stats2["upgraded"] == 0, stats2
    assert conn.execute("SELECT COUNT(*) FROM ticket_link").fetchone()[0] == total_links
    checks += 1
    print(f"  check 7  {total_links} links written; a second run inserts 0 and duplicates 0")

    # A weaker method must never overwrite a stronger stored one; a stronger
    # one must upgrade it. (Step 6.2's changelog-doubling bug, D-112, is the
    # reason this is checked rather than assumed.)
    before = conn.execute(
        """SELECT link_method, confidence FROM ticket_link tl JOIN ticket t ON t.id=tl.ticket_id
           WHERE tl.work_item_id=? AND t.source_key='ENG-102'""", (wid(401),)).fetchone()
    assert before == ("branch_name", "high"), before
    SF.ingest_ticket_links(
        conn, [SF.LinkTextSources(work_item_id=wid(401), title="ENG-102 retitled")],
        "2026-08-21T13:00:00Z")
    after = conn.execute(
        """SELECT link_method, confidence FROM ticket_link tl JOIN ticket t ON t.id=tl.ticket_id
           WHERE tl.work_item_id=? AND t.source_key='ENG-102'""", (wid(401),)).fetchone()
    assert after == ("branch_name", "high"), f"a title must not downgrade a branch link: {after}"

    weak_wid = wid(403)
    SF.ingest_ticket_links(
        conn, [SF.LinkTextSources(work_item_id=weak_wid,
                                  branch_name="release/app-190-backport")],
        "2026-08-21T13:00:00Z")
    upgraded = conn.execute(
        """SELECT link_method, confidence FROM ticket_link tl JOIN ticket t ON t.id=tl.ticket_id
           WHERE tl.work_item_id=? AND t.source_key='APP-190'""", (weak_wid,)).fetchone()
    assert upgraded == ("branch_name", "high"), f"a branch must upgrade a title link: {upgraded}"
    checks += 1
    print("  check 8  link strength only ever goes up on a re-run, never down")

    # =====================================================================
    # D. The gate itself
    # =====================================================================
    g = SF.sprint_gate(conn, wid(401))
    assert g.passed and g.reason == "active_sprint", g
    assert g.passing_ticket_key == "ENG-102" and g.sprint_state == "active", g

    g = SF.sprint_gate(conn, wid(402))
    assert not g.passed and g.reason == "not_active_sprint_work", g
    assert "backlog" in g.detail, g.detail

    g = SF.sprint_gate(conn, wid(404))
    assert not g.passed and "state=future" in g.detail, g.detail

    g = SF.sprint_gate(conn, wid(403))
    assert not g.passed and "state=closed" in g.detail, g.detail

    g = SF.sprint_gate(conn, wid(411))
    assert not g.passed and "canceled" in g.detail, g.detail

    g = SF.sprint_gate(conn, wid(415))
    assert not g.passed and "in no sprint" in g.detail, \
        "APP-230 is 'Todo', not parked — it must still fail for having no cycle"

    g = SF.sprint_gate(conn, wid(414))
    assert not g.passed and g.reason == "no_ticket_link", g
    checks += 1
    print("  check 9  gate: active passes; backlog / canceled / future / closed / no-sprint "
          "/ no-link all fail, each under its own reason")

    # 'done' in an active sprint does NOT suppress: the PR is still unmerged.
    g = SF.sprint_gate(conn, wid(425))
    assert g.passed and g.passing_ticket_key == "ENG-104" and g.ticket_status == "Done", g
    checks += 1
    print("  check 10  a 'Done' ticket in an active sprint does not suppress an unmerged PR")

    # One live ticket is enough even when another link is parked.
    g = SF.sprint_gate(conn, wid(423))
    assert g.ticket_keys == ["APP-222", "ENG-101"], g.ticket_keys
    assert g.passed and g.passing_ticket_key == "ENG-101", g
    checks += 1
    print("  check 11  one live linked ticket carries the item even when another is canceled")

    # =====================================================================
    # E. Pattern 1
    # =====================================================================
    r = SF.evaluate_p1(conn, wid(401))
    assert r.outcome == SF.FIRE and r.pattern == SF.P1, r
    assert r.next_actor == "marco", r
    assert abs(r.hours_idle - 96.0) < 0.01, r.hours_idle
    assert "CI green" in r.evidence and "Sprint 24 (active)" in r.evidence, r.evidence
    checks += 1
    print(f"  check 12  P1 fires on #401 after {r.hours_idle:.0f}h, next actor {r.next_actor}")

    assert SF.evaluate_p1(conn, wid(405)).reason.startswith("ci_not_known_green"), \
        "an unknown CI state must never be read as green"
    assert SF.evaluate_p1(conn, wid(405)).outcome == SF.ABSTAIN
    assert SF.evaluate_p1(conn, wid(401)).outcome == SF.FIRE, \
        "an unknown MERGE state must not suppress — #401 has merge_state='unknown'"
    checks += 1
    print("  check 13  'unknown' is never converted into a claim, in either direction")

    for n, expect in [(406, "merge_conflict"),
                      (407, "latest_review_is_changes_requested"),
                      (409, "draft"),
                      (417, "not_open"),
                      (416, "not_a_pull_request"),
                      (410, "never_reviewed")]:
        r = SF.evaluate_p1(conn, wid(n))
        assert r.outcome == SF.ABSTAIN and r.reason == expect, (n, r.outcome, r.reason)
    r = SF.evaluate_p1(conn, wid(408))
    assert r.outcome == SF.ABSTAIN and r.reason == "idle_only_12.0h", r.reason
    checks += 1
    print("  check 14  P1 abstains — and says why — on conflict / superseded / draft / "
          "merged / issue / unreviewed / too-recent")

    for n in (402, 403, 404, 414):
        r = SF.evaluate_p1(conn, wid(n))
        assert r.outcome == SF.SUPPRESSED, (n, r.outcome, r.reason)
    assert SF.evaluate_p1(conn, wid(414)).reason == "no_ticket_link"
    checks += 1
    print("  check 15  P1 shapes that matched in full are SUPPRESSED, not silently dropped")

    # =====================================================================
    # F. Pattern 2
    # =====================================================================
    r = SF.evaluate_p2(conn, wid(410))
    assert r.outcome == SF.FIRE and r.next_actor == "dana", r
    assert abs(r.hours_idle - 120.0) < 0.01, r.hours_idle
    checks += 1
    print(f"  check 16  P2 fires on #410 after {r.hours_idle:.0f}h waiting on {r.next_actor}")

    for n, expect in [(412, "every_requested_reviewer_responded"),
                      (413, "another_reviewer_approved_since"),
                      (419, "no_live_manual_review_request"),
                      (420, "no_live_manual_review_request")]:
        r = SF.evaluate_p2(conn, wid(n))
        assert r.outcome == SF.ABSTAIN and r.reason == expect, (n, r.outcome, r.reason)
    r = SF.evaluate_p2(conn, wid(421))
    assert r.outcome == SF.ABSTAIN and r.reason == "waited_only_12.0h", r.reason
    checks += 1
    print("  check 17  P2 abstains on a response / another approval / CODEOWNERS / "
          "withdrawn / too-recent request")

    # One result per ITEM, naming the longest-silent reviewer — the per-reviewer
    # vs per-item mismatch D-083 named in Part I.
    r = SF.evaluate_p2(conn, wid(422))
    assert r.outcome == SF.FIRE and r.next_actor == "alice", r
    assert abs(r.hours_idle - 144.0) < 0.01, r.hours_idle
    item_rows = [x for x in SF.run_pipeline(conn) if x.work_item_id == wid(422)]
    assert len(item_rows) == 1, "two ghosted reviewers must still produce one item-level result"
    checks += 1
    print("  check 18  two ghosted reviewers produce ONE result, naming the longest-silent one")

    for n in (411, 415):
        r = SF.evaluate_p2(conn, wid(n))
        assert r.outcome == SF.SUPPRESSED and r.reason == "not_active_sprint_work", (n, r)
    checks += 1
    print("  check 19  P2 shapes on canceled / no-cycle tickets are SUPPRESSED")

    # =====================================================================
    # G. The pipeline as a whole
    # =====================================================================
    results = SF.run_pipeline(conn)
    assert len(results) == len(ids), (len(results), len(ids))
    assert len({r.work_item_id for r in results}) == len(ids), "one result per item, no duplicates"
    assert all(r.outcome in (SF.FIRE, SF.SUPPRESSED, SF.ABSTAIN) for r in results)
    assert all(r.reason for r in results), "every result must carry a reason, including abstains"
    checks += 1
    print(f"  check 20  every one of {len(results)} items gets exactly one outcome and a reason")

    by_number = {}
    for it in spec["items"]:
        by_number[it["number"]] = wid(it["number"])
    rmap = {r.work_item_id: r for r in results}

    # #417 moved from the ABSTAIN set to the FIRE set at Phase 7.4X, and it
    # was NOT edited to make the new pattern look good — nothing about the
    # fixture changed. It is a pull request that merged on 2026-08-14 whose
    # linked ENG-101 is still sitting in 'In Progress' in active Sprint 24,
    # which is Ghost State Case A exactly. This fixture was hand-written in
    # Phase 6.4, months before P3 existed, and its own `_expect` note read
    # "ABSTAIN — already merged. Nothing to chase." That note was right about
    # the pull request and wrong about the ticket: there was nothing to chase
    # on GitHub, and a stale card on the board that no pattern could see.
    # Finding a real instance of a new pattern in evidence written before the
    # pattern existed is the strongest available check that the rule
    # describes something real rather than something fitted to it.
    expected_fire = {401: SF.P1, 410: SF.P2, 417: SF.P3, 422: SF.P2, 423: SF.P1,
                     425: SF.P1}
    expected_suppressed = {402, 403, 404, 411, 414, 415}
    for n, pat in expected_fire.items():
        r = rmap[by_number[n]]
        assert r.outcome == SF.FIRE and r.pattern == pat, (n, r.outcome, r.pattern)
    for n in expected_suppressed:
        assert rmap[by_number[n]].outcome == SF.SUPPRESSED, (n, rmap[by_number[n]].outcome)
    for n in by_number:
        if n not in expected_fire and n not in expected_suppressed:
            assert rmap[by_number[n]].outcome == SF.ABSTAIN, (n, rmap[by_number[n]])
    checks += 1
    print("  check 21  every item's outcome matches the fixture's own stated expectation")

    # #425 matches BOTH patterns; P1 must win on precedence.
    r425 = rmap[by_number[425]]
    assert r425.pattern == SF.P1, r425
    assert SF.evaluate_p2(conn, by_number[425]).outcome == SF.FIRE, \
        "the precedence test is only meaningful if P2 would also have fired"
    checks += 1
    print("  check 22  when both patterns fire, P1 (press merge) wins over P2 (go review)")

    # An item where every pattern abstains keeps every pattern's reason.
    # Phase 7.4X widened what "hiding neither" has to mean: with four
    # patterns, `alt_reason` can only carry the next-ranked different one, so
    # the complete picture moved to `all_reasons` and this check follows it
    # there. The property being checked is unchanged — no pattern's verdict
    # on an item is silently dropped.
    r419 = rmap[by_number[419]]
    assert r419.outcome == SF.ABSTAIN and r419.alt_reason, r419
    assert set(r419.all_reasons) == {SF.P1, SF.P2, SF.P3, SF.P4}, r419.all_reasons
    assert r419.all_reasons[SF.P2] == "no_live_manual_review_request", r419.all_reasons
    assert r419.all_reasons[SF.P1] == "never_reviewed", r419.all_reasons
    checks += 1
    print("  check 23  a four-way abstain records every pattern's reason, hiding none")

    # --- Phase 7.4X: the two new patterns on Phase 6.4's own fixtures ------
    r417 = rmap[by_number[417]]
    assert r417.pattern == SF.P3 and "ENG-101" in r417.evidence, r417
    assert "merged on GitHub" in r417.evidence, r417
    checks += 1
    print("  check 25a  P3 finds the ghost state Phase 6's fixtures already contained")

    # P4 has no instance here and must say so rather than firing on something
    # else: these fixtures carry no `presence` rows at all, so every reviewer
    # reads 'unknown', and 'unknown' is never converted into "they are away".
    assert not any(r.pattern == SF.P4 and r.outcome == SF.FIRE for r in results), \
        "P4 must not fire without a real out_of_office presence row"
    p4_reasons = {SF.evaluate_p4(conn, i).reason for i in ids.values()}
    assert "no_pending_reviewer_is_out_of_office" in p4_reasons, p4_reasons
    checks += 1
    print("  check 25b  P4 stays silent on a fixture set with no presence data, "
          "and says which condition was missing")

    summary = SF.summarise(results)
    assert summary[SF.FIRE] == 6, summary
    assert summary["fired_by_pattern"][SF.P3] == 1, summary
    assert summary[SF.SUPPRESSED] == 6, summary
    assert summary[SF.ABSTAIN] == len(ids) - 12, summary
    assert summary["suppressed_by_reason"]["no_ticket_link"] == 1, summary
    assert summary["suppressed_by_reason"]["not_active_sprint_work"] == 5, summary
    assert sum(summary["abstained_by_reason"].values()) == summary[SF.ABSTAIN], summary
    # The abstain key is every distinct reason on the row, in pattern-rank
    # order — see summarise()'s own comment for why it is not two. The two
    # keys checked here are the same two items Phase 6 checked; P3's and P4's
    # reasons are now named alongside P1's and P2's rather than displacing
    # them.
    assert summary["abstained_by_reason"][
        "never_reviewed / no_linked_ticket_marked_done / "
        "no_live_manual_review_request"] == 2, summary["abstained_by_reason"]
    assert summary["abstained_by_reason"][
        "never_reviewed / no_linked_ticket_marked_done / "
        "no_pending_reviewer_is_out_of_office / waited_only_12.0h"] == 1, summary["abstained_by_reason"]
    # Every abstain is counted exactly once in the short rollup too, and the
    # two breakdowns must never disagree about how many there were.
    assert sum(summary["abstained_by_primary_reason"].values()) == summary[SF.ABSTAIN], summary
    assert summary["abstained_by_primary_reason"]["never_reviewed"] == 4, summary
    checks += 1
    print("  check 24  the summary counts match: "
          f"{summary[SF.FIRE]} fire, {summary[SF.SUPPRESSED]} suppressed, "
          f"{summary[SF.ABSTAIN]} abstain")

    # Determinism: the same database must give the same answer twice.
    again = SF.run_pipeline(conn)
    assert [ (r.work_item_id, r.outcome, r.pattern, r.reason) for r in results ] == \
           [ (r.work_item_id, r.outcome, r.pattern, r.reason) for r in again ], \
           "the pipeline must be deterministic"
    checks += 1
    print("  check 25  a second pipeline run returns identical results")

    print(f"\nAll {checks} fixture-based checks passed.")
    return results, summary


def print_report(results, summary):
    print("\n--- What the pipeline would actually say ---")
    print(f"{'item':<14} {'outcome':<11} {'pattern':<22} {'actor':<8} {'idle':>7}  ticket / reason")
    for r in sorted(results, key=lambda x: (-SF._OUTCOME_RANK[x.outcome], x.item_key)):
        idle = f"{r.hours_idle:.0f}h" if r.hours_idle is not None else "-"
        tick = ",".join(r.ticket_keys) if r.ticket_keys else "-"
        why = r.reason if not r.alt_reason else f"{r.reason} / {r.alt_reason}"
        tail = tick if r.outcome == SF.FIRE else f"{tick}  [{why}]"
        print(f"{r.item_key:<14} {r.outcome:<11} {str(r.pattern or '-'):<22} "
              f"{str(r.next_actor or '-'):<8} {idle:>7}  {tail}")
    print("\nsuppressed_by_reason:", json.dumps(summary["suppressed_by_reason"]))
    print("abstained_by_reason: ", json.dumps(summary["abstained_by_reason"]))


if __name__ == "__main__":
    res, summ = run()
    print_report(res, summ)
