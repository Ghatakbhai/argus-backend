"""Phase 7.4X, Tasks 1.4 and 2.4 — unit proof for the two new deterministic
detectors, `sprint_filter.evaluate_p3` (Ghost State Reconciler) and
`sprint_filter.evaluate_p4` (Slack OOO x sprint-end advisor).

Postgres-free on purpose, and that is not a shortcut: `sprint_filter.py`
reads a `sqlite3.Connection` (D-127 — Phase 6's engine was deliberately not
rewritten into Postgres's dialect), so a sqlite world built from the real
`src/schema.sql` IS the production shape for this module, the same standard
`test_dashboard_payload.py` already holds itself to. The Postgres suite
proves the surrounding backend; this file proves the rules.

Every world here is built from a plain statement of a situation, so a
failure reads as "ARGUS got THIS case wrong" rather than "assertion 4
failed".
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import sprint_filter as SF  # noqa: E402

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NOW = "2026-08-28T09:00:00Z"
LONG_AGO = "2026-08-20T09:00:00Z"          # 8 days before NOW
YESTERDAY = "2026-08-27T02:00:00Z"         # 31h before NOW
TWO_HOURS_AGO = "2026-08-28T07:00:00Z"     # inside the 24h threshold


def _world():
    """One GitHub project, one Jira project, one active sprint, three people.

    Nothing is flagged in this base world — every test below turns exactly
    one fact on, so a firing result can only be caused by the fact that test
    named.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with open(os.path.join(SRC, "schema.sql")) as f:
        conn.executescript(f.read())

    conn.execute("INSERT INTO source (id, name, base_url)"
                 " VALUES (1,'github','https://github.com')")
    conn.execute("INSERT INTO source (id, name, base_url)"
                 " VALUES (2,'jira','https://acme.atlassian.net')")
    conn.execute("INSERT INTO project (id, source_id, source_key, display_name)"
                 " VALUES (1,1,'acme/api','acme/api')")
    conn.execute("INSERT INTO project (id, source_id, source_key, display_name)"
                 " VALUES (2,2,'ENG','Engineering')")
    conn.execute("INSERT INTO snapshot (id, source_id, project_id, observed_at,"
                 " started_at, is_complete) VALUES (1,1,1,?,?,1)", (NOW, NOW))
    for aid, login in ((1, "priya-n"), (2, "sarah-m"), (3, "tom-b")):
        conn.execute("INSERT INTO actor (id, source_id, source_key, kind, kind_reason)"
                     " VALUES (?,1,?,'human','assumed_human')", (aid, login))
    # An active sprint that still has a week to run, and a second one closing
    # in 12 hours. Both are 'active' — the difference is only `ends_at`, which
    # is exactly the distinction P4's first trigger leg turns on.
    conn.execute("INSERT INTO sprint (id, project_id, source_key, name, state,"
                 " starts_at, ends_at) VALUES (1,2,'501','Sprint 12','active',?,?)",
                 (LONG_AGO, "2026-09-04T09:00:00Z"))
    conn.execute("INSERT INTO sprint (id, project_id, source_key, name, state,"
                 " starts_at, ends_at) VALUES (2,2,'502','Sprint 13','active',?,?)",
                 (LONG_AGO, "2026-08-28T21:00:00Z"))
    conn.commit()
    return conn


def _ticket(conn, tid, key, status, category, sprint_id=1):
    conn.execute(
        "INSERT INTO ticket (id, source_id, project_id, source_key, title,"
        " source_status, status_category, sprint_id, created_at)"
        " VALUES (?,2,2,?,?,?,?,?,?)",
        (tid, key, f"{key} work", status, category, sprint_id, LONG_AGO))
    return tid


def _pr(conn, wid, number, *, state="open", closed_at=None, is_draft=0, author=1):
    conn.execute(
        "INSERT INTO work_item (id, snapshot_id, project_id, source_number, kind,"
        " title, state, is_draft, author_id, created_at, closed_at, url)"
        " VALUES (?,1,1,?,'change_request',?,?,?,?,?,?,?)",
        (wid, number, f"[ENG-{number}] a change", state, is_draft, author,
         LONG_AGO, closed_at, f"https://github.com/acme/api/pull/{number}"))
    return wid


def _link(conn, tid, wid):
    conn.execute("INSERT INTO ticket_link (ticket_id, work_item_id, link_method,"
                 " confidence, detected_at) VALUES (?,?,'branch_name','high',?)",
                 (tid, wid, NOW))


def _human_event(conn, wid, actor, at, etype="commented"):
    conn.execute(
        "INSERT INTO event (snapshot_id, work_item_id, type, actor_id, occurred_at,"
        " counts_as_human, human_reason) VALUES (1,?,?,?,?,1,'human')",
        (wid, etype, actor, at))


def _request_review(conn, wid, actor, at, origin="manual"):
    conn.execute("INSERT INTO review_request (work_item_id, actor_id, requested_by,"
                 " requested_at, origin) VALUES (?,?,1,?,?)", (wid, actor, at, origin))


def _out_of_office(conn, actor, frm=LONG_AGO, to="2026-09-02T09:00:00Z"):
    conn.execute("INSERT INTO presence (actor_id, status, detected_via,"
                 " effective_from, effective_to, detected_at)"
                 " VALUES (?,'out_of_office','slack_status',?,?,?)", (actor, frm, to, NOW))


# ===========================================================================
# Pattern 3 — Case A: merged on GitHub, still live work on the board
# ===========================================================================

def test_p3_case_a_fires_when_a_merged_pr_leaves_its_ticket_in_progress():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.FIRE, (r.outcome, r.reason, r.evidence)
    assert r.pattern == SF.P3
    assert "ENG-101" in r.evidence and "In Progress" in r.evidence
    assert "merged on GitHub" in r.evidence
    assert r.hours_idle == pytest.approx(31.0, abs=0.1)


@pytest.mark.parametrize("category,status", [
    ("in_progress", "In Progress"), ("in_review", "In Review"), ("ready", "Ready"),
])
def test_p3_case_a_covers_every_active_category(category, status):
    conn = _world()
    _ticket(conn, 10, "ENG-101", status, category)
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    assert SF.evaluate_p3(conn, 1).outcome == SF.FIRE


def test_p3_case_a_is_silent_before_the_24_hour_threshold():
    """A merge and a board update do not have to be simultaneous. The whole
    point of the 24h floor is that a team gets a working day to catch up."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=TWO_HOURS_AGO)
    _link(conn, 10, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason.startswith("merged_only_2.0h")


def test_p3_case_a_is_silent_when_the_ticket_was_moved_to_done():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "Done", "done")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason == "no_linked_ticket_still_active"


def test_p3_case_a_abstains_rather_than_guessing_an_unreadable_merge_date():
    """D-031/D-037/D-042's rule applied to a clock: a merged row with no
    readable date could be five minutes or five months old, and no fallback
    clock can answer that. It abstains — it does not fall back to created_at
    and produce an alert in the direction that happens to be convenient."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=None)
    _link(conn, 10, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason == "merged_without_a_readable_date"


def test_p3_case_a_is_suppressed_when_the_drifting_ticket_is_not_in_an_active_sprint():
    """The gate still has the last word on P3, exactly as on P1/P2 — and a
    SUPPRESSED row, not silence, so the count stays auditable."""
    conn = _world()
    conn.execute("UPDATE sprint SET state='closed' WHERE id=1")
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.SUPPRESSED
    assert r.reason == "not_active_sprint_work"


def test_p3_gate_reads_the_drifting_ticket_not_some_other_linked_one():
    """The load-bearing reason P3 passes `only_ticket_key` to the gate.

    ENG-101 is the ticket that has drifted and it is in NO sprint. ENG-102 is
    linked to the same PR, is in an active sprint, and has nothing to do with
    the drift. The default gate ("at least one linked ticket is live work")
    would wave this through and the digest line would then name Sprint 12 —
    a sprint the drifting ticket is not in.
    """
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress", sprint_id=None)
    _ticket(conn, 11, "ENG-102", "In Progress", "in_progress", sprint_id=1)
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    _link(conn, 11, 1)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.SUPPRESSED, r.evidence
    assert "ENG-101 is in no sprint" in r.evidence


def test_p3_abstains_with_its_own_reason_when_no_ticket_could_be_linked():
    """An integration gap, reported as one — not as "the board is fine"."""
    conn = _world()
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason == "no_ticket_link"


# ===========================================================================
# Pattern 3 — Case B: the board says done, the PR is still open
# ===========================================================================

def test_p3_case_b_fires_when_a_done_ticket_still_has_an_open_pr():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "Done", "done")
    _pr(conn, 1, 401, state="open")
    _link(conn, 10, 1)
    _human_event(conn, 1, 1, YESTERDAY)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.FIRE, (r.reason, r.evidence)
    assert "still open" in r.evidence and "ENG-101" in r.evidence
    assert r.hours_idle == pytest.approx(31.0, abs=0.1)


def test_p3_case_b_is_silent_while_the_pr_is_still_moving():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "Done", "done")
    _pr(conn, 1, 401, state="open")
    _link(conn, 10, 1)
    _human_event(conn, 1, 1, TWO_HOURS_AGO)
    r = SF.evaluate_p3(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason.startswith("idle_only_2.0h")


def test_p3_case_b_ignores_drafts():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "Done", "done")
    _pr(conn, 1, 401, state="open", is_draft=1)
    _link(conn, 10, 1)
    _human_event(conn, 1, 1, YESTERDAY)
    assert SF.evaluate_p3(conn, 1).reason == "draft"


def test_p3_ignores_issues_and_plain_closed_prs():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "Done", "done")
    _pr(conn, 1, 401, state="closed", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    assert SF.evaluate_p3(conn, 1).reason == "state_is_closed"

    conn.execute("UPDATE work_item SET kind='issue' WHERE id=1")
    assert SF.evaluate_p3(conn, 1).reason == "not_a_pull_request"


def test_p3_accepts_an_explicit_now_and_still_never_reads_wall_clock():
    """The `now` parameter the execution plan's signature names. Passing an
    earlier moment must make the same world stop firing — proof the clock
    really is the argument and not `datetime.now()` sneaking in."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    assert SF.evaluate_p3(conn, 1, now=NOW).outcome == SF.FIRE
    assert SF.evaluate_p3(conn, 1, now="2026-08-27T10:00:00Z").outcome == SF.ABSTAIN


# ===========================================================================
# Pattern 4 — reviewer out of office, cycle closing
# ===========================================================================

def test_p4_fires_when_the_requested_reviewer_is_ooo_and_the_cycle_closes_soon():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)  # ends in 12h
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2)
    r = SF.evaluate_p4(conn, 1)
    assert r.outcome == SF.FIRE, (r.reason, r.evidence)
    assert r.pattern == SF.P4
    assert "sarah-m" in r.evidence and "out of office" in r.evidence
    assert "Sprint 13 ends in 12h" in r.evidence
    assert "backup reviewer" in r.evidence


def test_p4_addresses_the_author_not_the_person_on_holiday():
    """A nudge sent to someone who is provably not reading it is not an
    alert, it is a delay. See evaluate_p4's own section docstring."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2)
    r = SF.evaluate_p4(conn, 1)
    assert r.next_actor == "tom-b"          # the author
    assert r.next_actor != "sarah-m"        # the absent reviewer


def test_p4_second_trigger_leg_an_idle_request_with_no_cycle_deadline():
    """Sprint 12 has a week left, so the deadline leg is not met — but the
    request has been idle 31h, which is the other half of the OR."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=1)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2)
    r = SF.evaluate_p4(conn, 1)
    assert r.outcome == SF.FIRE
    assert "Sprint 12 ends in 168h" in r.evidence


def test_p4_is_silent_when_neither_leg_of_the_or_is_met():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=1)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, TWO_HOURS_AGO)
    _out_of_office(conn, 2)
    r = SF.evaluate_p4(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason.startswith("not_urgent")


def test_p4_is_silent_when_the_reviewer_is_at_their_desk():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    r = SF.evaluate_p4(conn, 1)
    assert r.outcome == SF.ABSTAIN
    assert r.reason == "no_pending_reviewer_is_out_of_office"


def test_p4_treats_an_expired_absence_as_not_out_rather_than_carrying_it_forward():
    """`presence_at`'s own rule, which this module re-implements to avoid a
    circular import — so it has to be proven here, not assumed inherited."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2, frm=LONG_AGO, to="2026-08-26T09:00:00Z")   # already back
    assert SF.evaluate_p4(conn, 1).reason == "no_pending_reviewer_is_out_of_office"


def test_p4_ignores_codeowners_requests_the_same_way_p2_does():
    """D-043: an automatic request is not a promise anybody made."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY, origin="codeowners")
    _out_of_office(conn, 2)
    assert SF.evaluate_p4(conn, 1).reason == "no_live_manual_review_request"


def test_p4_is_silent_when_the_absent_reviewer_already_responded():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _human_event(conn, 1, 2, "2026-08-27T12:00:00Z", etype="review_submitted")
    _out_of_office(conn, 2)
    assert SF.evaluate_p4(conn, 1).reason == "every_requested_reviewer_responded"


def test_p4_is_silent_when_somebody_else_approved_since():
    """H6, inherited from P2/S-04: the PR is not waiting on the absent
    reviewer at all, so chasing a backup for them would be a false alarm."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2)
    _human_event(conn, 1, 3, "2026-08-28T01:00:00Z", etype="review_submitted")
    eid = conn.execute("SELECT MAX(id) FROM event").fetchone()[0]
    conn.execute("INSERT INTO review (event_id, work_item_id, actor_id, state,"
                 " submitted_at) VALUES (?,1,3,'approved',?)",
                 (eid, "2026-08-28T01:00:00Z"))
    assert SF.evaluate_p4(conn, 1).reason == "another_reviewer_approved_since"


def test_p4_names_the_return_date_when_slack_gave_one_and_says_so_when_it_did_not():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, YESTERDAY)
    _out_of_office(conn, 2, to=None)
    r = SF.evaluate_p4(conn, 1)
    assert r.outcome == SF.FIRE
    assert "return date unknown" in r.evidence


# ===========================================================================
# The pipeline: four patterns, still exactly one result per item
# ===========================================================================

def test_pipeline_returns_exactly_one_result_per_item_with_four_patterns():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _pr(conn, 2, 402, state="open")
    _link(conn, 10, 1)
    results = SF.run_pipeline(conn)
    assert len(results) == 2
    assert {r.work_item_id for r in results} == {1, 2}


def test_p4_outranks_p2_on_an_item_where_both_fire():
    """The precedence decision that matters most. Both patterns describe the
    identical silence; P4's line is P2's line plus the two facts a lead needs
    to act, so throwing it away for P2 would lose the only actionable part."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Review", "in_review", sprint_id=2)
    _pr(conn, 1, 401, state="open", author=3)
    _link(conn, 10, 1)
    _request_review(conn, 1, 2, LONG_AGO)      # 8 days: past P2's 48h too
    _out_of_office(conn, 2)
    assert SF.evaluate_p2(conn, 1).outcome == SF.FIRE       # P2 fires on its own
    assert SF.evaluate_p4(conn, 1).outcome == SF.FIRE       # so does P4
    picked = SF.run_pipeline(conn, [1])[0]
    assert picked.pattern == SF.P4, picked.pattern


def test_a_fire_always_beats_a_higher_ranked_patterns_abstain():
    """Outcome first, pattern rank only as a tiebreak — P1 outranks P3, but
    an abstaining P1 must never silence a firing P3."""
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    assert SF.evaluate_p1(conn, 1).outcome == SF.ABSTAIN
    picked = SF.run_pipeline(conn, [1])[0]
    assert picked.outcome == SF.FIRE and picked.pattern == SF.P3


def test_every_pattern_records_its_own_reason_on_an_abstaining_row():
    conn = _world()
    _pr(conn, 1, 401, state="open")
    picked = SF.run_pipeline(conn, [1])[0]
    assert picked.outcome == SF.ABSTAIN
    assert set(picked.all_reasons) == {SF.P1, SF.P2, SF.P3, SF.P4}
    assert picked.alt_reason and picked.alt_reason != picked.reason


def test_summarise_counts_the_new_patterns_by_name():
    conn = _world()
    _ticket(conn, 10, "ENG-101", "In Progress", "in_progress")
    _pr(conn, 1, 401, state="merged", closed_at=YESTERDAY)
    _link(conn, 10, 1)
    summary = SF.summarise(SF.run_pipeline(conn, [1]))
    assert summary["fired_by_pattern"] == {SF.P3: 1}
