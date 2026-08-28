"""ARGUS Phase 7.4b — assembles the dashboard's envelope JSON.

This is the piece `src/dashboard/CONTRACT.md` named as owed: the exact shape
`src/dashboard/fixtures/digest_payload.json` invented by hand, now built for
real from Phase 6's own frozen engine (`sprint_filter.py`, `digest.py`,
`presence.py` — unmodified, per D-127) instead of typed out by a person.

**What this module does NOT attempt**, named plainly rather than faked:

  * `freshness.verified_at` — a re-check *after* the digest was assembled,
    confirming the flagged items are still open. Nothing in this project
    performs that re-check yet. Always None here. CONTRACT.md §4: shipping a
    guessed value here would be the exact "we could not see, rendered as
    it's fine" defect this whole project exists to argue against.
  * Semantic clustering of differently-worded reports of the same underlying
    blocker. `_clusters()` groups rows only where the **typed blocker text
    matches exactly** — the narrowest, most defensible reading of D-152's
    rule ("a blocker somebody actually typed"). Two people describing the
    same outage in different words are not merged; that would be exactly
    the guessed-shared-cause error D-152 already rejected once.
  * A CI *history*. `readiness.checks_state` is this project's only stored
    CI signal, and it is a current snapshot, not a log — there is no table
    of past check runs to draw a timeline entry from. `evidence_detail.ci`
    reports the current state; the timeline does not narrate how it got
    there.

**A load-bearing scope note.** Everything in this module reads a
`sqlite3.Connection` — the same one `sprint_filter.run_pipeline` and
`digest.collect` have always read, per D-127's decision not to rewrite
~250KB of proven engine SQL into Postgres's dialect. That is deliberate, not
an oversight: as of this session, nothing in the live Postgres backend ever
turns a GitHub/Jira/Slack webhook into `work_item`/`event` rows for a real
tenant (`app.py`'s own webhook handler docstring says so — "a content event
queues a fresh ingest_run... rather than being mapped id"), so there is no
live Postgres data for a Postgres-native version of this module to read yet
regardless. This module is what makes `digest_delivery.payload_json` real
for the data ARGUS *does* have today — a migrated Phase 6 sqlite snapshot —
and it is exactly the function a future live pipeline would call once that
deeper gap (named in `context/DECISIONS.md`, not part of 7.4b) is closed.
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
from typing import Any, Optional

# `digest.py`, `presence.py`, `sprint_filter.py` live in src/, one directory
# above src/backend/ — this module's own location, computed rather than
# hardcoded, so it works the same way whether it is imported from a script
# run out of src/, from backend.migrate_sqlite, or from a test in
# src/backend/tests/.
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import digest as D  # noqa: E402
import presence as P  # noqa: E402
from . import llm_copilot  # noqa: E402 — Milestone 2 (D-172)
import sprint_filter as SF  # noqa: E402

_CI_LABEL = {"clean": "green", "blocked": "red", "unknown": "unknown"}

# Milestone 1, Task 5.4. Not every ABSTAIN reason means the same thing to a
# lead reading the audit drawer: most are a clean, confident non-match (a
# closed issue, a draft PR, a reviewer who already responded) and are
# correctly silent. A specific few mean "we could not tell" — a coverage
# gap, not a verdict — and CONTRACT.md §4 already named exactly one of them
# (`no_readable_clock`, the existing `held_candidates` count) as the real,
# available case. `ci_not_known_green (unknown)` is the same kind of gap
# (CI genuinely never reported, not CI that reported failure) and is added
# here for the same reason. This classifies DISPLAY only — it changes no
# outcome, no `alert.outcome` row, nothing `sprint_filter.py` decided.
def _is_unknown_reason(reason: str) -> bool:
    return reason == "no_readable_clock" or reason.startswith("ci_not_known_green (unknown)")


def _ci_state(conn: sqlite3.Connection, wid: int) -> Optional[str]:
    row = conn.execute(
        "SELECT checks_state FROM readiness WHERE work_item_id=?", (wid,)
    ).fetchone()
    if not row:
        return None
    return _CI_LABEL.get(row[0], row[0])


def _actor_id_by_login(conn: sqlite3.Connection, login: Optional[str]) -> Optional[int]:
    if not login:
        return None
    row = conn.execute("SELECT id FROM actor WHERE source_key=? LIMIT 1", (login,)).fetchone()
    return row[0] if row else None


def _presence_str(conn: sqlite3.Connection, login: Optional[str], now: str) -> Optional[str]:
    actor_id = _actor_id_by_login(conn, login)
    if actor_id is None:
        return None
    p = P.presence_at(conn, actor_id, now)
    return f"{login} {p.status}"


_EVENT_VERB = {
    "opened": "Opened", "closed": "Closed", "reopened": "Reopened",
    "commented": "Commented", "review_submitted": "Submitted a review",
    "review_requested": "Requested review", "review_request_removed": "Review request removed",
    "assigned": "Assigned", "unassigned": "Unassigned", "labeled": "Labeled",
    "unlabeled": "Unlabeled", "milestoned": "Milestoned", "demilestoned": "Demilestoned",
    "committed": "Pushed a commit", "force_pushed": "Force-pushed",
    "ready_for_review": "Marked ready for review", "converted_to_draft": "Converted to draft",
    "renamed": "Renamed", "referenced": "Referenced", "cross_referenced": "Cross-referenced",
    "reacted": "Reacted", "other": "Activity",
}


def _describe_event(ev_type: str, login: Optional[str], detail: Optional[str]) -> str:
    text = _EVENT_VERB.get(ev_type, ev_type)
    if login:
        text += f" by {login}"
    if detail:
        snippet = " ".join(detail.strip().split())
        if len(snippet) > 80:
            snippet = snippet[:77] + "..."
        text += f": {snippet}"
    return text


def _timeline(conn: sqlite3.Connection, wid: int, now: str, row: D.DigestRow) -> list[dict]:
    """Real `event` rows plus the two synthetic facts digest.py itself already
    knows about this item: the [Blocked on...] answer (if any) and where
    things stand right now. Nothing here is inferred beyond what a stored
    row says."""
    entries: list[dict[str, Any]] = []
    for ev_type, at, detail, login in conn.execute(
        """SELECT e.type, e.occurred_at, e.detail, a.source_key
           FROM event e LEFT JOIN actor a ON a.id = e.actor_id
           WHERE e.work_item_id = ? AND e.occurred_at IS NOT NULL AND e.occurred_at <= ?
           ORDER BY e.occurred_at""",
        (wid, now),
    ).fetchall():
        entries.append({"at": at, "what": _describe_event(ev_type, login, detail), "hot": False})

    blocker = D.latest_blocker(conn, wid, now)
    if blocker:
        login, text, at = blocker
        entries.append({
            "at": at, "hot": True,
            "what": f"{login} answered [Blocked on…]: “{(text or '').strip()}”",
        })

    entries.sort(key=lambda e: e["at"] or "")
    entries.append({"at": now, "hot": True,
                    "what": f"Still open — {row.headline}" if row.headline else "Still open"})
    return entries[-8:]


def _evidence_detail(conn: sqlite3.Connection, res: SF.FilterResult, now: str,
                     row: D.DigestRow) -> dict:
    d = res.as_dict()
    d["observed_at"] = now
    d["ci"] = _ci_state(conn, res.work_item_id)
    d["presence"] = _presence_str(conn, row.person, now)
    d["timeline"] = _timeline(conn, res.work_item_id, now, row)
    return d


def _recent_comments(conn: sqlite3.Connection, wid: int, limit: int = 5) -> list[str]:
    """The "recent 3-5 review comments" Milestone 2 Task 2.1 asks for.
    Human/AI-drafted only — a bot's own status-check comment is not the
    conversational context a TL;DR should be summarizing (same
    `authorship` vocabulary D-057 already established for comment.py)."""
    rows = conn.execute(
        "SELECT body FROM comment WHERE work_item_id = ? AND authorship != 'bot'"
        " ORDER BY created_at DESC LIMIT ?", (wid, limit)).fetchall()
    return [r[0] for r in reversed(rows) if r[0]]


def _ticket_keys(conn: sqlite3.Connection, wid: int) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT t.source_key FROM ticket_link tl JOIN ticket t ON t.id = tl.ticket_id"
        " WHERE tl.work_item_id = ?", (wid,)).fetchall()]


def _reviewer_logins(conn: sqlite3.Connection, wid: int) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT DISTINCT a.source_key FROM event e JOIN actor a ON a.id = e.actor_id"
        " WHERE e.work_item_id = ? AND e.type IN ('review_requested', 'review_submitted')"
        "   AND a.source_key IS NOT NULL", (wid,)).fetchall()]


def _copilot_enrichment(conn: sqlite3.Connection, res: SF.FilterResult, row: D.DigestRow,
                        evidence: str) -> Optional[dict]:
    """Milestone 2, Tasks 2.1-2.4/3.1-3.3: assembles this FIRE item's
    context and calls the LLM copilot layer exactly once. Computed here, at
    digest-build time (once per ingest run, per FIRE item), and persisted
    into `payload_json` by the caller — this IS the caching Task 4.3 asks
    for; there is no separate cache table because there is nothing to key
    one by that `digest_delivery.payload_json` does not already provide.
    Returns `None` with zero side effects if `ARGUS_LLM_API_KEY` is unset or
    the call fails for any reason — `llm_copilot.generate_enrichment`'s own
    Fail-Safe Fallback Invariant, unchanged here."""
    wid = res.work_item_id
    wrow = conn.execute("SELECT title, body, author_id FROM work_item WHERE id = ?",
                        (wid,)).fetchone()
    if wrow is None:
        return None
    title, body, author_id = wrow
    author_login = None
    if author_id is not None:
        arow = conn.execute("SELECT source_key FROM actor WHERE id = ?", (author_id,)).fetchone()
        author_login = arow[0] if arow else None

    ctx = llm_copilot.build_context(
        item_key=res.item_key, pattern=res.pattern, title=title or "", body=body or "",
        comments=_recent_comments(conn, wid), ticket_keys=_ticket_keys(conn, wid),
        evidence=evidence, author_login=author_login,
        reviewer_logins=_reviewer_logins(conn, wid))
    return llm_copilot.generate_enrichment(ctx)


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _cluster_id(text: str) -> str:
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return (slug[:40] or "blocker").rstrip("-")


def _clusters(rows: list[dict]) -> list[dict]:
    """D-152's rule, operationalised the narrowest way that is still real: a
    cluster forms only where two or more BLOCKED rows carry the exact same
    typed blocker text. See module docstring for what this deliberately does
    not attempt (matching two different phrasings of the same outage)."""
    groups: dict[str, list[dict]] = {}
    for r in rows:
        if r["section"] != D.SECTION_BLOCKED:
            continue
        text = (r.get("blocker_text") or "").strip()
        if not text:
            continue
        groups.setdefault(text, []).append(r)

    clusters = []
    for text, members in groups.items():
        if len(members) < 2:
            continue
        cid = _cluster_id(text)
        for m in members:
            m["cluster"] = cid
        tickets = sorted({k for m in members
                          for k in (m.get("evidence_detail") or {}).get("ticket_keys", [])})
        oldest_hours = max((m.get("age_hours") or 0) for m in members)
        clusters.append({
            "id": cid,
            "label": text if len(text) <= 60 else text[:57] + "...",
            "tone": "urgent",
            "why": (f"{len(members)} items report the same blocker, in the words the "
                    f"reporter used: “{text}”."),
            "member_keys": [m["item_key"] for m in members],
            "tickets": tickets,
            "oldest_age_label": D.age_phrase(oldest_hours),
        })
    return clusters


def _people_out(conn: sqlite3.Connection, now: str) -> list[dict]:
    out = []
    for actor_id, login in conn.execute(
        """SELECT DISTINCT p.actor_id, a.source_key FROM presence p
           JOIN actor a ON a.id = p.actor_id
           WHERE p.status = 'out_of_office' AND p.effective_from <= ?
             AND (p.effective_to IS NULL OR p.effective_to > ?)""",
        (now, now),
    ).fetchall():
        since = P.out_of_office_since(conn, actor_id, now)
        if since is None:
            continue
        hours = D._hours_since(D.ST._require_now(now), since)
        held = conn.execute(
            """SELECT COUNT(*) FROM triage_message
               WHERE sent_to_actor_id=? AND status='suppressed_presence'
                 AND sent_at >= ? AND sent_at <= ?""",
            (actor_id, since, now),
        ).fetchone()[0]
        out.append({
            "login": login, "status_text": "Out of office", "since": since,
            "days_out": round((hours or 0) / 24, 1), "alerts_held": held,
        })
    return out


def _integrations(conn: sqlite3.Connection) -> list[dict]:
    """The honest version of CONTRACT.md §4's integrations[] rollup: real
    presence/absence of an installed integration per source, from the tables
    that actually record it. No uptime, no rate-limit state — this project
    has no table those would come from yet, and a percentage this module
    made up would be exactly the failure CONTRACT.md warns against."""
    out = []
    try:
        rows = conn.execute("SELECT id, name FROM source ORDER BY name").fetchall()
    except sqlite3.OperationalError:
        return out
    has_integration_table = True
    try:
        conn.execute("SELECT 1 FROM integration LIMIT 1")
    except sqlite3.OperationalError:
        has_integration_table = False
    for source_id, name in rows:
        status, detail = "not_connected", "no integration installed"
        if has_integration_table:
            n = conn.execute(
                "SELECT COUNT(*) FROM integration WHERE source_id=? AND revoked_at IS NULL",
                (source_id,),
            ).fetchone()[0]
            if n:
                status, detail = "ok", f"{n} integration(s) installed"
        out.append({"name": name, "status": status, "detail": detail})
    return out


def build_dashboard_payload(
    conn: sqlite3.Connection,
    results: list[SF.FilterResult],
    now: str,
    *,
    tenant_slug: str,
    team_label: str,
    tenant_members: int,
    shadow_until: Optional[str] = None,
    dig: Optional[D.Digest] = None,
) -> dict:
    """The full envelope `src/dashboard/index.html` reads, built from real
    data. Returns a plain dict, ready for `json.dumps`.

    `dig`: pass an already-computed `Digest` (e.g. because the caller also
    needs it to render the Slack/HTML text) to avoid running `digest.collect`
    twice over the same inputs. `collect()` is a pure read, so computing it
    twice would not disagree with itself — this parameter exists to save the
    work, not to guard against drift.
    """
    if dig is None:
        dig = D.collect(conn, results, now, team_label=team_label)
    live = {r.work_item_id: r for r in results if r.outcome == SF.FIRE}

    row_dicts = []
    for row in dig.rows:
        rd = row.as_dict()
        res = live.get(row.work_item_id)
        rd["evidence_detail"] = _evidence_detail(conn, res, now, row) if res else None
        rd["blocker_text"] = row.headline if row.section == D.SECTION_BLOCKED else None
        rd["cluster"] = None
        # Milestone 2, Task 5.1: embedded per-row, alongside evidence_detail,
        # not as one top-level dict — the natural home for something a
        # single Slack DM or dashboard card renders about ONE item.
        # Computed only for FIRE rows (`res` is None otherwise, per `live`
        # above): SUPPRESSED/ABSTAIN items were never going to reach a
        # person, so there is nothing for a copilot to summarize FOR.
        rd["copilot"] = (_copilot_enrichment(conn, res, row, res.evidence)
                         if res else None)
        row_dicts.append(rd)

    clusters = _clusters(row_dicts)

    suppressed_items = []
    for res in results:
        if res.outcome != SF.SUPPRESSED:
            continue
        suppressed_items.append({
            "item_key": res.item_key,
            "title": D._item_title(conn, res.work_item_id),
            "url": D._item_url(conn, res.work_item_id),
            "pattern": res.pattern,
            "reason": res.reason,
            "detail": res.evidence,
            "decided_at": now,
        })

    # Milestone 1, Task 5.4: the item-level version of what `held_candidates`
    # below has only ever counted. A lead could see "2 held" but never which
    # two — the exact "silently dropped" gap 5.4 names. Same row shape as
    # `suppressed_items` above, on purpose: the audit drawer already knows
    # how to render that shape.
    unknown_items = []
    for res in results:
        if res.outcome != SF.ABSTAIN or not _is_unknown_reason(res.reason):
            continue
        unknown_items.append({
            "item_key": res.item_key,
            "title": D._item_title(conn, res.work_item_id),
            "url": D._item_url(conn, res.work_item_id),
            "pattern": res.pattern,
            "reason": res.reason,
            "detail": res.evidence,
            "decided_at": now,
        })

    held_candidates = sum(1 for r in results
                          if r.outcome == SF.ABSTAIN and r.reason == "no_readable_clock")
    delivery_blockers = dig.counts.fired
    if delivery_blockers:
        state, headline = "action_required", (
            f"{delivery_blockers} high-confidence delivery blocker"
            f"{'s' if delivery_blockers != 1 else ''} detected")
    else:
        state, headline = "clean", "All clear"
    integrations = _integrations(conn)
    if any(i["status"] != "ok" for i in integrations):
        state = "degraded" if state != "action_required" else state

    freshness = {
        "state": state,
        "evaluated_at": now,
        "verified_at": None,  # see module docstring — not built, not guessed
        "delivery_blockers": delivery_blockers,
        "held_candidates": held_candidates,
        "headline": headline,
        "detail": (f"{dig.counts.items_checked} items checked, "
                   f"{dig.counts.suppressed} suppressed, "
                   f"{dig.counts.abstained} not matching a pattern."),
        "integrations": integrations,
    }

    digest_dict = dig.as_dict()
    digest_dict["rows"] = row_dicts  # the enriched rows, not dig.as_dict()'s bare ones

    return {
        "contract_version": "7.4d",
        "generated_by": "src/backend/dashboard_payload.py",
        "tenant": {
            "slug": tenant_slug, "label": team_label,
            "members": tenant_members, "shadow_until": shadow_until,
        },
        "freshness": freshness,
        "digest": digest_dict,
        "clusters": clusters,
        "people_out": _people_out(conn, now),
        "suppressed_items": suppressed_items,
        "unknown_items": unknown_items,
    }
