"""ARGUS Phase 7 — Milestone 1, Task 5 (5.2/5.3): the system-health signal.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT.

`docs/MILESTONE_1_CORE_INFRASTRUCTURE_GAPS.md` §5 asks for detector output
to become explicitly tri-state — `FIRE`, `SUPPRESSED`, or `UNKNOWN` — in
`sprint_filter.py`. Verifying that against the code (the same discipline
D-169 held itself to before touching `sprint_filter.py`) found it already
IS tri-state, and has been since Phase 6.4: `FIRE` / `SUPPRESSED` / `ABSTAIN`,
with `ABSTAIN`'s own module docstring stating the exact rule the milestone
doc is asking for — "an unknown is never converted into a claim, in
whichever direction a claim would have been convenient." `sprint_filter.py`
is untouched by this module, on purpose: it is frozen, tested (D-169's own
mutation-testing precedent), and correct. Renaming `ABSTAIN` to `UNKNOWN`
would not fix anything — it would erase the distinction between "the pattern
genuinely did not match" (most open work items, every day, forever) and "we
do not have enough data to judge," and every lead's digest would read as
permanently degraded. See `context/DECISIONS.md` for the full reasoning.

What §5 is actually reaching for — named plainly in its own sub-tasks 5.2
and 5.3 — is a DIFFERENT, ORTHOGONAL signal: not "what did this one work
item's pattern check decide," but "can this tenant's data be trusted right
now." That is a property of the PIPELINE (is GitHub actually reachable, is
an integration still connected, has a webhook arrived recently), not of any
one `FilterResult`. This module computes exactly that, as an additive
CLEAN/DEGRADED verdict alongside — never instead of — the existing
FIRE/SUPPRESSED/ABSTAIN outcome on every alert. Nothing here changes what
fires, what's suppressed, or what's stored in `alert.outcome` (still
CHECK-constrained to the original three values; widening it for a fourth
value nobody's alert-level logic asked for would be exactly the same
mistake D-169 Decision 4 already declined to make for `sprint_filter.py`
itself).

THE THREE CONDITIONS, PER 5.2's OWN WORDING
--------------------------------------------
  1. Missing integration coverage — GitHub is the one integration every
     live pipeline requires (`ingest_worker.NoGitHubInstallation`); its
     absence is always reported. Jira/Linear/Slack are optional per tenant
     (D-16x) — a tenant that never connected one is not degraded by that
     alone (most pilots won't run all three). A tenant that HAD one and it
     was since revoked (unlinked, token rotated out, workspace uninstalled)
     is reported: that is a real regression a lead should hear about.
  2. Stale webhook state (>24h) — for a tenant with an active GitHub
     integration, the freshest of (a) the newest recorded `webhook_delivery`
     and (b) the newest successfully-finished `ingest_run` is checked
     against `now`. Neither ever having happened, for an integration that
     IS installed, is itself reported (installed-but-silent is not a clean
     state to leave unmentioned).
  3. Provider rate-limiting — `ingest_worker.run_one()` already collects a
     per-source `error_detail` string on the `ingest_run` row (repo/Jira-
     project/Linear-team failures, semicolon-joined, unchanged by this
     session). `live_github.py`, `live_jira.py` and `live_linear.py` all
     report a 429/rate-limit condition as recognisable text in that same
     string (`"HTTP 429 (rate limited or forbidden)"`,
     `"HTTP 429: ..."`, `"rate limited: ..."` respectively) — verified
     against each module directly rather than assumed. This module matches
     on that text rather than inventing a new structured field those three
     modules don't populate.

Any one of the three present makes the tenant DEGRADED. Zero makes it
CLEAN. This module never guesses at a fourth condition CONTRACT.md §4
explicitly named as not yet real (uptime percentages, fetch-latency
rollups) — the same "a freshness indicator that is itself guessing is worse
than no banner" rule that section already holds itself to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

CLEAN = "CLEAN"
DEGRADED = "DEGRADED"

STALE_WEBHOOK_HOURS = 24.0

# Verified against the literal strings each fetch module produces on a
# 429/rate-limit response — see this module's docstring, condition 3.
_RATE_LIMIT_MARKERS = ("429", "rate limit", "rate-limited", "ratelimited")


def _is_rate_limited_text(text: Optional[str]) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _RATE_LIMIT_MARKERS)


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class HealthReason:
    kind: str          # missing_integration | stale_webhook | rate_limited
    detail: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail}


@dataclass
class SystemHealth:
    status: str                                    # CLEAN | DEGRADED
    reasons: list[HealthReason] = field(default_factory=list)
    checked_at: str = ""

    def as_dict(self) -> dict:
        return {
            "system_health": self.status,
            "system_health_reasons": [r.as_dict() for r in self.reasons],
            "system_health_checked_at": self.checked_at,
        }


def _github_integration(conn, tenant_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT i.id, i.installed_at FROM integration i"
        " JOIN source s ON s.id = i.source_id AND s.tenant_id = i.tenant_id"
        " WHERE s.tenant_id = %s AND s.name = 'github' AND i.revoked_at IS NULL"
        " ORDER BY i.installed_at LIMIT 1",
        (tenant_id,),
    ).fetchone()
    return dict(row) if row else None


def _was_ever_connected(conn, tenant_id: str, source_name: str) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM integration i"
        " JOIN source s ON s.id = i.source_id AND s.tenant_id = i.tenant_id"
        " WHERE s.tenant_id = %s AND s.name = %s AND i.revoked_at IS NOT NULL",
        (tenant_id, source_name),
    ).fetchone()
    return bool(row and row["n"])


def missing_integration_coverage(conn, tenant_id: str) -> list[HealthReason]:
    """5.2, condition 1. Never flags an optional integration (jira/linear/
    slack) that was simply never connected — only GitHub's absence (always
    required) and any source that WAS connected and has since gone dark."""
    reasons: list[HealthReason] = []
    if _github_integration(conn, tenant_id) is None:
        reasons.append(HealthReason(
            "missing_integration",
            "no active GitHub integration — nothing can be ingested for this tenant",
        ))
    for name in ("jira", "linear", "slack"):
        if _was_ever_connected(conn, tenant_id, name):
            reasons.append(HealthReason(
                "missing_integration",
                f"{name} was connected for this tenant and has since been revoked",
            ))
    return reasons


def stale_webhook_state(conn, tenant_id: str, now: str,
                        stale_after_hours: float = STALE_WEBHOOK_HOURS) -> list[HealthReason]:
    """5.2, condition 2. Only meaningful when GitHub IS connected — an
    absent integration is already reported by
    `missing_integration_coverage` and must not be counted twice."""
    gh = _github_integration(conn, tenant_id)
    if gh is None:
        return []

    last_webhook = conn.execute(
        "SELECT MAX(received_at) AS at FROM webhook_delivery WHERE tenant_id = %s",
        (tenant_id,),
    ).fetchone()["at"]
    last_run = conn.execute(
        "SELECT MAX(finished_at) AS at FROM ingest_run"
        " WHERE tenant_id = %s AND status = 'succeeded'",
        (tenant_id,),
    ).fetchone()["at"]

    candidates = [d for d in (_parse_iso(last_webhook), _parse_iso(last_run)) if d is not None]
    now_dt = _parse_iso(now) or datetime.now(timezone.utc)
    if not candidates:
        return [HealthReason(
            "stale_webhook",
            "GitHub integration is installed but no webhook or successful ingest "
            "run has ever been recorded for this tenant",
        )]
    last_signal = max(candidates)
    age_hours = (now_dt - last_signal).total_seconds() / 3600.0
    if age_hours > stale_after_hours:
        return [HealthReason(
            "stale_webhook",
            f"no webhook or successful ingest run in {age_hours:.1f}h "
            f"(threshold {stale_after_hours:.0f}h); last signal at {last_signal.isoformat()}",
        )]
    return []


def rate_limited_run(conn, tenant_id: str, run_id: Optional[int]) -> list[HealthReason]:
    """5.2, condition 3. Reads the `error_detail` `ingest_worker.run_one()`
    already writes — no new column, no new table. `run_id=None` (no run to
    check yet) reports nothing; that is a "we have not run" state, not a
    rate-limit state, and conflating them would be exactly the kind of
    invented claim this project's tri-state rule exists to forbid."""
    if run_id is None:
        return []
    row = conn.execute(
        "SELECT error_detail FROM ingest_run WHERE tenant_id = %s AND id = %s",
        (tenant_id, run_id),
    ).fetchone()
    detail = row["error_detail"] if row else None
    if _is_rate_limited_text(detail):
        return [HealthReason("rate_limited", detail)]
    return []


def _latest_run_id(conn, tenant_id: str) -> Optional[int]:
    row = conn.execute(
        "SELECT id FROM ingest_run WHERE tenant_id = %s ORDER BY started_at DESC, id DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()
    return row["id"] if row else None


def compute_system_health(conn, tenant_id: str, now: str, *,
                          run_id: Optional[int] = None) -> SystemHealth:
    """The one function API callers use. `run_id`, if not given, defaults to
    the tenant's most recent `ingest_run` (matching what a lead means by
    "is the system healthy right now" when they haven't named a specific
    run) — used only for the rate-limit check; the other two conditions are
    tenant-wide by nature, not per-run."""
    if run_id is None:
        run_id = _latest_run_id(conn, tenant_id)

    reasons: list[HealthReason] = []
    reasons += missing_integration_coverage(conn, tenant_id)
    reasons += stale_webhook_state(conn, tenant_id, now)
    reasons += rate_limited_run(conn, tenant_id, run_id)

    status = DEGRADED if reasons else CLEAN
    return SystemHealth(status=status, reasons=reasons, checked_at=now)
