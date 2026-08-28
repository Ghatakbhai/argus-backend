"""ARGUS Milestone 2 — the Disciplined LLM Copilot Layer (D-172).

WHAT THIS IS, AND WHAT IT IS NOT.

`docs/MILESTONE_2_DISCIPLINED_LLM_COPILOT.md` and
`docs/STRATEGIC_ALIGNMENT_PRE_7_5.md` name four non-negotiable invariants
this module exists to hold, in this order of importance:

  1. **Trigger Invariant.** This module is never consulted to decide
     FIRE vs SUPPRESSED — `sprint_filter.py` alone does that, unchanged,
     before this module is ever called. `generate_enrichment()` takes an
     already-decided FIRE alert's context and produces framing on top of
     it; it cannot veto or soften the underlying alert.
  2. **Privacy & Redaction Invariant.** `scrub_sensitive_data()` and
     `strip_code_and_diffs()` run on every piece of text before it is
     assembled into a prompt — tokens, keys, DSNs, internal URLs, emails,
     and (for the callers that know them) personal names, generalized into
     the role they played (`author`/`reviewer`). Nothing resembling a
     source diff or fenced code block is ever sent.
  3. **Fail-Safe Fallback Invariant.** `generate_enrichment()` never raises.
     A missing API key, a network failure, a timeout past the ceiling, a
     malformed or schema-invalid response — every one of these is caught,
     logged via `logger.warning()`, and answered with `None`. Every caller
     in this codebase treats `None` as "render the raw deterministic alert,
     exactly as before this module existed" — never as an error to surface
     to a person.
  4. **Scope Discipline.** Two features, one combined call: the
     TL;DR summary (`summary_tldr`/`blocking_dependency`) and the action
     draft (`action_draft`/`suggested_recipient_role`). Combined into one
     prompt/one schema/one API call deliberately — two separate calls per
     alert would double latency and cost for no product benefit, and this
     project's own `PATTERN_HEADLINE`/`PATTERN_ASK` dictionaries already
     show that a single short, structured call is enough for a stall
     pattern's worth of context.

     **Widened once, deliberately, at Phase 7.4X (Task 3):** a THIRD
     feature, `generate_morning_briefing()`, was added by Dirgh's explicit
     decision after `docs/PHASE7_4X_CLAUDE_ARCHITECTURE_REVIEW.md` §3 named
     this exact widening as something that must be decided rather than drift
     into place. It is a separate call with its own prompt, schema, timeout
     proof and fallback — it does NOT ride along on the two-feature call
     above, because a per-item enrichment and a per-digest summary have
     different inputs and different failure consequences. Section 6 carries
     the full reasoning. The invariant now reads: three features, two calls,
     each independently proven to fail closed — and any fourth is another
     decision, not another accretion.

**Provider: Google Gemini, model `gemini-3.7-flash` — locked in by Dirgh,
not Claude's own choice (see context/DECISIONS.md D-172).** Verified via
Google's own current API documentation during this session (not assumed
from training data, per this project's own D-111/D-121-established habit
of checking a live-integration model/endpoint name against current docs
before writing a caller for it) — `ai.google.dev/gemini-api/docs/models/
gemini-3.7-flash` names `gemini-3.7-flash` as the model id, and
`ai.google.dev/gemini-api/docs/generate-content/structured-output` documents
the REST shape used below (`x-goog-api-key` header, `generationConfig.
responseMimeType`/`responseSchema` for strict JSON output). Reachability of
`generativelanguage.googleapis.com` was confirmed live this session (a
deliberately-invalid probe key returns a structured `API_KEY_INVALID` JSON
error, not a connection failure) — but a REAL call, with a real
`ARGUS_LLM_API_KEY`, has not been made from this sandbox. Named plainly
rather than claimed: this module is proven against canned JSON shaped like
Gemini's own documented response envelope, the same standard `live_jira.py`/
`live_github.py` held themselves to before their own first live credential
existed (D-111 era).

**Why `urllib`, not `httpx` or the `google-generativeai` package.** Every
other live external call in this codebase — `live_github.py`, `live_jira.py`,
`live_linear.py` — is synchronous `urllib.request`, not `httpx` (which is
in `requirements.txt` only for FastAPI's own `TestClient`) and not async.
`ingest_worker.py`'s own module docstring says so explicitly: "none of it
`async`-native in this codebase." The Milestone 2 planning document's literal
`asyncio.wait_for(..., timeout=3.0)` would need an event loop nothing on
this call path has — `urlopen(req, timeout=3.0)` is the same 3-second
ceiling, achieved the way every sibling module in this project already
achieves one. Recorded as a correction, not a silent deviation, same
discipline D-169/D-170 hold themselves to. `google-generativeai` (offered
as the alternative in the kickoff message) is not added: one more dependency
for a single JSON POST this project's own `urllib` pattern already covers,
and the milestone message itself named REST as an acceptable alternative.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from . import config

logger = logging.getLogger("argus.llm_copilot")

GEMINI_MODEL = "gemini-3.7-flash"
GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
DEFAULT_TIMEOUT_SECONDS = 3.0
USER_AGENT = "ARGUS/Milestone2-Copilot (+internal tool, not published)"

# The two features' recipient-role vocabulary (Task 3.2's schema). Kept
# narrow and closed — an enum, not free text — so a caller can route on it
# without guessing what the model might have written instead.
RECIPIENT_ROLES = ("author", "reviewer", "lead")


# ===========================================================================
# 1. Redaction — Task 1.2/1.3. Runs on every string before it reaches a
#    prompt. Order matters: diffs/code stripped first (so a secret embedded
#    in a stripped code block never needs its own rule), then secrets, then
#    names, then a hard length cap as a last defensive line.
# ===========================================================================

# Fenced code blocks (``` ... ```, with or without a language tag) and
# unified-diff hunks (git's own header lines) — Task 1.3's "diffs and full
# file blobs are strictly stripped" requirement. A PR body that quotes a
# short code snippet for context loses the snippet, not the whole body —
# deliberately conservative (over-redacting a snippet is cheap; leaking a
# diff is not).
_FENCED_CODE_RE = re.compile(r"```.*?```", re.DOTALL)
# A diff BLOCK, not just its header lines: once `diff --git`/`index ..`/
# `--- `/`+++ `/an `@@ ... @@` hunk marker is seen, every following line that
# is itself diff-shaped (starts with `+`, `-`, or a context space) is part
# of the same hunk and must go too — the actual changed code, not just the
# headers around it, is exactly what Task 1.3 exists to keep out of a
# prompt. Stops at the first line that is NOT diff-shaped (a blank line, or
# prose resuming after the diff).
_DIFF_BLOCK_RE = re.compile(
    r"^(?:diff --git.*|index [0-9a-f]{4,}\.\.[0-9a-f]{4,}.*|--- .*|\+\+\+ .*|@@ .*@@.*)"
    r"(?:\n(?:diff --git.*|index [0-9a-f]{4,}\.\.[0-9a-f]{4,}.*|--- .*|\+\+\+ .*|"
    r"@@ .*@@.*|[+\- ].*))*",
    re.MULTILINE)

# --- Secret patterns (Task 1.2) --------------------------------------------
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9\-_.=]{8,}", re.IGNORECASE)
# Any connection-string-shaped secret carrying inline credentials —
# postgres://, mysql://, redis://, mongodb://, amqp://, etc. — not just DSN
# by name.
_DSN_RE = re.compile(r"\b[a-zA-Z][\w+.-]*://[^\s:/@]+:[^\s@]+@[^\s/]+")
# `(?!\[redacted)` keeps this generic sweep from re-matching (and
# relabeling) a value one of the specific patterns above already redacted —
# e.g. "token=[redacted-jwt]" must stay labeled as a JWT, not get swallowed
# into a second, less specific "[redacted-credential]" substitution.
_GENERIC_SECRET_RE = re.compile(
    r"\b(?:api[_-]?key|secret|token|password|passwd)\b\s*[:=]\s*(?!\[redacted)\S+",
    re.IGNORECASE)
# Internal/staging hosts — never sent even redacted-of-credentials, since the
# hostname itself is the sensitive part (D-security note: an internal
# hostname is infrastructure topology, not public product surface).
_INTERNAL_URL_RE = re.compile(
    r"\bhttps?://(?:[\w-]+\.)*(?:internal|staging|local|localhost|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})(?:[:/][^\s]*)?", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b")

_MAX_FIELD_CHARS = 2000  # a hard cap per text field, independent of secrets


def strip_code_and_diffs(text: str) -> str:
    """Task 1.3: source diffs and code blobs never reach a prompt. Applied
    before `scrub_sensitive_data()` so a secret sitting inside a stripped
    block never needs its own detection rule."""
    if not text:
        return text
    text = _FENCED_CODE_RE.sub("[code omitted]", text)
    text = _DIFF_BLOCK_RE.sub("[diff omitted]", text)
    return text


def scrub_sensitive_data(text: Optional[str]) -> str:
    """Task 1.2: regex redaction for tokens, keys, DSNs, internal URLs, and
    emails. Deliberately over-inclusive (a redacted false positive costs
    nothing; a missed real secret costs everything) — see each pattern's own
    comment for what it catches and why. Idempotent and safe to call on text
    that has already been scrubbed."""
    if not text:
        return ""
    text = _JWT_RE.sub("[redacted-jwt]", text)
    text = _GITHUB_TOKEN_RE.sub("[redacted-github-token]", text)
    text = _AWS_KEY_RE.sub("[redacted-aws-key]", text)
    text = _DSN_RE.sub("[redacted-connection-string]", text)
    text = _BEARER_RE.sub("[redacted-bearer-token]", text)
    text = _GENERIC_SECRET_RE.sub("[redacted-credential]", text)
    text = _INTERNAL_URL_RE.sub("[internal-url]", text)
    text = _EMAIL_RE.sub("[email]", text)
    if len(text) > _MAX_FIELD_CHARS:
        text = text[:_MAX_FIELD_CHARS] + " …[truncated]"
    return text


def generalize_names(text: str, *, author_login: Optional[str] = None,
                     reviewer_logins: Optional[list[str]] = None) -> str:
    """Task "Redaction... generalize personal names into roles
    (author/reviewer)". A general named-entity redactor is out of scope for
    a deterministic-precision project (this codebase's own standing rule,
    D-toward-precision-over-recall throughout Phase 3-5) — instead, the
    ONLY names generalized are the ones the caller already knows the role
    of, from the alert itself (`alert.subject_actor_id`'s login, the PR's
    reviewers), the same closed-world discipline `PATTERN_HEADLINE`/
    `PATTERN_ASK` already use. A name nobody told this function about is
    left as-is — better an occasional real name in a redacted-of-secrets
    prompt than a false promise of full anonymization this function cannot
    actually deliver."""
    if author_login:
        text = re.sub(re.escape(author_login), "the author", text, flags=re.IGNORECASE)
    for login in (reviewer_logins or []):
        if login:
            text = re.sub(re.escape(login), "a reviewer", text, flags=re.IGNORECASE)
    return text


def redact(text: Optional[str], *, author_login: Optional[str] = None,
          reviewer_logins: Optional[list[str]] = None) -> str:
    """The full pipeline, in order: strip code/diffs, generalize known
    names, scrub secrets/PII. Names run before the secret scrub because a
    login that also looks like part of an email local-part should still be
    caught by `_EMAIL_RE` afterward if `generalize_names` did not already
    remove it (e.g. a name mentioned without the matching email present)."""
    text = strip_code_and_diffs(text or "")
    text = generalize_names(text, author_login=author_login, reviewer_logins=reviewer_logins)
    return scrub_sensitive_data(text)


# ===========================================================================
# 2. Context assembly — Task 2.1.
# ===========================================================================

@dataclass
class CopilotContext:
    """Everything `_build_prompt()` needs, already redacted by the caller's
    use of `redact()` on each field — this dataclass does not itself scrub,
    so a caller cannot forget by construction (`build_context()` below is
    the one path that fills it, and it always redacts)."""
    item_key: str
    pattern: Optional[str]
    title: str = ""
    body: str = ""
    comments: tuple[str, ...] = ()
    ticket_keys: tuple[str, ...] = ()
    evidence: str = ""


def build_context(*, item_key: str, pattern: Optional[str], title: str = "",
                  body: str = "", comments: Optional[list[str]] = None,
                  ticket_keys: Optional[list[str]] = None, evidence: str = "",
                  author_login: Optional[str] = None,
                  reviewer_logins: Optional[list[str]] = None) -> CopilotContext:
    """Task 2.1: assembles PR title/description, recent review comments, and
    linked ticket keys into a `CopilotContext`, redacting every text field
    on the way in. `comments` should already be the caller's own "recent
    3-5" slice (this function does not itself decide how many — see
    `dashboard_payload.py`'s call site for that policy) — capped at 5 here
    defensively regardless, so a caller's off-by-one never balloons a
    prompt's cost.

    Note on "linked Jira/Linear ticket description" (the milestone doc's own
    words): `ticket` (schema_pg.sql) has never had a description column —
    only `title`. Ticket KEYS are passed through instead; the model is told
    plainly in the prompt that only keys, not ticket bodies, are available.
    Same class of correction as D-169's CI-status-column finding: the
    document names data this schema does not carry, corrected here rather
    than invented.
    """
    return CopilotContext(
        item_key=item_key, pattern=pattern,
        title=redact(title, author_login=author_login, reviewer_logins=reviewer_logins),
        body=redact(body, author_login=author_login, reviewer_logins=reviewer_logins),
        comments=tuple(
            redact(c, author_login=author_login, reviewer_logins=reviewer_logins)
            for c in (comments or [])[-5:]),
        ticket_keys=tuple(ticket_keys or []),
        evidence=redact(evidence, author_login=author_login, reviewer_logins=reviewer_logins),
    )


# ===========================================================================
# 3. Prompt + JSON schema — Tasks 2.2/2.3/3.2/3.3, combined into one call
#    per the Scope Discipline note in this module's own docstring.
# ===========================================================================

_SYSTEM_PROMPT = """You are a calm, precise engineering-operations assistant. \
A deterministic rule engine has ALREADY decided this item is stuck — you are \
never asked whether it is stuck, only to explain it plainly and draft a \
polite next step. Never blame an individual developer; describe the \
situation, not a person's failing. Keep the summary to two sentences and \
under 240 characters. If you cannot tell what is blocking progress from the \
context given, say so honestly in blocking_dependency rather than guessing. \
The action draft should read as one person writing a short, friendly Slack \
message to a colleague — not corporate, not passive-aggressive."""

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary_tldr": {
            "type": "string",
            "description": "A 2-sentence, plain-English, blame-free root-cause "
                           "summary, at most 240 characters.",
        },
        "blocking_dependency": {
            "type": ["string", "null"],
            "description": "The specific thing progress is waiting on, or null "
                           "if none is identifiable from the context given.",
        },
        "action_draft": {
            "type": "string",
            "description": "A short, polite, contextual Slack message a lead "
                           "could send as-is to nudge this forward.",
        },
        "suggested_recipient_role": {
            "type": "string",
            "enum": list(RECIPIENT_ROLES),
            "description": "Who the action_draft is addressed to.",
        },
    },
    "required": ["summary_tldr", "action_draft", "suggested_recipient_role"],
}


def _build_prompt(ctx: CopilotContext) -> str:
    lines = [
        f"Item: {ctx.item_key}" + (f" (pattern: {ctx.pattern})" if ctx.pattern else ""),
        f"Title: {ctx.title}" if ctx.title else "Title: (none given)",
    ]
    if ctx.body:
        lines.append(f"Description: {ctx.body}")
    if ctx.evidence:
        lines.append(f"Why the rule engine flagged it (verbatim, already decided, "
                     f"not yours to second-guess): {ctx.evidence}")
    if ctx.comments:
        lines.append("Recent comments, oldest first:")
        lines.extend(f"  - {c}" for c in ctx.comments)
    if ctx.ticket_keys:
        # See build_context()'s own docstring: keys only, no ticket body text
        # exists in this schema to pass along.
        lines.append(f"Linked ticket(s) (keys only, no description available): "
                     f"{', '.join(ctx.ticket_keys)}")
    else:
        lines.append("No linked ticket.")
    return "\n".join(lines)


@dataclass
class CopilotResult:
    summary_tldr: str
    action_draft: str
    suggested_recipient_role: str
    blocking_dependency: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "summary_tldr": self.summary_tldr,
            "blocking_dependency": self.blocking_dependency,
            "action_draft": self.action_draft,
            "suggested_recipient_role": self.suggested_recipient_role,
        }


class CopilotUnavailable(RuntimeError):
    """Internal-only — raised by the pieces below and always caught inside
    `generate_enrichment()` itself (Fail-Safe Fallback Invariant). Never
    escapes this module; exists so the many distinct failure points below
    can share one catch site instead of duplicating logging at each one."""


def _validate_schema(data: dict) -> CopilotResult:
    if not isinstance(data, dict):
        raise CopilotUnavailable(f"response was not a JSON object: {type(data).__name__}")
    for key in ("summary_tldr", "action_draft", "suggested_recipient_role"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise CopilotUnavailable(f"missing/empty required field: {key}")
    role = data["suggested_recipient_role"]
    if role not in RECIPIENT_ROLES:
        raise CopilotUnavailable(f"suggested_recipient_role {role!r} not in {RECIPIENT_ROLES}")
    summary = data["summary_tldr"].strip()
    if len(summary) > 240:
        summary = summary[:237] + "..."
    blocking = data.get("blocking_dependency")
    if blocking is not None and not isinstance(blocking, str):
        raise CopilotUnavailable("blocking_dependency was present but not a string/null")
    return CopilotResult(summary_tldr=summary, action_draft=data["action_draft"].strip(),
                         suggested_recipient_role=role,
                         blocking_dependency=(blocking.strip() if blocking else None))


# ===========================================================================
# 4. The Gemini call itself — Task 1.1/4.1.
# ===========================================================================

def _call_gemini(prompt: str, *, api_key: str, timeout: float) -> dict:
    """One blocking HTTPS POST, timeout-bounded by `urlopen`'s own `timeout`
    kwarg (see module docstring for why this is `urllib`, not `asyncio.
    wait_for`). Raises `CopilotUnavailable` on ANY failure — network,
    non-2xx, or a response that doesn't parse as the expected envelope —
    which `generate_enrichment()` below is the only place that catches."""
    # Phase 7.4X: the transport itself now lives in `_call_gemini_json`
    # (section 6), shared with the morning briefing. This function is that
    # one with the enrichment feature's prompt and schema bound in — so a
    # future change to timeout handling, error translation or envelope
    # parsing cannot fix one feature and miss the other.
    return _call_gemini_json(prompt, system_prompt=_SYSTEM_PROMPT,
                             schema=_RESPONSE_SCHEMA, api_key=api_key,
                             timeout=timeout, max_tokens=512)


# ===========================================================================
# 5. The entry point — Task 4.2. The only function anything outside this
#    module should call.
# ===========================================================================

def generate_enrichment(ctx: CopilotContext, *, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                        provider: Optional[str] = None,
                        api_key: Optional[str] = None) -> Optional[dict]:
    """Task 4.1/4.2: the strict timeout ceiling and graceful fallback in one
    place. Returns a plain dict (`CopilotResult.as_dict()`'s shape) ready to
    embed as `payload_json["copilot"]`/a digest row's `copilot` field, or
    `None` if enrichment could not be produced for ANY reason — no API key
    configured, an unrecognized provider, a network failure, a timeout, or a
    response that failed schema validation. `None` is not an error state to
    a caller: every caller in this codebase renders the raw deterministic
    alert when this returns `None`, exactly as it always has.

    `provider`/`api_key` default to `config.LLM_PROVIDER`/`config.
    LLM_API_KEY` — parameters exist so tests can inject both without
    touching process environment (this project's standing convention: every
    external call site takes its credential as an argument, never reaches
    into `os.environ` itself below `config.py`).
    """
    provider = provider or config.LLM_PROVIDER
    api_key = api_key if api_key is not None else config.LLM_API_KEY

    if not api_key:
        logger.warning("llm_copilot: no ARGUS_LLM_API_KEY configured; skipping "
                       "enrichment for %s (raw alert will be used)", ctx.item_key)
        return None
    if provider != "google":
        logger.warning("llm_copilot: unrecognized ARGUS_LLM_PROVIDER %r for %s; "
                       "only 'google' is implemented, skipping enrichment",
                       provider, ctx.item_key)
        return None

    started = time.monotonic()
    try:
        prompt = _build_prompt(ctx)
        raw = _call_gemini(prompt, api_key=api_key, timeout=timeout)
        result = _validate_schema(raw)
        return result.as_dict()
    except CopilotUnavailable as exc:
        logger.warning("llm_copilot: enrichment failed for %s after %.2fs: %s "
                       "(falling back to raw alert)",
                       ctx.item_key, time.monotonic() - started, exc)
        return None
    except Exception as exc:  # noqa: BLE001 — the Fail-Safe Fallback Invariant
        # is absolute: an enrichment feature must never be the reason a real
        # stall alert fails to reach anyone, for ANY reason, including bugs
        # in this module itself.
        logger.warning("llm_copilot: unexpected error enriching %s after %.2fs: "
                       "%s: %s (falling back to raw alert)",
                       ctx.item_key, time.monotonic() - started, type(exc).__name__, exc)
        return None


# ===========================================================================
# 6. The Executive Morning Briefing — Phase 7.4X, Task 3.
#
# THIS IS THE THIRD LLM FEATURE, AND THAT IS A DELIBERATE WIDENING OF THIS
# MODULE'S OWN SCOPE DISCIPLINE INVARIANT.
#
# The docstring at the top of this file says "Exactly two features, one
# combined call," and `docs/PHASE7_4X_CLAUDE_ARCHITECTURE_REVIEW.md` §3 named
# this feature specifically as something that "widens an invariant you
# deliberately wrote narrow one session ago" and should therefore be "a
# deliberate, named decision rather than something that happens by
# accretion." Dirgh made that decision (Phase 7.4X kickoff, Task 3). It is
# named here, at the code, so a future reader does not find a third feature
# sitting under a docstring that forbids one.
#
# What is NOT widened, and is re-proven for this call independently rather
# than inherited from `generate_enrichment`:
#
#   * The 3-second ceiling. Its own `urlopen(timeout=...)`, its own tests.
#   * The Fail-Safe Fallback. Stricter here than for enrichment, in fact:
#     `generate_enrichment` returns None and the caller renders the raw
#     alert, but a briefing has no raw form to fall back to, so this function
#     ALWAYS returns a valid, schema-shaped dict — the deterministic one when
#     the model is unavailable for any reason.
#   * The Trigger Invariant. This reads a digest that `sprint_filter.py` has
#     already decided in full. It cannot promote, demote, or silence a row.
#   * Redaction. Every string reaching the prompt goes through `redact()`.
#
# WHY `healthy_count` IS NEVER THE MODEL'S ANSWER
# -----------------------------------------------
# It is in the response schema because Task 3.2 puts it there, and the model
# is asked for it so the schema the API validates against matches the
# document. The value RETURNED, though, is always the one computed here from
# the counts the engine produced. A language model is the wrong instrument
# for arithmetic anyone can check, and this project has spent five phases on
# the principle that a number in front of a human should be traceable to a
# row. A disagreement between the two is logged, not silently preferred
# either way.
# ===========================================================================

# digest.py's SECTION_TONE marks exactly these two sections 'urgent'. Named
# as a literal here rather than imported: this module deliberately depends on
# nothing but `config` (see the import block above), and pulling `digest` —
# which itself pulls `presence`, `slack_triage` and `sprint_filter` — into a
# backend module for two strings would be a much bigger coupling than the
# duplication costs. If digest.py's tone map ever changes, this is the line
# that has to change with it.
CRITICAL_SECTIONS = ("blocked", "escalation")

_BRIEFING_SYSTEM_PROMPT = """You are writing the first thing an engineering \
lead reads in the morning. A deterministic rule engine has already decided \
which items are stuck and why — you are never asked to re-judge that, only to \
say plainly what today looks like. One short paragraph, at most four \
sentences, no preamble, no headings, no bullet characters. Name situations, \
never blame people. If the day is quiet, say so in one sentence rather than \
inflating it. critical_blocks and friction_items must each be short phrases \
drawn only from the items listed — never invented, never more than five \
entries."""

_BRIEFING_SCHEMA = {
    "type": "object",
    "properties": {
        "briefing_summary": {
            "type": "string",
            "description": "One paragraph, at most four sentences, on the state "
                           "of the team's in-flight work this morning.",
        },
        "critical_blocks": {
            "type": "array", "items": {"type": "string"},
            "description": "Short phrases naming the items that need a decision "
                           "today. At most 5. Drawn only from the items given.",
        },
        "friction_items": {
            "type": "array", "items": {"type": "string"},
            "description": "Short phrases naming slow-but-not-critical items. "
                           "At most 5. Drawn only from the items given.",
        },
        "healthy_count": {
            "type": "integer",
            "description": "How many checked items are not flagged at all.",
        },
    },
    "required": ["briefing_summary", "critical_blocks", "friction_items", "healthy_count"],
}

_MAX_BRIEFING_ROWS = 25     # a prompt cost ceiling, not a product rule
_MAX_LIST_ENTRIES = 5


def _briefing_counts(active_rows: list, stats: Optional[dict]) -> tuple:
    """(critical_count, total_count, healthy_count) — all three deterministic.

    `total_count` is the number of flagged rows in front of the lead, not
    `items_checked`: "12 items in-flight" meaning "we looked at 12" would be
    read by every human as "12 things are wrong", and the fallback line is
    the one that renders when nothing else can.
    """
    stats = stats or {}
    critical = sum(1 for r in active_rows if (r or {}).get("section") in CRITICAL_SECTIONS)
    total = len(active_rows)
    checked = stats.get("items_checked")
    healthy = max(int(checked) - total, 0) if isinstance(checked, int) else 0
    return critical, total, healthy


def _fallback_briefing(active_rows: list, stats: Optional[dict]) -> dict:
    """Task 3.3's deterministic summary. Not an error state and never
    rendered as one: this is what the dashboard shows whenever no API key is
    configured, which is the ordinary, supported way to run ARGUS."""
    critical, total, healthy = _briefing_counts(active_rows, stats)
    return {
        "briefing_summary": f"{critical} critical blocks, {total} items in-flight",
        "critical_blocks": [r["item_key"] for r in active_rows
                            if (r or {}).get("section") in CRITICAL_SECTIONS
                            and r.get("item_key")][:_MAX_LIST_ENTRIES],
        "friction_items": [r["item_key"] for r in active_rows
                           if (r or {}).get("section") not in CRITICAL_SECTIONS
                           and r.get("item_key")][:_MAX_LIST_ENTRIES],
        "healthy_count": healthy,
        "source": "deterministic",
    }


def _build_briefing_prompt(active_rows: list, stats: Optional[dict]) -> str:
    critical, total, healthy = _briefing_counts(active_rows, stats)
    lines = [
        f"Flagged items this morning: {total} ({critical} in an urgent section). "
        f"Items checked and not flagged: {healthy}.",
        "",
        "The flagged items, one per line:",
    ]
    if not active_rows:
        lines.append("  (none — nothing was flagged this morning)")
    for r in active_rows[:_MAX_BRIEFING_ROWS]:
        r = r or {}
        bits = [str(r.get("item_key") or "unknown item")]
        if r.get("section"):
            bits.append(f"[{r['section']}]")
        if r.get("age_label"):
            bits.append(f"({r['age_label']} old)")
        headline = redact(r.get("headline") or r.get("title") or "")
        if headline:
            bits.append(f"— {headline}")
        lines.append("  " + " ".join(bits))
    return "\n".join(lines)


def _call_gemini_json(prompt: str, *, system_prompt: str, schema: dict,
                      api_key: str, timeout: float, max_tokens: int = 512) -> dict:
    """`_call_gemini`'s body, with the prompt/schema lifted out as arguments
    so the two features share one transport, one set of error translations
    and one timeout mechanism rather than growing a second copy that could
    drift. `_call_gemini` below is now this function with the enrichment
    feature's own prompt and schema bound in."""
    url = GEMINI_ENDPOINT.format(model=GEMINI_MODEL)
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "temperature": 0.2,
            "maxOutputTokens": max_tokens,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key,
                 "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise CopilotUnavailable(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CopilotUnavailable(f"network error: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CopilotUnavailable(f"timed out after {timeout}s") from exc

    try:
        envelope = json.loads(raw)
        text = envelope["candidates"][0]["content"]["parts"][0]["text"]
        return json.loads(text)
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise CopilotUnavailable(f"could not parse Gemini response envelope: {exc}") from exc


def _validate_briefing(data: dict, *, healthy_count: int, item_key: str) -> dict:
    """Task 3.2's schema contract, enforced on our side of the wire.

    `responseSchema` is a request to the API, not a guarantee about what
    comes back — the same reason `_validate_schema` exists for the enrichment
    feature. Every field is re-checked here."""
    if not isinstance(data, dict):
        raise CopilotUnavailable(f"briefing was not a JSON object: {type(data).__name__}")
    summary = data.get("briefing_summary")
    if not isinstance(summary, str) or not summary.strip():
        raise CopilotUnavailable("missing/empty briefing_summary")

    def _string_list(name: str) -> list:
        val = data.get(name)
        if val is None:
            return []
        if not isinstance(val, list):
            raise CopilotUnavailable(f"{name} was present but not a list")
        out = [v.strip() for v in val if isinstance(v, str) and v.strip()]
        return out[:_MAX_LIST_ENTRIES]

    model_healthy = data.get("healthy_count")
    if isinstance(model_healthy, int) and model_healthy != healthy_count:
        # Logged, not obeyed and not silently dropped — see this section's
        # header for why the deterministic figure wins.
        logger.warning("llm_copilot: briefing for %s returned healthy_count=%s; "
                       "using the engine's own %s instead",
                       item_key, model_healthy, healthy_count)
    return {
        "briefing_summary": summary.strip(),
        "critical_blocks": _string_list("critical_blocks"),
        "friction_items": _string_list("friction_items"),
        "healthy_count": healthy_count,
        "source": "llm",
    }


def generate_morning_briefing(tenant_id, active_rows: Optional[list] = None,
                              stats: Optional[dict] = None, *,
                              timeout: float = DEFAULT_TIMEOUT_SECONDS,
                              provider: Optional[str] = None,
                              api_key: Optional[str] = None) -> dict:
    """Phase 7.4X Task 3.1: the 10-second executive standup briefing.

    ALWAYS returns a dict carrying all four of Task 3.2's fields plus a
    `source` key (`"llm"` or `"deterministic"`) saying which path produced
    it. Never returns None, never raises — a lead opening the dashboard must
    see a briefing whether or not a language model was reachable, and a
    dashboard that can tell the two apart is a dashboard that cannot quietly
    present a canned count as a written summary.

    `tenant_id` is used for logging only. It is deliberately NOT sent to the
    model: it identifies a paying customer and adds nothing to a summary of
    their own items.
    """
    active_rows = list(active_rows or [])
    provider = provider or config.LLM_PROVIDER
    api_key = api_key if api_key is not None else config.LLM_API_KEY
    label = f"tenant {tenant_id}"

    if not api_key:
        logger.info("llm_copilot: no ARGUS_LLM_API_KEY configured; %s gets the "
                    "deterministic morning briefing", label)
        return _fallback_briefing(active_rows, stats)
    if provider != "google":
        logger.warning("llm_copilot: unrecognized ARGUS_LLM_PROVIDER %r for %s; "
                       "deterministic morning briefing", provider, label)
        return _fallback_briefing(active_rows, stats)

    _c, _t, healthy = _briefing_counts(active_rows, stats)
    started = time.monotonic()
    try:
        raw = _call_gemini_json(
            _build_briefing_prompt(active_rows, stats),
            system_prompt=_BRIEFING_SYSTEM_PROMPT, schema=_BRIEFING_SCHEMA,
            api_key=api_key, timeout=timeout, max_tokens=768)
        return _validate_briefing(raw, healthy_count=healthy, item_key=label)
    except CopilotUnavailable as exc:
        logger.warning("llm_copilot: morning briefing failed for %s after %.2fs: %s "
                       "(falling back to the deterministic summary)",
                       label, time.monotonic() - started, exc)
        return _fallback_briefing(active_rows, stats)
    except Exception as exc:  # noqa: BLE001 — same absolute rule as above.
        logger.warning("llm_copilot: unexpected error building the morning briefing "
                       "for %s after %.2fs: %s: %s (falling back)",
                       label, time.monotonic() - started, type(exc).__name__, exc)
        return _fallback_briefing(active_rows, stats)
