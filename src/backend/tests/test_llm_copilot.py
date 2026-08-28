"""Milestone 2, Task 6.1 — verification for llm_copilot.py (D-172).

No real call to `generativelanguage.googleapis.com` is made from this suite
(same standing rule as `live_github.py`/`live_jira.py`/`live_linear.py`'s
own tests — D-115 era: no route to a real network 3rd-party from the
sandboxes this project's CI-equivalent runs in, and no real
`ARGUS_LLM_API_KEY` exists in this environment regardless). `urllib.request.
urlopen` is monkeypatched at the point `_call_gemini` calls it, the same
"fake the transport, prove everything around it" convention
`test_slack_dispatcher.py`'s `FakeSlack` and `test_slack_app.py` already
use for Slack.
"""
import os
import sys

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(BACKEND))

from backend import llm_copilot  # noqa: E402


# ===========================================================================
# 1. Redaction (Task 1.2/1.3).
# ===========================================================================

def test_scrub_redacts_aws_key():
    assert "AKIAIOSFODNN7EXAMPLE" not in llm_copilot.scrub_sensitive_data(
        "here is a key AKIAIOSFODNN7EXAMPLE for you")


def test_scrub_redacts_github_pat():
    text = "auth with ghp_" + "a" * 36
    out = llm_copilot.scrub_sensitive_data(text)
    assert "ghp_" not in out
    assert "[redacted-github-token]" in out


def test_scrub_redacts_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out = llm_copilot.scrub_sensitive_data(f"token={jwt}")
    assert jwt not in out
    assert "[redacted-jwt]" in out


def test_scrub_redacts_bearer_token():
    out = llm_copilot.scrub_sensitive_data("Authorization: Bearer abcDEF123456789")
    assert "abcDEF123456789" not in out
    assert "[redacted-bearer-token]" in out


def test_scrub_redacts_dsn_with_inline_credentials():
    out = llm_copilot.scrub_sensitive_data(
        "connect via postgres://admin:sup3rSecret@db.internal:5432/argus")
    assert "sup3rSecret" not in out
    assert "[redacted-connection-string]" in out


def test_scrub_redacts_internal_staging_urls():
    out = llm_copilot.scrub_sensitive_data(
        "see https://deploy.staging.rocketco.internal/status for details")
    assert "staging.rocketco.internal" not in out
    assert "[internal-url]" in out


def test_scrub_redacts_private_ip_urls():
    out = llm_copilot.scrub_sensitive_data("check http://10.2.3.4:8080/health")
    assert "10.2.3.4" not in out
    assert "[internal-url]" in out


def test_scrub_redacts_emails():
    out = llm_copilot.scrub_sensitive_data("ping octocat@rocket.example about this")
    assert "octocat@rocket.example" not in out
    assert "[email]" in out


def test_scrub_leaves_ordinary_text_alone():
    text = "The PR is blocked on a Stripe webhook review from the payments team."
    assert llm_copilot.scrub_sensitive_data(text) == text


def test_scrub_truncates_very_long_fields():
    out = llm_copilot.scrub_sensitive_data("x" * 5000)
    assert len(out) < 5000
    assert out.endswith("[truncated]")


def test_strip_code_and_diffs_removes_fenced_code_block():
    text = "Here's the fix:\n```python\nAKIAIOSFODNN7EXAMPLE = 'oops'\n```\nplease review"
    out = llm_copilot.strip_code_and_diffs(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[code omitted]" in out
    assert "please review" in out


def test_strip_code_and_diffs_removes_diff_hunks():
    diff = (
        "diff --git a/x.py b/x.py\n"
        "index 1234567..89abcde 100644\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,3 +1,3 @@\n"
        "-old line\n"
        "+new line with a secret AKIAIOSFODNN7EXAMPLE\n"
    )
    out = llm_copilot.strip_code_and_diffs(diff)
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_generalize_names_swaps_known_author_and_reviewers():
    out = llm_copilot.generalize_names(
        "octocat opened this and asked hubot to review",
        author_login="octocat", reviewer_logins=["hubot"])
    assert "octocat" not in out
    assert "hubot" not in out
    assert "the author" in out
    assert "a reviewer" in out


def test_generalize_names_leaves_unknown_names_alone():
    """Documented limitation, not a bug: only logins the caller already
    knows the role of are generalized — see the function's own docstring."""
    out = llm_copilot.generalize_names("mentioned by someone else entirely",
                                       author_login="octocat")
    assert "someone else entirely" in out


def test_redact_pipeline_strips_diff_then_names_then_secrets():
    text = ("octocat pushed:\n```\nAKIAIOSFODNN7EXAMPLE\n```\n"
           "contact octocat@rocket.example for help")
    out = llm_copilot.redact(text, author_login="octocat")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "octocat@rocket.example" not in out
    assert "the author" in out


# ===========================================================================
# 2. Context assembly (Task 2.1) — redaction happens on the way in.
# ===========================================================================

def test_build_context_redacts_every_text_field():
    ctx = llm_copilot.build_context(
        item_key="rocket/api#42", pattern="P1-approved-unmerged",
        title="fix for octocat's bug", body="uses key AKIAIOSFODNN7EXAMPLE",
        comments=["octocat: still waiting", "```leaked = 'x'```"],
        ticket_keys=["ENG-101"], evidence="approved 52h ago",
        author_login="octocat")
    assert "AKIAIOSFODNN7EXAMPLE" not in ctx.body
    assert "octocat" not in ctx.title
    assert "leaked" not in ctx.comments[1]
    assert ctx.ticket_keys == ("ENG-101",)


def test_build_context_caps_comments_at_five():
    ctx = llm_copilot.build_context(
        item_key="rocket/api#1", pattern=None,
        comments=[f"comment {i}" for i in range(10)])
    assert len(ctx.comments) == 5
    assert ctx.comments[-1] == "comment 9"  # the most recent 5, kept in order


# ===========================================================================
# 3. Schema validation (Task 2.4/3.2).
# ===========================================================================

def _valid_response() -> dict:
    return {"summary_tldr": "Blocked on a Stripe webhook review; nothing else pending.",
            "blocking_dependency": "Stripe webhook approval",
            "action_draft": "Hey — mind taking a quick look, or should I reassign?",
            "suggested_recipient_role": "reviewer"}


def test_validate_schema_accepts_a_well_formed_response():
    result = llm_copilot._validate_schema(_valid_response())
    assert result.summary_tldr.startswith("Blocked on a Stripe webhook")
    assert result.suggested_recipient_role == "reviewer"


def test_validate_schema_accepts_null_blocking_dependency():
    data = _valid_response()
    data["blocking_dependency"] = None
    result = llm_copilot._validate_schema(data)
    assert result.blocking_dependency is None


@pytest.mark.parametrize("missing", ["summary_tldr", "action_draft", "suggested_recipient_role"])
def test_validate_schema_rejects_missing_required_field(missing):
    data = _valid_response()
    del data[missing]
    with pytest.raises(llm_copilot.CopilotUnavailable):
        llm_copilot._validate_schema(data)


def test_validate_schema_rejects_bad_recipient_role():
    data = _valid_response()
    data["suggested_recipient_role"] = "ceo"
    with pytest.raises(llm_copilot.CopilotUnavailable):
        llm_copilot._validate_schema(data)


def test_validate_schema_truncates_an_overlong_summary():
    data = _valid_response()
    data["summary_tldr"] = "x" * 300
    result = llm_copilot._validate_schema(data)
    assert len(result.summary_tldr) <= 240


def test_validate_schema_rejects_non_dict():
    with pytest.raises(llm_copilot.CopilotUnavailable):
        llm_copilot._validate_schema(["not", "a", "dict"])


# ===========================================================================
# 4. The Fail-Safe Fallback Invariant (Task 4.1/4.2) — `generate_enrichment`
#    must NEVER raise, and must return None for every failure mode.
# ===========================================================================

def _ctx() -> llm_copilot.CopilotContext:
    return llm_copilot.build_context(item_key="rocket/api#7", pattern="P2-review-ghosted",
                                     title="fix the thing", evidence="approved 52h ago")


def test_no_api_key_returns_none_without_a_network_call(monkeypatch):
    called = []
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    result = llm_copilot.generate_enrichment(_ctx(), api_key=None)
    assert result is None
    assert called == []


def test_unrecognized_provider_returns_none(monkeypatch):
    called = []
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        lambda *a, **k: called.append(1))
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key", provider="openai")
    assert result is None
    assert called == []


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen_returning(payload: dict):
    import json as _json

    def _urlopen(req, timeout=None):
        envelope = {"candidates": [{"content": {"parts": [
            {"text": _json.dumps(payload)}]}}]}
        return _FakeResponse(_json.dumps(envelope).encode("utf-8"))
    return _urlopen


def test_a_well_formed_gemini_response_produces_a_dict(monkeypatch):
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning(_valid_response()))
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is not None
    assert result["summary_tldr"] == _valid_response()["summary_tldr"]
    assert result["suggested_recipient_role"] == "reviewer"


def test_a_schema_invalid_gemini_response_falls_back_to_none(monkeypatch):
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning({"summary_tldr": "ok"}))  # missing fields
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is None


def test_a_network_error_falls_back_to_none(monkeypatch):
    import urllib.error

    def _raise(*a, **k):
        raise urllib.error.URLError("no route to host")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _raise)
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is None


def test_an_http_error_falls_back_to_none(monkeypatch):
    import io
    import urllib.error

    def _raise(*a, **k):
        raise urllib.error.HTTPError(
            "https://generativelanguage.googleapis.com/x", 429, "rate limited",
            hdrs=None, fp=io.BytesIO(b'{"error":{"message":"rate limited"}}'))
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _raise)
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is None


def test_a_timeout_falls_back_to_none(monkeypatch):
    def _raise(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _raise)
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key", timeout=3.0)
    assert result is None


def test_malformed_json_body_falls_back_to_none(monkeypatch):
    def _urlopen(req, timeout=None):
        return _FakeResponse(b"not json at all")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _urlopen)
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is None


def test_unexpected_exception_inside_the_call_still_falls_back_to_none(monkeypatch):
    """The broad `except Exception` in generate_enrichment: even a bug in
    THIS module's own code must not be the reason a real FIRE alert fails
    to reach anyone."""
    def _boom(req, timeout=None):
        raise RuntimeError("something this module's own author did not anticipate")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _boom)
    result = llm_copilot.generate_enrichment(_ctx(), api_key="fake-key")
    assert result is None


def test_the_request_body_never_carries_a_diff_or_a_secret(monkeypatch):
    """Task 1.3's own assertion, proven at the network boundary: build a
    context from unredacted-looking raw inputs the normal way (through
    `build_context`, which always redacts) and confirm the actual bytes
    handed to `urlopen` contain neither."""
    captured = {}

    def _urlopen(req, timeout=None):
        captured["body"] = req.data
        return _fake_urlopen_returning(_valid_response())(req, timeout)
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _urlopen)

    ctx = llm_copilot.build_context(
        item_key="rocket/api#9", pattern="P1-approved-unmerged",
        title="octocat's PR", body="```AKIAIOSFODNN7EXAMPLE = 1```",
        author_login="octocat")
    llm_copilot.generate_enrichment(ctx, api_key="fake-key")

    body_text = captured["body"].decode("utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in body_text
    assert "octocat" not in body_text
    assert "```" not in body_text


# ===========================================================================
# Phase 7.4X, Task 3.5 — the Executive Morning Briefing.
#
# The invariant this section exists to prove is stricter than the enrichment
# feature's: `generate_enrichment` may return None and let the caller render
# the raw alert, but a briefing has no raw form, so
# `generate_morning_briefing` must ALWAYS return a valid, schema-shaped dict.
# Every failure mode below therefore asserts a usable briefing came back, not
# merely that nothing was raised.
# ===========================================================================

_ROWS = [
    {"item_key": "rocket/api#41", "section": "blocked", "age_label": "3 days",
     "headline": "Legal has not countersigned the DPA amendment"},
    {"item_key": "rocket/api#42", "section": "escalation", "age_label": "6 days",
     "headline": "octocat has been away 6 days"},
    {"item_key": "rocket/api#43", "section": "awaiting", "age_label": "2 days",
     "headline": "waiting on a reply"},
]
_STATS = {"items_checked": 12, "fired": 3, "suppressed": 4, "abstained": 5}


def _valid_briefing() -> dict:
    return {
        "briefing_summary": "Two items need a decision this morning; the rest are moving.",
        "critical_blocks": ["rocket/api#41 — waiting on Legal"],
        "friction_items": ["rocket/api#43 — no reply for two days"],
        "healthy_count": 99,
    }


def _briefing_keys(b: dict) -> set:
    return {"briefing_summary", "critical_blocks", "friction_items", "healthy_count"} & set(b)


def test_briefing_without_an_api_key_is_the_deterministic_summary():
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="")
    assert b["source"] == "deterministic"
    assert b["briefing_summary"] == "2 critical blocks, 3 items in-flight"
    assert b["critical_blocks"] == ["rocket/api#41", "rocket/api#42"]
    assert b["friction_items"] == ["rocket/api#43"]
    assert b["healthy_count"] == 9          # 12 checked - 3 flagged


def test_briefing_with_an_unrecognized_provider_falls_back_without_a_call(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("no network call may be made for an unknown provider")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _boom)
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS,
                                              provider="openai", api_key="fake-key")
    assert b["source"] == "deterministic"


def test_briefing_on_a_quiet_morning_says_zero_rather_than_inventing_work():
    b = llm_copilot.generate_morning_briefing("t-1", [], {"items_checked": 7}, api_key="")
    assert b["briefing_summary"] == "0 critical blocks, 0 items in-flight"
    assert b["critical_blocks"] == [] and b["friction_items"] == []
    assert b["healthy_count"] == 7


def test_briefing_healthy_count_never_goes_negative_on_odd_inputs():
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, {"items_checked": 1}, api_key="")
    assert b["healthy_count"] == 0
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, None, api_key="")
    assert b["healthy_count"] == 0


def test_a_well_formed_briefing_response_is_used(monkeypatch):
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning(_valid_briefing()))
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="fake-key")
    assert b["source"] == "llm"
    assert b["briefing_summary"].startswith("Two items need a decision")
    assert b["critical_blocks"] == ["rocket/api#41 — waiting on Legal"]
    assert _briefing_keys(b) == {"briefing_summary", "critical_blocks",
                                 "friction_items", "healthy_count"}


def test_the_models_healthy_count_is_discarded_for_the_engines_own(monkeypatch):
    """A language model is the wrong instrument for arithmetic anyone can
    check. The model says 99; the engine counted 9; 9 is what a lead sees."""
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning(_valid_briefing()))
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="fake-key")
    assert b["healthy_count"] == 9


def test_briefing_list_fields_are_capped_at_five(monkeypatch):
    payload = dict(_valid_briefing(), critical_blocks=[f"item-{i}" for i in range(20)])
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning(payload))
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="fake-key")
    assert len(b["critical_blocks"]) == 5


@pytest.mark.parametrize("bad", [
    {"briefing_summary": "", "critical_blocks": [], "friction_items": [], "healthy_count": 1},
    {"critical_blocks": [], "friction_items": [], "healthy_count": 1},
    {"briefing_summary": "ok", "critical_blocks": "not a list",
     "friction_items": [], "healthy_count": 1},
    ["not", "an", "object"],
])
def test_a_schema_invalid_briefing_falls_back_to_the_deterministic_one(monkeypatch, bad):
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen",
                        _fake_urlopen_returning(bad))
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="fake-key")
    assert b["source"] == "deterministic"
    assert b["briefing_summary"] == "2 critical blocks, 3 items in-flight"


def test_a_briefing_timeout_falls_back_to_the_deterministic_summary(monkeypatch):
    """Task 3.3's own requirement, and the 3-second ceiling re-proven for
    this second call rather than inherited from the first."""
    def _slow(req, timeout=None):
        assert timeout == 3.0, f"the 3-second ceiling was not applied: {timeout}"
        raise TimeoutError("too slow")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _slow)
    b = llm_copilot.generate_morning_briefing("t-1", _ROWS, _STATS, api_key="fake-key")
    assert b["source"] == "deterministic"


def test_a_briefing_network_error_falls_back(monkeypatch):
    def _down(req, timeout=None):
        raise llm_copilot.urllib.error.URLError("no route to host")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _down)
    assert llm_copilot.generate_morning_briefing(
        "t-1", _ROWS, _STATS, api_key="fake-key")["source"] == "deterministic"


def test_a_briefing_http_error_falls_back(monkeypatch):
    import io as _io

    def _http(req, timeout=None):
        raise llm_copilot.urllib.error.HTTPError(
            "https://x", 429, "Too Many Requests", {}, _io.BytesIO(b'{"error":"quota"}'))
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _http)
    assert llm_copilot.generate_morning_briefing(
        "t-1", _ROWS, _STATS, api_key="fake-key")["source"] == "deterministic"


def test_an_unexpected_exception_in_the_briefing_path_still_falls_back(monkeypatch):
    def _weird(req, timeout=None):
        raise RuntimeError("something nobody anticipated")
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _weird)
    assert llm_copilot.generate_morning_briefing(
        "t-1", _ROWS, _STATS, api_key="fake-key")["source"] == "deterministic"


def test_the_briefing_prompt_carries_no_tenant_id_and_no_secrets(monkeypatch):
    """The briefing's own version of the redaction proof, at the network
    boundary. `tenant_id` identifies a paying customer and adds nothing to a
    summary of their own items, so it is never sent."""
    captured = {}

    def _urlopen(req, timeout=None):
        captured["body"] = req.data
        return _fake_urlopen_returning(_valid_briefing())(req, timeout)
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _urlopen)

    rows = _ROWS + [{"item_key": "rocket/api#44", "section": "awaiting",
                     "headline": "deploy blocked, token AKIAIOSFODNN7EXAMPLE expired"}]
    llm_copilot.generate_morning_briefing(
        "acme-secret-tenant-uuid", rows, _STATS, api_key="fake-key")

    body_text = captured["body"].decode("utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in body_text
    assert "acme-secret-tenant-uuid" not in body_text
    assert "rocket/api#41" in body_text        # the items themselves do go


def test_the_briefing_prompt_is_bounded_on_a_very_large_morning(monkeypatch):
    captured = {}

    def _urlopen(req, timeout=None):
        captured["body"] = req.data
        return _fake_urlopen_returning(_valid_briefing())(req, timeout)
    monkeypatch.setattr(llm_copilot.urllib.request, "urlopen", _urlopen)

    rows = [{"item_key": f"rocket/api#{i}", "section": "awaiting",
             "headline": "waiting"} for i in range(500)]
    llm_copilot.generate_morning_briefing("t-1", rows, {"items_checked": 500},
                                          api_key="fake-key")
    assert captured["body"].decode("utf-8").count("rocket/api#") <= 25
