"""ARGUS Phase 7.1 — API keys.

A key is shown to a pilot team exactly once, at creation. What the database
keeps is a SHA-256 of it plus a non-secret prefix used for lookup, so a dump of
`tenant_api_key` yields nothing usable. The app role cannot read that table at
all; it goes through the SECURITY DEFINER resolver.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from . import config

KEY_NAMESPACE = "argus_sk_"


def now_iso() -> str:
    """ISO-8601 UTC, matching the string format every timestamp in ARGUS uses."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_key() -> tuple[str, str, str]:
    """Return (plaintext, prefix, sha256-hex). The plaintext is never stored."""
    plaintext = KEY_NAMESPACE + secrets.token_urlsafe(32)
    return plaintext, plaintext[: config.KEY_PREFIX_LEN], hash_key(plaintext)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    key_id: str
    slug: str
    status: str
    shadow_until: str | None

    @property
    def may_send_dms(self) -> bool:
        """Shadow Mode (step 7.6) is enforced here, once, rather than trusted to
        every future call site to remember."""
        return self.status == "live"
