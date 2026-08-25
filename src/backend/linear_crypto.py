"""ARGUS Phase 7.4c-e — encryption for Linear credentials at rest (§3.1.4).

Like Jira (D-164), Linear has no App-install flow the way GitHub/Slack do —
an ARGUS admin enters a pilot's credential by hand during onboarding, once,
and it is reused on every ingest run after that, which means it has to be
stored.

Same AES-256-GCM-at-rest construction as `slack_crypto.py` (D-143) and
`jira_crypto.py` (D-164): any string works as the key (SHA-256 derives the
real 32-byte AES key), same authenticated encryption (a tampered or
cross-tenant ciphertext fails to decrypt rather than decrypting to
something else).

**Own module, own key (`ARGUS_LINEAR_CREDENTIAL_KEY`), not a literal reuse
of `jira_crypto`'s functions or its `ARGUS_JIRA_CREDENTIAL_KEY`** — despite
`jira_crypto.py`'s own docstring floating that as one option for "a future
third credential type." Decided against it this session, for the same
reason `jira_crypto.py` itself gave for NOT folding into `slack_crypto.py`
directly: rotating one integration's key must never require touching, or
risk regressing, an unrelated one's — `config.py`'s own comment on
`SLACK_TOKEN_KEY` states this as a standing rule, not a Slack-specific one.
Sharing `ARGUS_JIRA_CREDENTIAL_KEY` for Linear too would mean a Jira key
rotation silently re-keys (and locks out) every pilot's Linear credential
at the same time — a real coupling with no offsetting benefit, since
AEAD-with-a-derived-key costs nothing to duplicate safely (`jira_crypto.
py`'s own words, applied here a second time). Recorded as this session's
own call — D-16x — open to Dirgh's override if he'd rather the literal
reuse `jira_crypto.py` suggested.

What is encrypted: just the API key, as `{"api_key": ...}` JSON — Linear
credentials are a single secret, not an email+token pair the way Jira's
are, so the payload shape is simpler than `jira_crypto`'s. `team_key` is
not secret and is stored in the clear on the same `integration` row
(`external_account_id`), matching `jira_crypto.py`'s treatment of
`project_key`. Linear has no per-tenant `base_url` to store either — one
global API endpoint for every workspace (`https://api.linear.app`, already
seeded once per tenant into `source.base_url` by
`argus_seed_tenant_sources`, roles.sql) — so unlike Jira's credential
endpoint, Linear's admin endpoint (`app.py`) needs no `base_url` field at
all.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

KEY_VERSION = 1
_PREFIX = "v1:"
_NONCE_BYTES = 12


class LinearCredentialKeyMissing(RuntimeError):
    """Raised when a Linear credential would be read or written with no key
    configured. Deliberately loud — the alternative (storing an API key in
    the clear) is a silent downgrade nobody would notice until a database
    dump made it a real problem."""


class LinearCredentialUndecryptable(RuntimeError):
    """The ciphertext did not authenticate: wrong key, wrong tenant, or the
    row was tampered with. Never retried, never worked around — same
    discipline as `jira_crypto.JiraCredentialUndecryptable`."""


def _key() -> bytes:
    if not config.LINEAR_CREDENTIAL_KEY:
        raise LinearCredentialKeyMissing(
            "ARGUS_LINEAR_CREDENTIAL_KEY is not set — refusing to store or read a Linear "
            "credential. Set it in this host's environment and restart.")
    return hashlib.sha256(config.LINEAR_CREDENTIAL_KEY.encode("utf-8")).digest()


def _aad(tenant_id: str) -> bytes:
    return f"argus:linear_credential:{tenant_id}".encode("utf-8")


def encrypt_credential(api_key: str, tenant_id: str) -> str:
    """Return `v1:<base64(nonce || ciphertext||tag)>` sealing
    `{"api_key": ...}` as JSON. A fresh random nonce per call — safe to
    re-encrypt (an admin rotating a tenant's Linear API key) without any
    nonce-reuse concern."""
    payload = json.dumps({"api_key": api_key}).encode("utf-8")
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, payload, _aad(tenant_id))
    return _PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt_credential(stored: str, tenant_id: str) -> dict:
    """Returns `{"api_key": ...}`."""
    if not stored.startswith(_PREFIX):
        raise LinearCredentialUndecryptable(f"unrecognised ciphertext format: {stored[:8]!r}")
    try:
        blob = base64.b64decode(stored[len(_PREFIX):], validate=True)
    except (ValueError, TypeError) as exc:
        raise LinearCredentialUndecryptable("ciphertext is not valid base64") from exc
    if len(blob) <= _NONCE_BYTES:
        raise LinearCredentialUndecryptable("ciphertext too short to contain a nonce")
    try:
        opened = AESGCM(_key()).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:],
                                        _aad(tenant_id))
    except InvalidTag as exc:
        raise LinearCredentialUndecryptable(
            "Linear credential failed authentication — wrong ARGUS_LINEAR_CREDENTIAL_KEY, or "
            "the row belongs to a different tenant than the one asking for it.") from exc
    try:
        return json.loads(opened.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LinearCredentialUndecryptable("decrypted payload is not valid JSON") from exc
