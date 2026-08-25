"""ARGUS Phase 7.4c-d — encryption for Jira credentials at rest (§3.1.4).

Jira has no App-install flow the way GitHub (a real App, an installation
access token minted live from a private key, D-133) or Slack (OAuth, D-143)
do — there is no equivalent "install" a pilot team clicks through. The real
credential (a site email + a Jira Cloud API token) has to be entered once by
an ARGUS admin during onboarding (§5 of the operational checklist) and
reused on every ingest run after that, which means it has to be *stored*,
unlike GitHub's installation token (minted fresh every hour, never
persisted) or even Slack's bot token (arrives over a redirect this service
controls end to end).

Rather than invent a second encryption scheme, this module is
`slack_crypto.py`'s exact AES-256-GCM-at-rest pattern (D-143), generalized:
same construction, same non-technical-owner-friendly key handling (any
string works — SHA-256 derives the real 32-byte key), same authenticated
encryption (a tampered or cross-tenant ciphertext fails to decrypt rather
than decrypting to something else). Kept as its own module with its own key
(`ARGUS_JIRA_CREDENTIAL_KEY`, config.py) rather than folding into
`slack_crypto.py` directly: Slack's module is proven, in production, and
depended on by every pilot workspace today — touching it for an unrelated
credential type is a real regression risk for zero benefit, when the whole
point of AEAD-with-a-derived-key is that it costs nothing to duplicate
safely. A future third credential type (Linear, 7.4c-e) should reuse
*this* module's functions directly rather than adding a third copy.

What is encrypted: the whole credential payload (email + API token) as one
JSON string, not split across columns — `integration.credential_ref` is a
single TEXT column (schema.sql §11's comment: "a POINTER... never the
secret itself"), so encrypting one JSON blob into it needs no schema
change, matching the "no new table" alternative §3.1.4 itself named.
`base_url` and `project_key` are NOT secret and are stored in the clear
elsewhere on the same `integration` row (`display_name`/`external_account_id`
respectively) so an admin can see which Jira site/project a credential
belongs to without decrypting anything.
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


class JiraCredentialKeyMissing(RuntimeError):
    """Raised when a Jira credential would be read or written with no key
    configured. Deliberately loud — the alternative (storing an email + API
    token in the clear) is a silent downgrade nobody would notice until a
    database dump made it a real problem."""


class JiraCredentialUndecryptable(RuntimeError):
    """The ciphertext did not authenticate: wrong key, wrong tenant, or the
    row was tampered with. Never retried, never worked around — same
    discipline as `slack_crypto.SlackTokenUndecryptable`."""


def _key() -> bytes:
    if not config.JIRA_CREDENTIAL_KEY:
        raise JiraCredentialKeyMissing(
            "ARGUS_JIRA_CREDENTIAL_KEY is not set — refusing to store or read a Jira "
            "credential. Set it in this host's environment and restart.")
    return hashlib.sha256(config.JIRA_CREDENTIAL_KEY.encode("utf-8")).digest()


def _aad(tenant_id: str) -> bytes:
    return f"argus:jira_credential:{tenant_id}".encode("utf-8")


def encrypt_credential(email: str, api_token: str, tenant_id: str) -> str:
    """Return `v1:<base64(nonce || ciphertext||tag)>` sealing
    `{"email": ..., "api_token": ...}` as JSON.

    A fresh random nonce per call — same reasoning as
    `slack_crypto.encrypt_token`: safe to re-encrypt (an admin rotating a
    tenant's Jira API token) without any nonce-reuse concern.
    """
    payload = json.dumps({"email": email, "api_token": api_token}).encode("utf-8")
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, payload, _aad(tenant_id))
    return _PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt_credential(stored: str, tenant_id: str) -> dict:
    """Returns `{"email": ..., "api_token": ...}`."""
    if not stored.startswith(_PREFIX):
        raise JiraCredentialUndecryptable(f"unrecognised ciphertext format: {stored[:8]!r}")
    try:
        blob = base64.b64decode(stored[len(_PREFIX):], validate=True)
    except (ValueError, TypeError) as exc:
        raise JiraCredentialUndecryptable("ciphertext is not valid base64") from exc
    if len(blob) <= _NONCE_BYTES:
        raise JiraCredentialUndecryptable("ciphertext too short to contain a nonce")
    try:
        opened = AESGCM(_key()).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:],
                                        _aad(tenant_id))
    except InvalidTag as exc:
        raise JiraCredentialUndecryptable(
            "Jira credential failed authentication — wrong ARGUS_JIRA_CREDENTIAL_KEY, or "
            "the row belongs to a different tenant than the one asking for it.") from exc
    try:
        return json.loads(opened.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JiraCredentialUndecryptable("decrypted payload is not valid JSON") from exc
