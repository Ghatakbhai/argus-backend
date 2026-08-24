"""ARGUS Phase 7.3 — encryption for workspace bot tokens at rest (D-143).

Phase 6 stored one Slack bot token in a file on Dirgh's laptop and kept a
POINTER to it in the database (`integration.credential_ref`), following the
rule D-087 set: the database holds references, never secrets. With fifteen
pilot workspaces there is no laptop and no file — each workspace's token
arrives over OAuth on a server and has to be persisted there.

So the rule is kept in a different way. The token is encrypted with
AES-256-GCM before it is written, and the key exists only in this host's
environment (`ARGUS_SLACK_TOKEN_KEY`). A stolen database dump — the realistic
failure this defends against, and the one a managed Postgres with a public IP
makes newly plausible — yields ciphertext and no key.

What this deliberately does NOT claim: it is not protection against a
compromise of the running process, which by definition holds the key. That
attacker already has the tokens of whatever tenants the process was serving.
The isolation model (D-125/D-130) is what bounds that blast radius; this is
the layer beneath it, not a replacement for it.

AES-GCM rather than a plain cipher because it is authenticated: a ciphertext
someone edited in the database fails to decrypt rather than decrypting to
some other token. The `tenant_id` is bound in as associated data, so a
ciphertext copied from one tenant's row into another's is rejected too.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

KEY_VERSION = 1
_PREFIX = "v1:"
_NONCE_BYTES = 12


class SlackTokenKeyMissing(RuntimeError):
    """Raised when a token would be read or written with no key configured.

    Deliberately loud. The alternative — falling back to storing the token in
    the clear — is the kind of silent downgrade that only gets discovered
    after it has been running in production for a month.
    """


class SlackTokenUndecryptable(RuntimeError):
    """The ciphertext did not authenticate: wrong key, wrong tenant, or the
    row was tampered with. Never retried, never worked around."""


def _key() -> bytes:
    """Derive the 32-byte AES key from whatever string the host was given.

    SHA-256 of the raw environment value, so ARGUS_SLACK_TOKEN_KEY can be any
    string at all — in particular whatever Render's "Generate Value" button
    produces, with no base64 rules or length requirements for a non-technical
    owner to get wrong.
    """
    if not config.SLACK_TOKEN_KEY:
        raise SlackTokenKeyMissing(
            "ARGUS_SLACK_TOKEN_KEY is not set — refusing to store or read a Slack "
            "bot token. Set it in this host's environment and restart.")
    return hashlib.sha256(config.SLACK_TOKEN_KEY.encode("utf-8")).digest()


def _aad(tenant_id: str) -> bytes:
    return f"argus:slack_token:{tenant_id}".encode("utf-8")


def encrypt_token(plaintext: str, tenant_id: str) -> str:
    """Return `v1:<base64(nonce || ciphertext||tag)>`.

    A fresh random nonce per call, which is what makes it safe to re-encrypt
    the same token on every reinstall.
    """
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, plaintext.encode("utf-8"), _aad(tenant_id))
    return _PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt_token(stored: str, tenant_id: str) -> str:
    if not stored.startswith(_PREFIX):
        raise SlackTokenUndecryptable(f"unrecognised ciphertext format: {stored[:8]!r}")
    try:
        blob = base64.b64decode(stored[len(_PREFIX):], validate=True)
    except (ValueError, TypeError) as exc:
        raise SlackTokenUndecryptable("ciphertext is not valid base64") from exc
    if len(blob) <= _NONCE_BYTES:
        raise SlackTokenUndecryptable("ciphertext too short to contain a nonce")
    try:
        opened = AESGCM(_key()).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:],
                                        _aad(tenant_id))
    except InvalidTag as exc:
        raise SlackTokenUndecryptable(
            "Slack token failed authentication — wrong ARGUS_SLACK_TOKEN_KEY, or the "
            "row belongs to a different tenant than the one asking for it.") from exc
    return opened.decode("utf-8")
