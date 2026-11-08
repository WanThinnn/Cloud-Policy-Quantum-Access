"""Compact, fingerprint-bound references to public keys held by the Vault plugin."""
import base64
import hashlib
import re

PUBLIC_KEY_REFERENCE_PREFIX = "vault-authority-sha256:"


def public_key_fingerprint(value):
    """Accept legacy Base64 keys and strictly validated plugin references."""
    if not isinstance(value, str) or not value:
        raise ValueError("Missing CoverCrypt public key")
    if value.startswith(PUBLIC_KEY_REFERENCE_PREFIX):
        fingerprint = value[len(PUBLIC_KEY_REFERENCE_PREFIX):]
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("Invalid CoverCrypt public-key reference")
        return fingerprint
    raw = base64.b64decode(value, validate=True)
    if not raw:
        raise ValueError("Empty CoverCrypt public key")
    return hashlib.sha256(raw).hexdigest()


def public_key_reference(value):
    return PUBLIC_KEY_REFERENCE_PREFIX + public_key_fingerprint(value)
