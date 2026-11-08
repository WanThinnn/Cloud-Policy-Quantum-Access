"""Fingerprints for the upstream Vault API's Base64 public-key representation."""
import base64
import hashlib


def public_key_fingerprint(value):
    """Accept upstream Base64 keys only; never reinterpret a private API reference."""
    if not isinstance(value, str) or not value:
        raise ValueError("Missing CoverCrypt public key")
    raw = base64.b64decode(value, validate=True)
    if not raw:
        raise ValueError("Empty CoverCrypt public key")
    return hashlib.sha256(raw).hexdigest()
