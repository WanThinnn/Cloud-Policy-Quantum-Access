"""Public-key representations from the upstream Vault authority contract v1."""
import base64
import hashlib
import re

PUBLIC_KEY_REFERENCE_PREFIX = 'vault-authority-sha256:'
REFERENCE_FORMAT = 'vault-authority-sha256-v1'
_FINGERPRINT = re.compile(r'[0-9a-f]{64}')


def valid_fingerprint(value):
    return isinstance(value, str) and _FINGERPRINT.fullmatch(value) is not None


def public_key_fingerprint(value):
    """Parse transport only; trust a reference only after verifying the plugin contract."""
    if not isinstance(value, str) or not value:
        raise ValueError("Missing CoverCrypt public key")
    if value.startswith(PUBLIC_KEY_REFERENCE_PREFIX):
        fingerprint = value[len(PUBLIC_KEY_REFERENCE_PREFIX):]
        if not valid_fingerprint(fingerprint):
            raise ValueError('Invalid public-key reference')
        return fingerprint
    raw = base64.b64decode(value, validate=True)
    if not raw:
        raise ValueError("Empty CoverCrypt public key")
    return hashlib.sha256(raw).hexdigest()
