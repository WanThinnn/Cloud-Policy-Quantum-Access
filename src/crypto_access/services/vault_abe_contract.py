"""Validate the library's published Vault authority contract, without changing it.

Source: upstream plugins/vault/AUTHORITY.md, contract_version=1. Validation
errors deliberately contain no response body, credentials, key or plaintext.
"""
import base64
import json
from dataclasses import dataclass

from .covercrypt_public_key import REFERENCE_FORMAT, public_key_fingerprint, valid_fingerprint


class VaultABEContractError(ValueError):
    pass


@dataclass(frozen=True)
class PublicAuthority:
    public_key: str
    public_key_format: str
    fingerprint: str
    revision: int
    pqc: bool
    verifier: str | None


def parse_public_authority(data, scheme, configuration=None):
    if (not isinstance(data, dict) or type(data.get('contract_version')) is not int or
            data['contract_version'] != 1):
        raise VaultABEContractError('Vault ABE authority contract v1 is required; upgrade the library/plugin.')
    if data.get('scheme') != scheme:
        raise VaultABEContractError('Vault authority scheme differs from the requested scheme.')
    revision = data.get('revision')
    if type(revision) is not int or not 1 <= revision <= (1 << 64) - 1:
        raise VaultABEContractError('Invalid Vault authority revision.')
    public_key = data.get('public_key')
    encoding = data.get('public_key_format')
    if not isinstance(public_key, str) or not public_key or len(public_key) > 512 * 1024:
        raise VaultABEContractError('Missing or oversized public key; request reference transport.')
    is_reference = public_key.startswith('vault-authority-sha256:')
    if encoding != (REFERENCE_FORMAT if is_reference else 'base64'):
        raise VaultABEContractError('Vault public-key encoding does not match its declared format.')
    try:
        fingerprint = public_key_fingerprint(public_key)
    except (TypeError, ValueError) as exc:
        raise VaultABEContractError('Malformed Vault public key.') from exc
    if not valid_fingerprint(data.get('public_key_fingerprint')) or data['public_key_fingerprint'] != fingerprint:
        raise VaultABEContractError('Vault public-key fingerprint mismatch.')
    signed = data.get('pqc')
    verifier = data.get('pqc_public_key')
    if type(signed) is not bool or signed != bool(verifier):
        raise VaultABEContractError('Vault authority signature state is inconsistent.')
    if verifier:
        try:
            if not isinstance(verifier, str) or len(verifier) > 64 * 1024 or not base64.b64decode(verifier, validate=True):
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise VaultABEContractError('Invalid Vault verification key.') from exc
    if scheme == 'covercrypt':
        try:
            actual = json.loads(data['config_json'])
            expected = json.loads(configuration.config_json)
            same_config = json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise VaultABEContractError('Invalid Vault CoverCrypt configuration.') from exc
        if not same_config or data.get('mode') != 'hybridized':
            raise VaultABEContractError('Vault CoverCrypt configuration or mode does not match the active schema.')
    return PublicAuthority(public_key, encoding, fingerprint, revision, signed, verifier)


def verify_create_only_help(payload):
    """Use Vault SDK's built-in OpenAPI help before any first setup.

    An authority 404 alone cannot distinguish an empty new mount from an old
    plugin that would silently ignore create_only. Do not probe by writing.
    """
    try:
        document = payload['openapi']
        schema = document['paths']['/setup']['post']['requestBody']['content']['application/json']['schema']
        if '$ref' in schema:
            prefix = '#/components/schemas/'
            if not schema['$ref'].startswith(prefix):
                raise ValueError()
            schema = document['components']['schemas'][schema['$ref'][len(prefix):]]
        fields = schema['properties']
        supported = fields['create_only']['type'] == 'boolean' and fields['public_key_format']['type'] == 'string'
    except (KeyError, TypeError, ValueError, AttributeError):
        supported = False
    if not supported:
        raise VaultABEContractError('Vault plugin does not advertise create_only/reference support; setup was refused.')
