"""Typed per-version crypto metadata. Never infer history from current feature flags."""
import copy
import struct
from .covercrypt_public_key import public_key_fingerprint, valid_fingerprint

from rest_framework.exceptions import APIException


class CryptoMetadataError(APIException):
    status_code = 409
    default_detail = 'Crypto metadata is missing or inconsistent for this version; administrator recovery is required.'
    default_code = 'crypto_metadata_required'


PLAINTEXT_METADATA = {
    'schema': 1, 'scheme': None, 'format': 'plaintext', 'pqc_signed': False, 'backend': 'none',
}


def inspect_header(data):
    """Read the native v1/v2 AAD layout; AEAD/signature verification remains mandatory afterward.

    Source: hybrid-cp-abe.cpp (AAD = version, [scheme], IV[12], uint64 LE key length, ABE key).
    The supported deployment is Linux AMD64 / Windows x64, both little endian.
    """
    if not data or data[0] not in (1, 2):
        raise CryptoMetadataError()
    offset = 2 if data[0] == 2 else 1
    scheme = 'ac17'
    if data[0] == 2:
        if len(data) < 2 or data[1] not in (0, 1, 2):
            raise CryptoMetadataError()
        scheme = ('ac17', 'tkn20', 'covercrypt')[data[1]]
    length_offset = offset + 12
    if len(data) < length_offset + 8 + 16:
        raise CryptoMetadataError()
    key_length = struct.unpack_from('<Q', data, length_offset)[0]
    if key_length == 0 or length_offset + 8 + key_length + 16 > len(data):
        raise CryptoMetadataError()
    return {'scheme': scheme, 'format': f'hybrid-v{data[0]}'}


def validate_metadata(value):
    if (not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] not in (1, 2) or
            type(value.get('pqc_signed')) is not bool):
        raise CryptoMetadataError()
    fields = set(PLAINTEXT_METADATA)
    if value['schema'] == 2:
        fields |= {'keyset_id', 'authority_revision', 'contract_version'}
        if (value.get('backend') != 'vault' or value.get('format') != 'hybrid-v2' or
                type(value.get('contract_version')) is not int or value['contract_version'] != 1 or
                not valid_fingerprint(value.get('keyset_id')) or
                type(value.get('authority_revision')) is not int or
                not 1 <= value['authority_revision'] <= (1 << 64) - 1):
            raise CryptoMetadataError()
    if set(value) != fields:
        raise CryptoMetadataError()
    if value.get('format') == 'plaintext':
        if any(value.get(key) != expected for key, expected in PLAINTEXT_METADATA.items()):
            raise CryptoMetadataError()
    elif (value.get('format') not in ('hybrid-v1', 'hybrid-v2') or
          value.get('scheme') not in ('ac17', 'tkn20', 'covercrypt') or value.get('backend') not in ('native', 'vault')):
        raise CryptoMetadataError()
    elif value['format'] == 'hybrid-v1' and value['scheme'] != 'ac17':
        raise CryptoMetadataError()
    return copy.deepcopy(value)


def metadata_from_plugin(result, data, *, scheme, signed, public_key, revision):
    """Map upstream encryption-time schema 1 to CPQA version metadata schema 2."""
    if not isinstance(result, dict):
        raise CryptoMetadataError()
    value = result.get('crypto_metadata')
    fields = set(PLAINTEXT_METADATA) | {'keyset_id', 'authority_revision'}
    if not isinstance(value, dict) or set(value) != fields or type(value.get('schema')) is not int or value['schema'] != 1:
        raise CryptoMetadataError('Vault plugin encryption metadata contract is required; upgrade the plugin.')
    metadata = validate_metadata({**value, 'schema': 2, 'contract_version': 1})
    header = inspect_header(data)
    if (metadata['scheme'] != scheme or metadata['pqc_signed'] != signed or metadata['authority_revision'] != revision or
            metadata['keyset_id'] != public_key_fingerprint(public_key) or
            any(metadata[key] != header[key] for key in ('scheme', 'format'))):
        raise CryptoMetadataError('Vault ciphertext metadata differs from the requested operation or authority.')
    return metadata


def metadata_for_read(version, data, *, backend):
    value = version.crypto_metadata if version is not None else {}
    legacy = not value
    if legacy and version is not None and version.cpabe_policy == '':
        value = dict(PLAINTEXT_METADATA)
        legacy = False
    elif legacy:
        header = inspect_header(data)
        if header['scheme'] == 'covercrypt':
            # The upstream ciphertext header does not record whether ML-DSA
            # signing was enabled. Never guess the verification mode for an
            # older CoverCrypt version.
            raise CryptoMetadataError()
        # Historical signature mode is not visible in the header. Only a successful
        # signature verification can automatically establish a trustworthy signed mode.
        value = {'schema': 1, **header, 'pqc_signed': True, 'backend': backend}
    value = validate_metadata(value)
    if version is not None and (value['format'] == 'plaintext') == bool(version.cpabe_policy):
        raise CryptoMetadataError()
    if value['format'] != 'plaintext':
        header = inspect_header(data)
        if any(value[key] != header[key] for key in ('scheme', 'format')) or value['backend'] != backend:
            raise CryptoMetadataError()
    return value, legacy


def persist_verified_metadata(version, value):
    if version is not None and not version.crypto_metadata:
        from crypto_access.models import FileVersion
        FileVersion.objects.filter(pk=version.pk, physical_path=version.physical_path, crypto_metadata={}).update(
            crypto_metadata=value)
        version.crypto_metadata = value
