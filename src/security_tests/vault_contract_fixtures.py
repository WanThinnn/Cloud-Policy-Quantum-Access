"""Public, synthetic fixtures for upstream plugins/vault/AUTHORITY.md v1."""
import base64
import hashlib


SETUP_HELP = {'openapi': {'paths': {'/setup': {'post': {'requestBody': {'content': {
    'application/json': {'schema': {'$ref': '#/components/schemas/WriteSetupRequest'}}}}}}},
    'components': {'schemas': {'WriteSetupRequest': {'properties': {
        'create_only': {'type': 'boolean'}, 'public_key_format': {'type': 'string'},
    }}}}}}


def authority_data(scheme='covercrypt', signed=False, config_json=None, reference=True):
    raw = b'public-only-fixture'
    fingerprint = hashlib.sha256(raw).hexdigest()
    result = {'contract_version': 1, 'scheme': scheme, 'revision': 1, 'pqc': signed,
              'public_key': 'vault-authority-sha256:' + fingerprint if reference else base64.b64encode(raw).decode(),
              'public_key_format': 'vault-authority-sha256-v1' if reference else 'base64',
              'public_key_fingerprint': fingerprint, 'native_version': 'fixture'}
    if signed:
        result['pqc_public_key'] = base64.b64encode(b'public-verification-fixture').decode()
    if scheme == 'covercrypt':
        result.update(config_json=config_json, mode='hybridized')
    return result
