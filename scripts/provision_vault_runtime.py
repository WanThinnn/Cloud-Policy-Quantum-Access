"""Operator-only provisioning of the Vault identity used by production Django."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

import hvac


RUNTIME_PATH = 'cpqa-runtime'
RUNTIME_POLICY = 'cpqa-runtime'
PUBLIC_COVERCRYPT_FIELDS = (
    'CPABE_PK_COVERCRYPT', 'PQC_PK_COVERCRYPT',
    'COVERCRYPT_KEYSET_MANIFEST_primary', 'COVERCRYPT_AUTHORITY_HISTORY_v1',
)


def runtime_policy(mounts, allow_export):
    rules = {
        'auth/token/lookup-self': ['read'],
        'auth/token/renew-self': ['update'],
        f'secret/data/{RUNTIME_PATH}': ['read'],
        f'secret/metadata/{RUNTIME_PATH}': ['read'],
        'secret/data/runtime-settings/smtp/*': ['create', 'read', 'update'],
    }
    for mount in sorted(mounts):
        if not re.fullmatch(r'abe_(?:ac17|tkn20|covercrypt(?:_[a-z0-9][a-z0-9_-]{0,47})?)', mount):
            raise ValueError('Unexpected Vault mount in the runtime allowlist.')
        rules[f'{mount}/authority'] = ['read']
        rules[f'{mount}/encrypt'] = ['update']
        rules[f'{mount}/decrypt_with_attributes'] = ['update']
        if allow_export:
            rules[f'{mount}/genkey'] = ['update']
            rules[f'{mount}/decrypt'] = ['update']
    return '\n'.join(f'path "{path}" {{ capabilities = {json.dumps(caps)} }}' for path, caps in rules.items())


def provision(client, source_path, allow_export, extra_mounts):
    kv = client.secrets.kv.v2
    source = kv.read_secret_version(path=source_path, raise_on_deleted_version=True)['data']['data']
    allowed = {'MASTER_FIELD_ENCRYPTION_KEY', 'CPABE_PK_AC17', 'CPABE_PK_TKN20', 'PQC_PK_AC17', 'PQC_PK_TKN20',
               'COVERCRYPT_KEYSET_INITIALIZING_primary', *PUBLIC_COVERCRYPT_FIELDS}
    data = {key: source[key] for key in allowed if key in source}
    if not all(data.get(key) for key in ('MASTER_FIELD_ENCRYPTION_KEY', 'CPABE_PK_AC17', 'CPABE_PK_TKN20')):
        raise ValueError('The operator record must contain the existing field key and both classical public keys.')
    mounts = {'abe_ac17', 'abe_tkn20', 'abe_covercrypt', *extra_mounts}
    active_manifest = data.get('COVERCRYPT_KEYSET_MANIFEST_primary')
    if active_manifest:
        mounts.add(json.loads(active_manifest)['vault_mount'])
    for entry in data.get('COVERCRYPT_AUTHORITY_HISTORY_v1', {}).values():
        mounts.add(json.loads(entry['COVERCRYPT_KEYSET_MANIFEST_primary'])['vault_mount'])
    policy = runtime_policy(mounts, allow_export)

    try:
        current = kv.read_secret_version(path=RUNTIME_PATH, raise_on_deleted_version=True)['data']
        version = current['metadata']['version']
        if current['data'] != data:
            kv.create_or_update_secret(path=RUNTIME_PATH, secret=data, cas=version)
    except hvac.exceptions.InvalidPath:
        kv.create_or_update_secret(path=RUNTIME_PATH, secret=data, cas=0)
    client.sys.create_or_update_policy(name=RUNTIME_POLICY, policy=policy)
    result = client.auth.token.create(
        policies=[RUNTIME_POLICY], no_default_policy=True, ttl='8h', explicit_max_ttl='24h', renewable=True,
        no_parent=True, display_name='cpqa-web',
    )
    return result['auth']['client_token']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-path', default='crypto_access')
    parser.add_argument('--allow-exported-user-keys', action='store_true')
    parser.add_argument('--mount', action='append', default=[])
    parser.add_argument('--token-out', type=Path, required=True)
    args = parser.parse_args()
    address, ca = os.environ.get('VAULT_ADDR', ''), os.environ.get('VAULT_CACERT', '')
    operator_token = os.environ.get('VAULT_TOKEN', '')
    if not address.startswith('https://') or not Path(ca).is_file() or not operator_token:
        parser.error('Set the HTTPS VAULT_ADDR, VAULT_CACERT and an operator VAULT_TOKEN.')
    if args.source_path == RUNTIME_PATH:
        parser.error('Use a separate operator metadata source.')
    client = hvac.Client(url=address, verify=ca, token=operator_token, timeout=30)
    token = None
    temporary = None
    try:
        if not args.token_out.parent.is_dir():
            parser.error('Create and protect the runtime token directory before provisioning.')
        token = provision(client, args.source_path, args.allow_exported_user_keys, args.mount)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=args.token_out.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(token + '\n')
        temporary.replace(args.token_out)
    except Exception as exc:
        if token is not None:
            client.auth.token.revoke(token)
        raise SystemExit(f'Vault runtime provisioning failed ({type(exc).__name__}).') from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print('Runtime token file written. Restart Django workers to load the new token.')


if __name__ == '__main__':
    main()
