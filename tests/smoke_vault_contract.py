"""Run real CPQA crypto/API tests on a disposable Raft Vault and private network.

The web image supplies Python dependencies only. Bind-mounted source uses the
isolated security_tests settings, SQLite, local cache and in-memory blob storage.
No deployment .env, database, token, shares, volume or cloud storage is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault-image', required=True)
    parser.add_argument('--web-image', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    suffix = uuid.uuid4().hex[:12]
    network, name = 'cpqa-contract-net-' + suffix, 'cpqa-contract-vault-' + suffix
    address, token = None, None

    def docker(*arguments, **kwargs):
        return subprocess.run(['docker', *arguments], check=True, **kwargs)

    def api(path, payload=None):
        request = urllib.request.Request(address + '/v1/' + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            method='PUT' if payload is not None else 'GET',
            headers={'X-Vault-Token': token or '', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read()
            return json.loads(data) if data else {}

    def ready(path):
        deadline = time.monotonic() + 45
        while True:
            try:
                return api(path)
            except (OSError, urllib.error.URLError):
                if time.monotonic() >= deadline:
                    raise RuntimeError('Disposable Vault fixture did not become ready')
                time.sleep(0.5)

    with tempfile.TemporaryDirectory(prefix='cpqa-contract-') as temporary:
        config = Path(temporary) / 'vault.hcl'
        config.write_text('''plugin_directory = "/vault/plugins"
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"
storage "raft" { path = "/vault/file" }
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
''', encoding='utf-8')
        try:
            docker('network', 'create', network, capture_output=True)
            docker('run', '-d', '--name', name, '--network', network, '--network-alias', 'fixture-abe',
                   '--cap-add', 'IPC_LOCK', '-p', '127.0.0.1::8200',
                   '--mount', f'type=bind,source={config.as_posix()},target=/tmp/contract.hcl,readonly',
                   args.vault_image, 'server', '-config=/tmp/contract.hcl', capture_output=True)
            port = docker('port', name, '8200/tcp', capture_output=True, text=True).stdout.strip().rsplit(':', 1)[1]
            address = 'http://127.0.0.1:' + port
            ready('sys/seal-status')
            initialized = api('sys/init', {'secret_shares': 1, 'secret_threshold': 1})
            api('sys/unseal', {'key': initialized['keys'][0]})
            token = initialized['root_token']
            del initialized
            ready('sys/health')
            digest = docker('exec', name, 'sha256sum', '/vault/plugins/vault-plugin-abe', capture_output=True, text=True).stdout.split()[0]
            api('sys/plugins/catalog/secret/vault-plugin-abe', {'sha256': digest, 'command': 'vault-plugin-abe'})
            for scheme in ('ac17', 'tkn20', 'covercrypt'):
                api('sys/mounts/abe_' + scheme, {'type': 'vault-plugin-abe'})
            api('sys/mounts/secret', {'type': 'kv', 'options': {'version': '2'}})
            api('secret/data/isolated-contract', {'data': {'COVERCRYPT_MOUNT_CREATED': 'abe_covercrypt'}})
            environment = dict(os.environ, CPQA_TEST_VAULT_TOKEN=token)
            docker('run', '--rm', '--network', network, '--entrypoint', 'python', '--workdir', '/app',
                   '--env', 'CPQA_TEST_VAULT_ADDR=http://fixture-abe:8200', '--env', 'CPQA_TEST_VAULT_TOKEN',
                   '--env', 'NO_PROXY=fixture-abe,localhost,127.0.0.1',
                   '--mount', f'type=bind,source={(root / "src").as_posix()},target=/app,readonly',
                   args.web_image, '-m', 'django', 'test', 'security_tests.test_vault_contract_integration',
                   '--settings=security_tests.settings', '--noinput', env=environment)
            print('CPQA upload/download, history, copy, policy assignment, recovery and deny: OK')
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)


if __name__ == '__main__':
    main()
