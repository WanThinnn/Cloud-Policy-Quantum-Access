"""Real crypto against a disposable Vault; never uses deployment env/volumes.

python tests/smoke_crypto_image.py --image cpqa-vault-test:6.0.0
"""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    image = parser.parse_args().image
    manifest = subprocess.check_output([
        'docker', 'run', '--rm', '--entrypoint', 'cat', image, '/opt/cpqa/crypto/source.env'
    ], text=True)
    expected_version = dict(line.split('=', 1) for line in manifest.splitlines()
                            if line and not line.startswith('#'))['CRYPTO_VERSION']
    name = 'cpqa-crypto-smoke-' + uuid.uuid4().hex[:12]
    token = 'disposable-test-only'
    # Simulate executable artifacts left by an older image without any host volume.
    subprocess.run([
        'docker', 'run', '--rm', '--cap-add', 'IPC_LOCK', '--entrypoint', '/bin/sh', image, '-ec',
        'echo stale > /vault/plugins/vault-plugin-abe; '
        'echo stale > /vault/plugins/libhybrid-pq-cp-abe.so; '
        '/usr/local/bin/cpqa-vault-entrypoint version >/dev/null; '
        'cmp /opt/cpqa/crypto/plugin/vault-plugin-abe /vault/plugins/vault-plugin-abe; '
        'cmp /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so /vault/plugins/libhybrid-pq-cp-abe.so',
    ], check=True)
    print('Stale plugin artifacts refreshed: OK')
    with tempfile.TemporaryDirectory(prefix='cpqa-crypto-') as temporary:
        config = Path(temporary) / 'vault.hcl'
        config.write_text('plugin_directory = "/vault/plugins"\ndisable_mlock = true\n')
        try:
            subprocess.run([
                'docker', 'run', '-d', '--rm', '--name', name,
                '--cap-add', 'IPC_LOCK', '-p', '127.0.0.1::8200',
                '-v', f'{config.as_posix()}:/tmp/test-vault.hcl:ro', image,
                'server', '-dev', '-config=/tmp/test-vault.hcl',
                '-dev-listen-address=0.0.0.0:8200', '-dev-root-token-id=' + token,
            ], check=True, capture_output=True)
            port = subprocess.check_output(['docker', 'port', name, '8200/tcp'], text=True).strip().rsplit(':', 1)[1]
            address = 'http://127.0.0.1:' + port + '/v1/'

            def api(path, payload=None):
                request = urllib.request.Request(
                    address + path,
                    data=None if payload is None else json.dumps(payload).encode(),
                    headers={'X-Vault-Token': token, 'Content-Type': 'application/json'},
                )
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read()
                    return json.loads(body) if body else {}

            for attempt in range(60):
                try:
                    api('sys/health')
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.5)
            else:
                raise RuntimeError('Disposable Vault did not become ready')

            digest = subprocess.check_output([
                'docker', 'exec', name, 'sha256sum', '/vault/plugins/vault-plugin-abe'
            ], text=True).split()[0]
            api('sys/plugins/catalog/secret/vault-plugin-abe', {
                'sha256': digest, 'command': 'vault-plugin-abe',
            })
            for scheme, attrs, wrong, policy in [
                ('ac17', 'admin it', 'guest', 'admin and it'),
                ('tkn20', 'role:admin,dept:it', 'role:guest', 'role:admin and dept:it'),
                ('covercrypt', 'Department::IT Level::ADMIN', 'Department::IT',
                 'Department::IT && Level::ADMIN'),
            ]:
                for signed in (False, True):
                    mount = f'test_{scheme}_{int(signed)}'
                    api('sys/mounts/' + mount, {'type': 'vault-plugin-abe'})

                    def call(path, data):
                        return api(mount + '/' + path, data)['data']

                    setup_request = {'scheme': scheme, 'pqc': signed}
                    if scheme == 'covercrypt':
                        setup_request['config_json'] = json.dumps({'dimensions': [
                            {'name': 'Department', 'attributes': ['IT', 'HR']},
                            {'name': 'Level', 'attributes': ['USER', 'ADMIN']},
                        ]})
                    setup = call('setup', setup_request)
                    assert setup['native_version'] == expected_version, setup['native_version']
                    user = call('genkey', {'scheme': scheme, 'attributes': attrs})
                    denied = call('genkey', {'scheme': scheme, 'attributes': wrong})
                    plain = base64.b64encode(b'CPQA real crypto\x00\xff').decode()
                    cipher = call('encrypt', {'scheme': scheme, 'policy': policy,
                                             'plaintext': plain, 'public_key': setup['public_key']})
                    request = {'ciphertext': cipher['ciphertext'], 'secret_key': user['secret_key']}
                    if signed:
                        request['pqc_public_key'] = setup['pqc_public_key']
                    assert call('decrypt', request)['plaintext'] == plain
                    request['secret_key'] = denied['secret_key']
                    try:
                        call('decrypt', request)
                    except urllib.error.HTTPError as error:
                        assert error.code == 400, error.code
                    else:
                        raise AssertionError('Unauthorized key decrypted ciphertext')
                    print(f'{scheme}, signed={signed}: allow/deny OK')
            print(f'Vault image loads matching native library {expected_version}: OK')
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    main()
