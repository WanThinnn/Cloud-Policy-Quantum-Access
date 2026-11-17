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
from threading import Event, Thread
import time
import urllib.error
import urllib.request
import uuid


def sample_resources(containers, stop, samples):
    while not stop.is_set():
        result = subprocess.run(
            ['docker', 'stats', '--no-stream', '--format', '{{json .}}', *containers],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for row in result.stdout.splitlines():
                value = json.loads(row)
                used = value['MemUsage'].split(' / ')[0]
                for suffix, scale in (('GiB', 1024), ('MiB', 1), ('KiB', 1 / 1024), ('B', 1 / 1024**2)):
                    if used.endswith(suffix):
                        samples.setdefault(value['Name'], []).append(
                            (float(value['CPUPerc'].strip('%')), float(used[:-len(suffix)]) * scale)
                        )
                        break
        stop.wait(0.5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault-image', required=True)
    parser.add_argument('--web-image', required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--benchmark', action='store_true', help='Measure the disposable no-cache read path')
    modes.add_argument('--restore-drill', action='store_true', help='Restore a disposable Vault snapshot and signed document')
    parser.add_argument('--internal-decrypt', action='store_true', help='Test the new plugin with a limited runtime identity')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    suffix = uuid.uuid4().hex[:12]
    network, name = 'cpqa-contract-net-' + suffix, 'cpqa-contract-vault-' + suffix
    web_name = 'cpqa-contract-web-' + suffix
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
            restore_share = initialized['keys'][0] if args.restore_drill else None
            token = initialized['root_token']
            del initialized
            ready('sys/health')
            digest = docker('exec', name, 'sha256sum', '/vault/plugins/vault-plugin-abe', capture_output=True, text=True).stdout.split()[0]
            api('sys/plugins/catalog/secret/vault-plugin-abe', {'sha256': digest, 'command': 'vault-plugin-abe'})
            for scheme in ('ac17', 'tkn20', 'covercrypt'):
                api('sys/mounts/abe_' + scheme, {'type': 'vault-plugin-abe'})
            api('sys/mounts/secret', {'type': 'kv', 'options': {'version': '2'}})
            api('secret/data/isolated-contract', {'data': {'COVERCRYPT_MOUNT_CREATED': 'abe_covercrypt'}})
            if args.internal_decrypt and not args.benchmark and not args.restore_drill:
                api('sys/audit/fixture', {'type': 'file', 'options': {'file_path': '/vault/file/cpqa-fixture-audit.json'}})
            environment = dict(os.environ, CPQA_TEST_VAULT_TOKEN=token)
            label = 'security_tests.test_vault_contract_integration'
            execution_options = []
            if args.benchmark:
                label += '.VaultContractIntegrationTests.test_benchmark_uncached_vault_reads'
                environment['CPQA_TEST_VAULT_BENCHMARK'] = '1'
                execution_options.extend(['--env', 'CPQA_TEST_VAULT_BENCHMARK'])
            if args.restore_drill:
                label += '.VaultContractIntegrationTests.test_disposable_backup_restore_drill'
                environment['CPQA_TEST_RESTORE_SHARE'] = restore_share
                execution_options.extend(['--env', 'CPQA_TEST_RESTORE_SHARE'])
            if args.internal_decrypt:
                environment['CPQA_TEST_INTERNAL_DECRYPT'] = '1'
                execution_options.extend([
                    '--env', 'CPQA_TEST_INTERNAL_DECRYPT',
                    '--mount', f'type=bind,source={(root / "scripts/provision_vault_runtime.py").as_posix()},'
                               'target=/tmp/fixture_vault_operator.py,readonly',
                ])
            lifecycle = ['-d', '--name', web_name] if args.benchmark else ['--rm']
            docker('run', *lifecycle, '--network', network, '--entrypoint', 'python', '--workdir', '/app',
                   '--env', 'CPQA_TEST_VAULT_ADDR=http://fixture-abe:8200', '--env', 'CPQA_TEST_VAULT_TOKEN',
                   '--env', 'NO_PROXY=fixture-abe,localhost,127.0.0.1',
                   *execution_options,
                   '--mount', f'type=bind,source={(root / "src").as_posix()},target=/app,readonly',
                   args.web_image, '-m', 'django', 'test', label,
                   '--settings=security_tests.settings', '--noinput', env=environment)
            if args.benchmark:
                stop, samples = Event(), {}
                sampler = Thread(target=sample_resources, args=((name, web_name), stop, samples))
                sampler.start()
                try:
                    result = docker('wait', web_name, capture_output=True, text=True).stdout.strip()
                finally:
                    stop.set()
                    sampler.join()
                docker('logs', web_name)
                if result != '0':
                    raise RuntimeError(f'Benchmark test exited with code {result}')
                for container in (name, web_name):
                    values = samples.get(container, [])
                    if not values:
                        raise RuntimeError(f'No Docker resource samples for {container}')
                    print(json.dumps({'container': container, 'samples': len(values),
                                      'peak_cpu_pct': max(v[0] for v in values),
                                      'peak_memory_mib': round(max(v[1] for v in values), 1)}))
            else:
                print('CPQA upload/download, history, copy, policy assignment, recovery and deny: OK')
            if args.internal_decrypt and not args.benchmark and not args.restore_drill:
                audit = docker('exec', name, 'cat', '/vault/file/cpqa-fixture-audit.json',
                               capture_output=True, text=True).stdout
                verified = 0
                for line in audit.splitlines():
                    event = json.loads(line)
                    request = event.get('request') or {}
                    if not request.get('path', '').endswith('/decrypt_with_attributes'):
                        continue
                    inputs = request.get('data') or {}
                    outputs = (event.get('response') or {}).get('data') or {}
                    if 'secret_key' in inputs or 'secret_key' in outputs:
                        raise RuntimeError('Internal decrypt exposed a user key in audit')
                    if 'plaintext' in outputs:
                        if not outputs['plaintext'].startswith('hmac-sha256:'):
                            raise RuntimeError('Internal decrypt plaintext is not HMAC-protected in audit')
                        verified += 1
                if not verified:
                    raise RuntimeError('No successful internal decrypt found in audit')
                print(f'Vault audit verified on {verified} completed internal decrypt operations.')
        finally:
            if args.benchmark:
                subprocess.run(['docker', 'rm', '-f', web_name], capture_output=True)
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
            subprocess.run(['docker', 'network', 'rm', network], capture_output=True)


if __name__ == '__main__':
    main()
