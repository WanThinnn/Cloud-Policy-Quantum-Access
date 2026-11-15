"""CLI update sequencing only; no Docker daemon, network, .env or services."""
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import start


class CryptoUpdateTests(unittest.TestCase):
    def test_build_consumes_unmodified_upstream_source(self):
        root = Path(__file__).resolve().parents[1]
        build = (root / 'docker/build-crypto.sh').read_text(encoding='utf-8')
        dockerfile = (root / 'docker/Dockerfile').read_text(encoding='utf-8')
        self.assertNotIn('git apply', build)
        self.assertNotIn('COPY docker/patches/', dockerfile)
        self.assertFalse(list((root / 'docker/patches').glob('*.patch')))
        self.assertIn('git diff --quiet HEAD --', build)
        self.assertIn('CRYPTO_CPQA_PATCHES=none', build)

    def invoke(self, args, fail_on=None):
        calls = []

        def run(command):
            calls.append(command)
            if fail_on and fail_on in command:
                raise subprocess.CalledProcessError(7, command)

        with tempfile.TemporaryDirectory() as directory:
            with patch.object(start, 'ENV_FILE', Path(directory) / '.env'), \
                 patch.object(start, 'run', side_effect=run), \
                 patch.object(start, 'extract_pqc_raw_key'), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = start.main(args)
        return result, calls

    def test_update_builds_before_start_without_overwriting_local_sources(self):
        result, calls = self.invoke(['update'])
        self.assertEqual(result, 0)
        self.assertEqual(calls[0], ['git', 'pull', '--ff-only'])
        build = next(i for i, c in enumerate(calls) if c[-1] == 'build')
        up = next(i for i, c in enumerate(calls) if c[-2:] == ['up', '-d'])
        self.assertLess(build, up)
        self.assertFalse(any(c[0] == 'git' and 'clone' in c for c in calls))
        self.assertFalse(any('down' in c or '-v' in c for c in calls))

    def test_build_failure_does_not_restart_containers(self):
        result, calls = self.invoke(['update'], fail_on='build')
        self.assertEqual(result, 7)
        self.assertFalse(any('up' in c or 'down' in c for c in calls))

    def test_git_failure_does_not_build(self):
        result, calls = self.invoke(['update'], fail_on='--ff-only')
        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 1)

    def test_prod_build_skips_pull_for_source_built_services(self):
        result, calls = self.invoke(['--prod', 'build'])
        self.assertEqual(result, 0)
        self.assertEqual(calls[0][-2:], ['pull', '--ignore-buildable'])
        self.assertEqual(calls[1][-1], 'build')

    def test_clean_preserves_host_keys_when_vault_volume_removal_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            keys = Path(directory)
            unseal = keys / 'vault_unseal_keys.json'
            token = keys / 'vault_token.txt'
            for file in (unseal, token):
                file.touch()
            command = ['docker', 'volume', 'rm', 'cloud-policy-quantum-access_vault_data']
            output = io.StringIO()
            with patch.object(start, 'load_env_file', return_value={'KEYS_DIR': str(keys)}), \
                 patch('builtins.input', side_effect=['y', 'n', 'n', 'y', 'n', 'n']), \
                 patch.object(start.subprocess, 'check_output', return_value=command[-1] + '\n'), \
                 patch.object(start, 'run', side_effect=[None, subprocess.CalledProcessError(7, command)]), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(start.main(['clean']), 7)
            self.assertTrue(unseal.exists())
            self.assertTrue(token.exists())
            self.assertNotIn('[OK] Selected volumes removed.', output.getvalue())


if __name__ == '__main__':
    unittest.main()
