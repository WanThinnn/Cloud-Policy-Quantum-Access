"""CoverCrypt public metadata recovery; no deployment DB, Vault or native keys."""
import base64
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from django.test import SimpleTestCase

from crypto_access.services import cpabe_service as module
from crypto_access.services.covercrypt_public_key import public_key_fingerprint, public_key_reference


class CoverCryptVaultKeysetTests(SimpleTestCase):
    def setUp(self):
        self.configuration = SimpleNamespace(
            fingerprint='sha256:fixture', attribute_versions={'department': 1},
            dimensions=[{'name': 'department', 'attributes': ['it', 'hr'], 'hierarchical': False}],
            config_json='{"dimensions":[{"attributes":["it","hr"],"hierarchical":false,"name":"department"}]}',
        )
        self.reference = public_key_reference(base64.b64encode(b'public-only-fixture').decode())
        self.state = {module.COVERCRYPT_MOUNT_CREATED_KEY: 'abe_covercrypt'}
        self.vault = Mock()
        self.vault.get_addr = 'https://vault.test'
        self.vault.is_authenticated.return_value = True
        self.vault.get_secret.side_effect = lambda name: self.state.get(name)
        self.vault.get_secrets.side_effect = lambda names: {n: self.state[n] for n in names if n in self.state}
        def put(name, value):
            if len(json.dumps(value)) > 1024 * 1024:
                return False
            self.state[name] = value
            return True
        self.vault.put_secret.side_effect = put
        self.vault.claim_secret.side_effect = lambda name, value: (
            False if self.state.get(name) is not None else put(name, value))
        def put_batch(values):
            self.state.update(values)
            return True
        self.vault.put_secrets.side_effect = put_batch
        self.response = Mock()
        self.data = {'scheme': 'covercrypt', 'public_key': self.reference, 'pqc': False,
                     'config_json': self.configuration.config_json, 'mode': 'hybridized'}
        self.response.json.side_effect = lambda: {'data': self.data}
        self.service = object.__new__(module.CPABEService)
        self.service._vault_verify = True
        self.service.use_vault_plugin = True
        for target, options in (
            ('crypto_access.services.cpabe_service.vault_service', {'new': self.vault}),
            ('crypto_access.services.covercrypt_config.build_covercrypt_configuration',
             {'return_value': self.configuration}),
        ):
            p = patch(target, **options)
            p.start()
            self.addCleanup(p.stop)
        for method in ('get', 'put'):
            patcher = patch.object(module.requests, method, return_value=self.response)
            setattr(self, method, patcher.start())
            self.addCleanup(patcher.stop)

    def recovering(self):
        self.state[module.COVERCRYPT_INIT_MARKER_KEY] = json.dumps({
            'status': 'initializing', 'config_fingerprint': self.configuration.fingerprint})

    def ensure(self, signed=False):
        return self.service._ensure_covercrypt_keyset(signed, {})

    def test_first_setup_persists_compact_reference_and_fingerprint(self):
        self.assertEqual(self.ensure(), self.reference)
        manifest = json.loads(self.state[module.COVERCRYPT_MANIFEST_KEY])
        self.assertEqual(manifest['public_key_fingerprint'], public_key_fingerprint(self.reference))
        self.assertEqual(self.state[module.COVERCRYPT_INIT_MARKER_KEY], 'initialized')
        self.get.assert_not_called()
        self.assertEqual(self.put.call_args.args[0], 'https://vault.test/v1/abe_covercrypt/setup')

    def test_oversized_legacy_response_is_not_written_to_kv(self):
        self.data['public_key'] = base64.b64encode(b'p' * (2 * 1024 * 1024)).decode()
        with self.assertRaisesRegex(module.CPABEError, 'Upgrade the Vault plugin'):
            self.ensure()
        self.assertNotIn(module.COVERCRYPT_PUBLIC_KEY_KEY, self.state)
        self.assertNotIn(module.COVERCRYPT_MANIFEST_KEY, self.state)

    def test_incomplete_setup_recovers_existing_authority_without_setup(self):
        self.recovering()
        self.assertEqual(self.ensure(), self.reference)
        self.put.assert_not_called()
        self.assertTrue(self.get.call_args.args[0].endswith('/authority'))
        self.assertEqual(self.ensure(), self.reference)
        self.assertEqual(self.get.call_count, 1)

    def test_missing_authority_never_triggers_replacement_setup(self):
        self.recovering()
        self.response.raise_for_status.side_effect = requests.HTTPError('not found')
        with self.assertRaises(module.CPABEError):
            self.ensure()
        self.put.assert_not_called()
        self.assertNotIn(module.COVERCRYPT_MANIFEST_KEY, self.state)

    def test_configuration_mismatch_never_writes_metadata(self):
        self.recovering()
        self.data['config_json'] = '{}'
        with self.assertRaises(module.CPABEError):
            self.ensure()
        self.vault.put_secrets.assert_not_called()
        self.put.assert_not_called()

    def test_different_recorded_key_is_not_overwritten(self):
        self.recovering()
        self.state[module.COVERCRYPT_PUBLIC_KEY_KEY] = base64.b64encode(b'other').decode()
        with self.assertRaisesRegex(module.CPABEError, 'differs from the recorded public key'):
            self.ensure()
        self.vault.put_secrets.assert_not_called()

    def test_signature_state_mismatch_is_rejected(self):
        self.recovering()
        self.data['pqc'] = True
        with self.assertRaisesRegex(module.CPABEError, 'signature state'):
            self.ensure()
        self.vault.put_secrets.assert_not_called()

    def test_guard_for_another_configuration_is_not_recovered(self):
        self.recovering()
        self.state[module.COVERCRYPT_INIT_MARKER_KEY] = '{"status":"initializing","config_fingerprint":"other"}'
        with self.assertRaises(module.CPABEError):
            self.ensure()
        self.get.assert_not_called()
        self.put.assert_not_called()

    def test_reference_parser_rejects_malformed_and_preserves_legacy_hash(self):
        raw = b'public-only-fixture'
        self.assertEqual(public_key_fingerprint(self.reference), hashlib.sha256(raw).hexdigest())
        self.assertEqual(public_key_fingerprint(base64.b64encode(raw).decode()), hashlib.sha256(raw).hexdigest())
        for value in ('vault-authority-sha256:abc', 'vault-authority-sha256:' + 'G' * 64, '', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                public_key_fingerprint(value)

    def test_signed_authority_recovery_preserves_verification_key(self):
        self.recovering()
        self.data['pqc'] = True
        verifier = base64.b64encode(b'public-verification-fixture').decode()
        self.data['pqc_public_key'] = verifier
        self.assertEqual(self.ensure(signed=True), self.reference)
        self.assertEqual(self.state[module.COVERCRYPT_PQC_PUBLIC_KEY_KEY], verifier)
        self.assertTrue(json.loads(self.state[module.COVERCRYPT_MANIFEST_KEY])['pqc_enabled'])
        self.put.assert_not_called()

    def test_cache_identity_uses_reference_fingerprint(self):
        self.ensure()
        identity = self.service.covercrypt_cache_identity()
        self.assertEqual(identity, self.configuration.fingerprint + ':' + public_key_fingerprint(self.reference))

    def test_recorded_verifier_cannot_be_replaced_during_recovery(self):
        self.recovering()
        self.data['pqc'] = True
        self.data['pqc_public_key'] = base64.b64encode(b'new-verifier-fixture').decode()
        self.state[module.COVERCRYPT_PQC_PUBLIC_KEY_KEY] = base64.b64encode(b'old-verifier-fixture').decode()
        with self.assertRaisesRegex(module.CPABEError, 'signature state'):
            self.ensure(signed=True)
        self.vault.put_secrets.assert_not_called()

    def test_failed_guard_claim_never_calls_setup(self):
        self.vault.claim_secret.return_value = False
        self.vault.claim_secret.side_effect = None
        with self.assertRaisesRegex(module.CPABEError, 'guard could not be acquired'):
            self.ensure()
        self.put.assert_not_called()

    def test_native_worker_without_guard_cannot_generate_keys(self):
        self.service._lib = Mock()
        self.service._setup_scheme_func = Mock()
        self.vault.claim_secret.side_effect = None
        self.vault.claim_secret.return_value = False
        with self.assertRaisesRegex(module.CPABEError, 'initialization guard'):
            self.service._ensure_covercrypt_native_keyset_locked()
        self.service._setup_scheme_func.assert_not_called()

    def test_two_initializers_only_call_setup_once(self):
        from concurrent.futures import ThreadPoolExecutor
        from security_tests.test_vault_concurrency import VersionedKV, worker
        kv = VersionedKV()
        kv.data = {module.COVERCRYPT_MOUNT_CREATED_KEY: 'abe_covercrypt'}
        real_vault = worker(kv)
        with patch.object(module, 'vault_service', real_vault):
            def initialize():
                try:
                    return self.ensure()
                except module.CPABEError:
                    return 'blocked'
            with ThreadPoolExecutor(2) as pool:
                futures = [pool.submit(initialize) for _ in range(2)]
                results = [f.result(timeout=10) for f in futures]
        self.assertEqual(results.count(self.reference), 1)
        self.assertEqual(self.put.call_count, 1)
        self.assertEqual(kv.data[module.COVERCRYPT_INIT_MARKER_KEY], 'initialized')
