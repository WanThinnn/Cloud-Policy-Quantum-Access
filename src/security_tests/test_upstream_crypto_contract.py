"""CPQA must consume the upstream API, without invented flags/endpoints/responses."""
import base64
import struct
from unittest.mock import Mock, patch
import requests

from django.test import SimpleTestCase
from crypto_access.services import cpabe_service as module
from crypto_access.services.vault_abe_contract import parse_public_authority
from crypto_access.services.version_crypto import CryptoMetadataError, metadata_from_plugin, validate_metadata
from security_tests.vault_contract_fixtures import authority_data


class UpstreamCryptoContractTests(SimpleTestCase):
    def test_vault_genkey_returns_bytes_and_applies_bounded_timeout(self):
        service, vault, response, _, _ = self.fixture('ac17', False)
        response.json.return_value = {'data': {'secret_key': 'AQID'}}
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put:
            self.assertEqual(service.generate_user_key_bytes({'department': 'it'}, scheme='ac17'), b'\x01\x02\x03')
        self.assertTrue(put.call_args.args[0].endswith('/abe_ac17/genkey'))
        self.assertEqual(put.call_args.kwargs['timeout'], module.VAULT_BUFFER_TIMEOUT)

    def test_vault_rejects_malformed_keys_and_hides_transport_details(self):
        service, vault, response, _, _ = self.fixture('ac17', False)
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put:
            for bad in ('secret-fixture!', '', None, 10):
                response.json.return_value = {'data': {'secret_key': bad}}
                with self.subTest(result_type=type(bad).__name__), self.assertRaises(module.CPABEVaultUnavailable) as error:
                    service.generate_user_key_bytes({'department': 'it'}, scheme='ac17')
                self.assertEqual(str(error.exception), 'Vault genkey returned an invalid result.')
            for failure in (requests.Timeout('private-fixture'), requests.ConnectionError('private-fixture')):
                put.side_effect = failure
                with self.assertRaises(module.CPABEVaultUnavailable) as error:
                    service.generate_user_key_bytes({'department': 'it'}, scheme='ac17')
                self.assertEqual(str(error.exception), 'Vault genkey is unavailable.')
                self.assertTrue(error.exception.__suppress_context__)

    def test_vault_distinguishes_decrypt_denial_from_sealed_or_unauthenticated(self):
        service, vault, response, _, ciphertext = self.fixture('ac17', False)
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response):
            for status, error in ((400, module.CPABEAccessDenied), (403, module.CPABEVaultUnavailable),
                                  (503, module.CPABEVaultUnavailable)):
                denied = requests.Response()
                denied.status_code = status
                response.raise_for_status.side_effect = requests.HTTPError('private-fixture', response=denied)
                with self.subTest(status=status), self.assertRaises(error) as caught:
                    service.decrypt_buffer(b'key-fixture', ciphertext, scheme='ac17')
                self.assertNotIn('private-fixture', str(caught.exception))

    def fixture(self, scheme, signed):
        service = object.__new__(module.CPABEService)
        service.use_vault_plugin = True
        service._vault_verify = True
        config = Mock(config_json='{"dimensions":[]}')
        public_data = authority_data(scheme, True, config.config_json, reference=(scheme == 'covercrypt'))
        authority = parse_public_authority(public_data, scheme, config)
        service._ensure_covercrypt_keyset = Mock(return_value=module.CoverCryptVaultRoute(
            'abe_covercrypt', config, authority,
        ))
        service._read_vault_authority = Mock(return_value=authority)
        vault = Mock()
        vault.get_addr = 'https://fixture'
        vault.get_token = 'test-only'
        vault.get_secret.side_effect = lambda name: authority.verifier if name.startswith('PQC_PK') else authority.public_key
        tag = {'ac17': 0, 'tkn20': 1, 'covercrypt': 2}[scheme]
        ciphertext = bytes([2, tag]) + b'0' * 12 + struct.pack('<Q', 1) + b'A' + b'0' * 16
        result = {'ciphertext': base64.b64encode(ciphertext).decode(), 'crypto_metadata': {
            'schema': 1, 'scheme': scheme, 'backend': 'vault', 'format': 'hybrid-v2', 'pqc_signed': signed,
            'keyset_id': authority.fingerprint, 'authority_revision': authority.revision}}
        response = Mock()
        response.json.return_value = {'data': result}
        return service, vault, response, result, ciphertext

    def test_all_schemes_use_explicit_sign_and_preserve_plugin_key_identity(self):
        for scheme in ('ac17', 'tkn20', 'covercrypt'):
            for signed in (False, True):
                with self.subTest(scheme=scheme, signed=signed):
                    service, vault, response, result, ciphertext = self.fixture(scheme, signed)
                    with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put, patch('crypto_access.services.covercrypt_config.build_covercrypt_configuration'):
                        data, metadata = service.encrypt_version(b'fixture', 'fixture-policy', scheme, signed)
                    self.assertEqual(data, ciphertext)
                    self.assertEqual(metadata['schema'], 2)
                    self.assertEqual(metadata['pqc_signed'], signed)
                    self.assertEqual(metadata['keyset_id'], result['crypto_metadata']['keyset_id'])
                    self.assertEqual(metadata['authority_revision'], 1)
                    self.assertEqual(set(put.call_args.kwargs['json']), {'scheme', 'plaintext', 'policy', 'public_key', 'sign'})
                    self.assertIs(put.call_args.kwargs['json']['sign'], signed)

    def test_opaque_or_mismatched_plugin_metadata_is_rejected(self):
        for field, value in [('missing', None), ('scheme', 'tkn20'), ('pqc_signed', True),
                             ('keyset_id', '0'*64), ('authority_revision', 2), ('authority_revision', True),
                             ('backend', 'native'), ('format', 'unknown'), ('unexpected', 'private-fixture')]:
            with self.subTest(field=field, value=value):
                service, vault, response, result, ciphertext = self.fixture('ac17', False)
                if field == 'missing': result.pop('crypto_metadata')
                else: result['crypto_metadata'][field] = value
                with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response):
                    with self.assertRaises(CryptoMetadataError) as error:
                        service.encrypt_version(b'private-plaintext-fixture', 'policy', 'ac17', False)
                self.assertNotIn('private-fixture', str(error.exception))
                self.assertNotIn('private-plaintext-fixture', str(error.exception))

    def test_authority_change_is_rejected_before_encryption(self):
        service, vault, response, result, ciphertext = self.fixture('ac17', False)
        service._read_vault_authority.return_value = None
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put') as put:
            with self.assertRaisesRegex(module.CPABEError, 'current Vault authority'):
                service.encrypt_version(b'fixture', 'policy', 'ac17', False)
            put.assert_not_called()

    def test_signature_key_mismatch_is_rejected_before_encryption(self):
        service, vault, response, result, ciphertext = self.fixture('ac17', True)
        vault.get_secret.side_effect = lambda name: 'wrong-fixture' if name.startswith('PQC_PK') else authority_data('ac17', reference=False)['public_key']
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put') as put:
            with self.assertRaisesRegex(module.CPABEError, 'signature verification key'):
                service.encrypt_version(b'fixture', 'policy', 'ac17', True)
            put.assert_not_called()

    def test_metadata_schema_one_remains_valid_and_schema_two_is_strict(self):
        old = {'schema':1,'scheme':'covercrypt','backend':'vault','format':'hybrid-v2','pqc_signed':True}
        self.assertEqual(validate_metadata(old), old)
        for field, value in [('keyset_id','bad'), ('authority_revision',0), ('contract_version',True), ('schema',3)]:
            new = {**old,'schema':2,'keyset_id':'a'*64,'authority_revision':1,'contract_version':1,field:value}
            with self.subTest(field=field), self.assertRaises(CryptoMetadataError): validate_metadata(new)

    def test_version_authority_cannot_be_replaced_even_with_a_cached_user_key(self):
        service, vault, response, result, ciphertext = self.fixture('ac17', False)
        metadata = metadata_from_plugin(result,ciphertext,scheme='ac17',signed=False,
                                         public_key=authority_data('ac17',reference=False)['public_key'],revision=1)
        with patch.object(module,'vault_service',vault):
            service.verify_version_authority(metadata)
            for field, value in [('keyset_id','0'*64),('authority_revision',2)]:
                with self.subTest(field=field), self.assertRaises(CryptoMetadataError):
                    service.verify_version_authority({**metadata,field:value})

    def test_decrypt_sends_only_fields_supported_by_upstream(self):
        for scheme, tag in (('ac17', 0), ('tkn20', 1), ('covercrypt', 2)):
            for signed in (False, True):
                with self.subTest(scheme=scheme, signed=signed):
                    service = object.__new__(module.CPABEService)
                    service.use_vault_plugin = True
                    service._vault_verify = True
                    vault = Mock()
                    vault.get_addr = 'https://fixture'
                    vault.get_token = 'test-only'
                    vault.get_secret.return_value = base64.b64encode(b'verifier-fixture').decode()
                    service._ensure_covercrypt_keyset = Mock(return_value=module.CoverCryptVaultRoute(
                        'abe_covercrypt', Mock(), Mock(verifier=vault.get_secret.return_value),
                    ))
                    response = Mock()
                    response.json.return_value = {'data': {'plaintext': base64.b64encode(b'fixture').decode()}}
                    ciphertext = bytes([2, tag]) + b'0' * 12 + struct.pack('<Q', 1) + b'A' + b'0' * 16
                    with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put:
                        operation = service.decrypt_buffer_and_verify if signed else service.decrypt_buffer
                        self.assertEqual(operation(b'user-key-fixture', ciphertext, scheme=scheme), b'fixture')
                    expected = {'ciphertext', 'secret_key'} | ({'pqc_public_key'} if signed else set())
                    self.assertEqual(set(put.call_args.kwargs['json']), expected)
