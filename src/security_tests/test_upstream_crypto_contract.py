"""CPQA must consume the upstream API, without invented flags/endpoints/responses."""
import base64
import struct
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from crypto_access.services import cpabe_service as module


class UpstreamCryptoContractTests(SimpleTestCase):
    def test_all_schemes_accept_ciphertext_only_response_and_send_only_upstream_fields(self):
        for scheme, tag in (('ac17', 0), ('tkn20', 1), ('covercrypt', 2)):
            for signed in (False, True):
                with self.subTest(scheme=scheme, signed=signed):
                    service = object.__new__(module.CPABEService)
                    service.use_vault_plugin = True
                    service._vault_verify = True
                    public = base64.b64encode(b'public-fixture').decode()
                    service._ensure_covercrypt_keyset = Mock(return_value=public)
                    vault = Mock()
                    vault.get_addr = 'https://fixture'
                    vault.get_token = 'test-only'
                    vault.get_secret.side_effect = lambda name: (
                        base64.b64encode(b'verifier-fixture').decode() if name.startswith('PQC_PK') and signed
                        else public if name.startswith('CPABE_PK') else None)
                    ciphertext = bytes([2, tag]) + b'0' * 12 + struct.pack('<Q', 1) + b'A' + b'0' * 16
                    response = Mock()
                    response.json.return_value = {'data': {'ciphertext': base64.b64encode(ciphertext).decode()}}
                    with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put:
                        data, metadata = service.encrypt_version(b'fixture', 'fixture-policy', scheme, signed)
                    self.assertEqual(data, ciphertext)
                    self.assertEqual(metadata['pqc_signed'], signed)
                    self.assertEqual(set(put.call_args.kwargs['json']), {'scheme', 'plaintext', 'policy', 'public_key'})
                    self.assertEqual(put.call_args.kwargs['json']['public_key'], public)

    def test_signature_mode_mismatch_fails_before_encryption(self):
        service = object.__new__(module.CPABEService)
        service.use_vault_plugin = True
        service._vault_verify = True
        vault = Mock()
        vault.get_secret.return_value = 'nonempty-fixture'
        with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put') as put:
            with self.assertRaisesRegex(module.CPABEError, 'signature mode'):
                service.encrypt_version(b'fixture', 'policy', 'ac17', False)
            put.assert_not_called()

    def test_decrypt_sends_only_fields_supported_by_upstream(self):
        for scheme, tag in (('ac17', 0), ('tkn20', 1), ('covercrypt', 2)):
            for signed in (False, True):
                with self.subTest(scheme=scheme, signed=signed):
                    service = object.__new__(module.CPABEService)
                    service.use_vault_plugin = True
                    service._vault_verify = True
                    service._ensure_covercrypt_keyset = Mock()
                    vault = Mock()
                    vault.get_addr = 'https://fixture'
                    vault.get_token = 'test-only'
                    vault.get_secret.return_value = base64.b64encode(b'verifier-fixture').decode()
                    response = Mock()
                    response.json.return_value = {'data': {'plaintext': base64.b64encode(b'fixture').decode()}}
                    ciphertext = bytes([2, tag]) + b'0' * 12 + struct.pack('<Q', 1) + b'A' + b'0' * 16
                    with patch.object(module, 'vault_service', vault), patch.object(module.requests, 'put', return_value=response) as put:
                        operation = service.decrypt_buffer_and_verify if signed else service.decrypt_buffer
                        self.assertEqual(operation(b'user-key-fixture', ciphertext, scheme=scheme), b'fixture')
                    expected = {'ciphertext', 'secret_key'} | ({'pqc_public_key'} if signed else set())
                    self.assertEqual(set(put.call_args.kwargs['json']), expected)
