import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from rest_framework.exceptions import PermissionDenied
from crypto_access.services.covercrypt_policy import bypass_attributes
from crypto_access.views import storage as views


CONFIG = SimpleNamespace(dimensions=[
    {'name': 'department', 'attributes': ['it', 'hr']},
    {'name': 'employment_status', 'attributes': ['active', 'inactive']},
    {'name': 'user_type', 'attributes': ['super_admin', 'data_owner']},
])


class CoverCryptBypassTests(SimpleTestCase):
    def setUp(self):
        self.crypto = Mock()
        self.crypto.covercrypt_cache_identity.return_value = 'fixture-authority'
        self.generated = []
        def generate(attrs, output_path, scheme=None):
            self.generated.append(dict(attrs))
            # Exercise the actual mapper, not a fake that accepts missing dimensions.
            from crypto_access.services.cpabe_service import CPABEService
            CPABEService.expand_hierarchical_attributes(None, attrs, scheme='covercrypt')
            Path(output_path).write_bytes(b'fixture-key')
        self.crypto.generate_user_key.side_effect = generate
        self.crypto.decrypt_buffer.return_value = b'plaintext-fixture'
        self.setting = patch('crypto_access.services.document_access.get_runtime_setting', return_value=False)
        self.strict = self.setting.start()
        self.addCleanup(self.setting.stop)
        for target, options in (
            ('crypto_access.models.KeyRevocation.user_cache_generation', {'return_value': 0}),
            ('crypto_access.services.covercrypt_config.build_covercrypt_configuration', {'return_value': CONFIG}),
            ('crypto_access.services.covercrypt_policy.build_covercrypt_configuration', {'return_value': CONFIG}),
            ('crypto_access.views.storage.cpabe_service', {'new': self.crypto}),
            ('crypto_access.views.storage.casbin_service.get_user_attributes', {'return_value': {'user_type': 'super_admin'}}),
            ('crypto_access.models.fields.encrypt_bytes', {'return_value': b'wrapped-fixture'}),
        ):
            p = patch(target, **options)
            p.start()
            self.addCleanup(p.stop)

    def decrypt(self, admin=True, owner=False, policy='employment_status::active', cache_get=None):
        user = SimpleNamespace(id=101, username='fixture', is_superuser=admin)
        metadata = {'schema': 1, 'scheme': 'covercrypt', 'format': 'hybrid-v2',
                    'backend': 'native', 'pqc_signed': False}
        blob = bytes([2, 2]) + b'0' * 12 + struct.pack('<Q', 1) + b'A' + b'0' * 16
        with patch.object(views.cache, 'get', return_value=cache_get) as get, patch.object(views.cache, 'set') as save:
            result = views.UploadedFileViewSet()._decrypt_file_if_needed(
                blob, 'documents', 'fixture.txt', user, is_owner=owner,
                file_version=SimpleNamespace(cpabe_policy=policy, crypto_metadata=metadata))
        return result, get.call_args.args[0], save

    def test_non_strict_admin_without_dimensions_can_decrypt(self):
        result, key, _ = self.decrypt()
        self.assertEqual(result, b'plaintext-fixture')
        self.assertEqual(self.generated[0]['employment_status'], 'active')
        self.assertEqual(set(self.generated[0]), {'department', 'employment_status', 'user_type'})
        self.assertIn('covercrypt_bypass_v1_', key)

    def test_profile_superadmin_without_django_flag_can_bypass(self):
        with patch('crypto_access.services.document_access.is_document_administrator', return_value=True):
            self.decrypt(admin=False)
        self.assertEqual(self.generated[0]['employment_status'], 'active')

    def test_owner_retains_existing_non_strict_bypass(self):
        self.decrypt(admin=False, owner=True)
        self.assertEqual(self.generated[0]['employment_status'], 'active')

    def test_regular_user_cannot_receive_policy_satisfying_attributes(self):
        with self.assertRaises(PermissionDenied):
            self.decrypt(admin=False)
        self.assertEqual(self.generated, [{'user_type': 'super_admin'}])

    def test_strict_denied_even_with_owner_and_cached_key(self):
        self.strict.return_value = True
        with patch.object(views.casbin_service, 'check_file_access_with_fallback', return_value=(False, 'deny')):
            with self.assertRaises(PermissionDenied):
                self.decrypt(owner=True, cache_get=b'old-bypass-cache')
        self.crypto.generate_user_key.assert_not_called()
        self.crypto.decrypt_buffer.assert_not_called()

    def test_strict_allowed_still_requires_real_attributes(self):
        self.strict.return_value = True
        with patch.object(views.casbin_service, 'check_file_access_with_fallback', return_value=(True, 'allow')):
            with self.assertRaises(PermissionDenied):
                self.decrypt(owner=True)
        self.assertEqual(self.generated, [{'user_type': 'super_admin'}])

    def test_strict_real_attributes_use_separate_cache_namespace(self):
        self.strict.return_value = True
        attributes = {'user_type': 'super_admin', 'department': 'it', 'employment_status': 'active'}
        with patch.object(views.casbin_service, 'check_file_access_with_fallback', return_value=(True, 'allow')), patch.object(
                views.casbin_service, 'get_user_attributes', return_value=attributes):
            _, key, _ = self.decrypt(owner=True)
        self.assertIn('covercrypt_strict_v1_', key)
        self.assertNotIn('bypass', key)
        self.assertEqual(self.generated, [attributes])

    def test_unsatisfiable_policy_never_generates_or_decrypts(self):
        with self.assertRaises(PermissionDenied):
            self.decrypt(policy='department::it && department::hr')
        self.crypto.generate_user_key.assert_not_called()
        self.crypto.decrypt_buffer.assert_not_called()


class CoverCryptPolicySatisfactionTests(SimpleTestCase):
    def setUp(self):
        p = patch('crypto_access.services.covercrypt_policy.build_covercrypt_configuration', return_value=CONFIG)
        p.start()
        self.addCleanup(p.stop)

    def test_backtracks_across_or_to_satisfy_whole_expression(self):
        result = bypass_attributes({}, ['(department::it || department::hr) && department::hr'])
        self.assertEqual(result['department'], 'hr')

    def test_conflicting_and_cannot_be_satisfied(self):
        with self.assertRaisesRegex(ValueError, 'no consistent'):
            bypass_attributes({}, ['department::it && department::hr'])

    def test_complete_assignment_does_not_modify_original_attributes(self):
        original = {'user_type': 'super_admin', 'department': 'hr'}
        result = bypass_attributes(original, ['department::it'])
        self.assertEqual(original, {'user_type': 'super_admin', 'department': 'hr'})
        self.assertEqual(result, {'user_type': 'super_admin', 'department': 'it', 'employment_status': 'active'})

    def test_all_or_branches_are_validated_including_unselected_branch(self):
        with self.assertRaises(ValueError):
            bypass_attributes({}, ['department::it || department::unknown'])

    def test_unsupported_syntax_fails_closed(self):
        for policy in ('', 'department:it', 'not department::it', 'department::it + department::hr',
                       'department::it &&', '__import__(os)', 'unknown::value', 'department::IT',
                       'department::it || True', '(department::it'):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                bypass_attributes({}, [policy])

    def test_policy_size_and_nesting_are_bounded(self):
        for policy in ('(' * 33 + 'department::it' + ')' * 33, 'department::it ' * 400):
            with self.assertRaises(ValueError):
                bypass_attributes({}, [policy])

    def test_search_budget_is_bounded(self):
        policy = ' && '.join(['(department::it || department::it)'] * 20) + ' && department::hr'
        with self.assertRaisesRegex(ValueError, 'too complex'):
            bypass_attributes({}, [policy])
