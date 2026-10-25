from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from crypto_access.services.cpabe_service import CPABEError, CPABEService
from crypto_access.services.tkn20_policy import bypass_attributes
from crypto_access.views import storage as storage_views


class TKN20PolicyTests(SimpleTestCase):
    def test_policy_value_replaces_conflicting_super_admin_value(self):
        original = {'user_type': 'super_admin'}
        result = bypass_attributes(original, ['user_type:data_owner'])
        self.assertEqual(result, {'user_type': 'data_owner'})
        self.assertEqual(original, {'user_type': 'super_admin'})

    def test_or_selects_one_consistent_value(self):
        result = bypass_attributes({}, ['(department:it or department:hr) and department:hr'])
        self.assertEqual(result['department'], 'hr')

    def test_conflicting_and_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no consistent'):
            bypass_attributes({}, ['department:it and department:hr'])

    def test_negation_does_not_add_the_excluded_value(self):
        result = bypass_attributes({'role': 'intern'}, ['not (role:intern or role:contractor)'])
        self.assertNotIn(result['role'], ['intern', 'contractor'])

    def test_negated_branch_backtracks_with_positive_constraint(self):
        result = bypass_attributes({}, ['not (department:it and role:intern) and department:it'])
        self.assertEqual(result['department'], 'it')
        self.assertNotEqual(result['role'], 'intern')

    def test_contradictory_negative_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            bypass_attributes({}, ['role:intern and not role:intern'])

    def test_policy_case_matches_native_tkn20_normalization(self):
        self.assertEqual(bypass_attributes({}, ['USER_TYPE:DATA_OWNER']), {'user_type': 'data_owner'})

    def test_unsupported_syntax_is_rejected(self):
        for policy in ('user_type:data_owner + role:admin', '__import__(os)', '', 'user_type:data_owner and'):
            with self.subTest(policy=policy), self.assertRaises((ValueError, SyntaxError)):
                bypass_attributes({}, [policy])

    def test_expansion_preserves_one_value_and_is_deterministic(self):
        service = CPABEService.__new__(CPABEService)
        attrs = {'role': 'director', 'user_type': 'data_owner', 'clearance_level': 'top_secret'}
        result = service.expand_hierarchical_attributes(attrs, scheme='tkn20')
        self.assertEqual(result, ['clearance_level:top_secret', 'role:director', 'user_type:data_owner'])
        self.assertEqual(result, service.expand_hierarchical_attributes(dict(reversed(list(attrs.items()))), 'tkn20'))

    def test_tkn20_rejects_conflicting_multivalue_labels(self):
        service = CPABEService.__new__(CPABEService)
        with self.assertRaisesRegex(CPABEError, 'one value'):
            service.expand_hierarchical_attributes({'user_type': ['super_admin', 'data_owner']}, 'tkn20')

    def test_tkn20_rejects_case_colliding_labels(self):
        service = CPABEService.__new__(CPABEService)
        with self.assertRaises(CPABEError):
            service.expand_hierarchical_attributes({'Department': 'it', 'department': 'hr'}, 'tkn20')

    def test_ac17_hierarchy_is_preserved(self):
        service = CPABEService.__new__(CPABEService)
        result = service.expand_hierarchical_attributes({'role': 'director'}, 'ac17')
        self.assertEqual(result, ['role:director', 'role:employee', 'role:intern', 'role:manager'])


class TKN20DecryptionBypassTests(SimpleTestCase):
    def setUp(self):
        original_crypto = vars(storage_views)['cpabe_service']
        self.crypto = Mock()
        storage_views.cpabe_service = self.crypto
        self.addCleanup(setattr, storage_views, 'cpabe_service', original_crypto)
        self.generated = []

        def generate(attrs, output_path, scheme=None):
            self.generated.append((attrs, scheme))
            Path(output_path).write_bytes(b'test-only-user-key')

        self.crypto.generate_user_key.side_effect = generate
        self.crypto.decrypt_buffer.return_value = b'recovered'

    def decrypt(self, superuser=False, owner=False):
        user = SimpleNamespace(id=123, username='test-user', is_superuser=superuser)
        with patch.object(storage_views, 'get_db_file_by_path', return_value=SimpleNamespace(abe_scheme='tkn20')), patch(
            'crypto_access.views.storage.casbin_service.get_user_attributes', return_value={'user_type': 'super_admin'}
        ), patch.object(storage_views.cache, 'get', return_value=None), patch.object(
            storage_views.cache, 'set'
        ) as cache_set, patch('crypto_access.models.fields.encrypt_bytes', return_value=b'wrapped-test-key'):
            result = storage_views.UploadedFileViewSet()._decrypt_file_if_needed(
                b'test-ciphertext', 'documents', 'test.txt', user,
                is_owner=owner, cpabe_policy_str='user_type:data_owner',
            )
        return result, cache_set.call_args.args[0]

    def test_superuser_uses_policy_compatible_key_and_new_cache_namespace(self):
        result, cache_key = self.decrypt(superuser=True)
        self.assertEqual(result, b'recovered')
        self.assertEqual(self.generated, [({'user_type': 'data_owner'}, 'tkn20')])
        self.assertIn('tkn20_bypass_v2_', cache_key)

    def test_owner_uses_the_same_consistent_bypass(self):
        self.decrypt(owner=True)
        self.assertEqual(self.generated, [({'user_type': 'data_owner'}, 'tkn20')])

    def test_ordinary_user_attributes_are_not_forged(self):
        _, cache_key = self.decrypt()
        self.assertEqual(self.generated, [({'user_type': 'super_admin'}, 'tkn20')])
        self.assertNotIn('bypass_v2', cache_key)
