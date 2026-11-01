from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from rest_framework.test import APIClient

from crypto_access.models import AccessPolicy, FileAccessPolicy, StorageBucket, UploadedFile, UserProfile, UserType
from crypto_access.views import storage as storage_views


class InlinePolicyTests(TestCase):
    def setUp(self):
        # mock.patch inspects the original object, which would initialize this lazy
        # native service. Replace it without introspection before using any patches.
        original_crypto = vars(storage_views)['cpabe_service']
        storage_views.cpabe_service = Mock()
        storage_views.cpabe_service.encrypt_version.return_value = (b'ciphertext', {
            'schema': 1, 'scheme': 'ac17', 'format': 'hybrid-v2', 'backend': 'native', 'pqc_signed': False,
        })
        self.addCleanup(setattr, storage_views, 'cpabe_service', original_crypto)
        self.client = APIClient()
        self.owner = User.objects.create_user(username='owner')
        self.other = User.objects.create_user(username='other')
        self.admin = User.objects.create_superuser(username='super_admin', email='test@example.local')
        role = UserType.objects.create(code='super_admin', name='Super Admin')
        UserProfile.objects.create(user=self.admin, user_type='super_admin', user_type_ref=role)
        self.bucket = StorageBucket.objects.create(name='documents')
        self.file = UploadedFile.objects.create(
            bucket=self.bucket, file_path='report.txt', file_name='report.txt',
            file_size=4, mime_type='text/plain', uploaded_by=self.owner,
        )
        self.inline = {
            'bucket_name': 'documents', 'file_path': 'report.txt', 'target_type': 'file',
            'create_new_policy': True, 'new_policy_name': 'inline_policy',
            'new_policy_subject_condition': 'r.sub.department == "it"',
            'new_policy_effect': 'allow', 'new_policy_resource': '*', 'new_policy_action': '*',
        }

    def assign(self, user, data=None):
        self.client.force_authenticate(user)
        return self.client.post('/api/storage/files/assign_policy/', data or self.inline, format='json')

    def test_nonowner_denied_without_creating_global_policy(self):
        response = self.assign(self.other)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AccessPolicy.objects.exists())
        self.assertFalse(FileAccessPolicy.objects.exists())

    def test_owner_cannot_create_global_policy(self):
        response = self.assign(self.owner)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AccessPolicy.objects.exists())
        self.assertFalse(FileAccessPolicy.objects.exists())

    def test_missing_target_does_not_create_policy(self):
        response = self.assign(self.admin, {**self.inline, 'file_path': 'missing.txt'})
        self.assertEqual(response.status_code, 404)
        self.assertFalse(AccessPolicy.objects.exists())

    def test_global_policy_abac_denial_applies_to_super_admin_role(self):
        with patch('crypto_access.views.storage.casbin_service.check_access', return_value=False):
            response = self.assign(self.admin)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AccessPolicy.objects.exists())

    def test_authorized_admin_can_create_and_assign_folder_policy(self):
        response = self.assign(self.admin, {**self.inline, 'target_type': 'folder', 'file_path': 'team'})
        self.assertEqual(response.status_code, 201, response.data)
        policy = AccessPolicy.objects.get(name='inline_policy')
        self.assertEqual(policy.created_by, self.admin)
        self.assertTrue(FileAccessPolicy.objects.filter(policy=policy, folder_path='team/').exists())

    def test_owner_can_assign_existing_policy(self):
        policy = AccessPolicy.objects.create(name='existing', subject_condition='', resource='document', action='read')
        response = self.assign(self.owner, {
            'bucket_name': 'documents', 'file_path': 'report.txt', 'policy_id': policy.pk,
        })
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(AccessPolicy.objects.count(), 1)
        self.assertTrue(FileAccessPolicy.objects.filter(uploaded_file=self.file, policy=policy).exists())

    def test_failed_encryption_rolls_back_policy_and_assignment(self):
        storage = Mock()
        storage.download_file.return_value = b'data'
        crypto = Mock()
        crypto.encrypt_version.side_effect = RuntimeError('test encryption failure')
        with patch('crypto_access.views.storage.get_storage_service', return_value=storage), patch(
            'crypto_access.views.storage.cpabe_service', crypto
        ):
            response = self.assign(self.admin)
        self.assertEqual(response.status_code, 500)
        crypto.encrypt_version.assert_called_once()
        self.assertFalse(AccessPolicy.objects.exists())
        self.assertFalse(FileAccessPolicy.objects.exists())

    def test_upload_denies_global_policy_for_owner_before_storage(self):
        self.client.force_authenticate(self.owner)
        with patch('crypto_access.views.storage.get_storage_service') as storage:
            response = self.client.post('/api/storage/files/upload/', {
                **self.inline, 'file': SimpleUploadedFile('upload.txt', b'data'),
            }, format='multipart')
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AccessPolicy.objects.exists())
        storage.assert_not_called()

    def test_failed_upload_leaves_no_inline_policy(self):
        self.client.force_authenticate(self.admin)
        with patch('crypto_access.views.storage.get_storage_service'), patch(
            'crypto_access.services.clamav_service.clamav_service.scan_file_buffer', return_value=(False, 'test rejection')
        ):
            response = self.client.post('/api/storage/files/upload/', {
                **self.inline, 'file_path': 'new.txt', 'file': SimpleUploadedFile('new.txt', b'data'),
            }, format='multipart')
        self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(AccessPolicy.objects.exists())

    def test_authorized_upload_persists_policy_with_creator(self):
        self.client.force_authenticate(self.admin)
        storage = Mock()
        storage.create_signed_url.return_value = 'https://example.local/test-only'
        crypto = Mock()
        crypto.encrypt_version.return_value = (b'ciphertext', {
            'schema': 1, 'scheme': 'ac17', 'format': 'hybrid-v2', 'backend': 'native', 'pqc_signed': False,
        })
        with patch('crypto_access.views.storage.get_storage_service', return_value=storage), patch(
            'crypto_access.views.storage.cpabe_service', crypto
        ), patch(
            'crypto_access.services.clamav_service.clamav_service.scan_file_buffer', return_value=(True, 'clean')
        ):
            response = self.client.post('/api/storage/files/upload/', {
                **self.inline, 'file_path': 'new.txt', 'file': SimpleUploadedFile('new.txt', b'data'),
            }, format='multipart')
        self.assertEqual(response.status_code, 201, response.data)
        policy = AccessPolicy.objects.get(name='inline_policy')
        self.assertEqual(policy.created_by, self.admin)
        self.assertTrue(FileAccessPolicy.objects.filter(policy=policy, uploaded_file__file_path='new.txt').exists())

    def test_assignment_error_during_upload_rolls_back_all_metadata(self):
        self.client.force_authenticate(self.admin)
        storage = Mock()
        storage.create_signed_url.return_value = 'https://example.local/test-only'
        with patch('crypto_access.views.storage.get_storage_service', return_value=storage), patch(
            'crypto_access.views.storage.cpabe_service'
        ) as crypto, patch(
            'crypto_access.services.clamav_service.clamav_service.scan_file_buffer', return_value=(True, 'clean')
        ), patch(
            'crypto_access.views.storage.FileAccessPolicy.objects.create', side_effect=RuntimeError('assignment failure')
        ):
            crypto.encrypt_version.return_value = (b'ciphertext', {
                'schema': 1, 'scheme': 'ac17', 'format': 'hybrid-v2', 'backend': 'native', 'pqc_signed': False,
            })
            response = self.client.post('/api/storage/files/upload/', {
                **self.inline, 'file_path': 'new.txt', 'file': SimpleUploadedFile('new.txt', b'data'),
            }, format='multipart')
        self.assertEqual(response.status_code, 500)
        self.assertFalse(AccessPolicy.objects.exists())
        self.assertFalse(FileAccessPolicy.objects.exists())
        self.assertEqual(UploadedFile.objects.count(), 1)

    def test_name_only_upload_cannot_use_legacy_creation_path(self):
        self.client.force_authenticate(self.owner)
        response = self.client.post('/api/storage/files/upload/', {
            'bucket_name': 'documents', 'new_policy_name': 'legacy',
            'file': SimpleUploadedFile('upload.txt', b'data'),
        }, format='multipart')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AccessPolicy.objects.exists())

    def test_inline_policy_uses_management_api_validation(self):
        response = self.assign(self.admin, {**self.inline, 'new_policy_name': 'INVALID NAME'})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AccessPolicy.objects.exists())

    def test_ambiguous_policy_selection_is_rejected(self):
        response = self.assign(self.admin, {**self.inline, 'policy_id': 1})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(AccessPolicy.objects.exists())
