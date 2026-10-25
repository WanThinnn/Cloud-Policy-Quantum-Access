"""The strict switch must cover metadata, owner/grant shortcuts and raw file reads."""
from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from crypto_access.middleware.abac_middleware import ABACMiddleware
from crypto_access.models import (
    AccessPolicy, FileAccessPolicy, FileVersion, StorageBucket, SystemSetting, UploadedFile, UserProfile,
)
from crypto_access.services.casbin_service import casbin_service
from crypto_access.services.runtime_settings import get_runtime_setting
from crypto_access.views import storage as storage_views


class StrictSuperAdminTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser('strict_admin', email='test@example.com', password='test')
        UserProfile.objects.create(user=self.admin, user_type='super_admin')
        self.bucket = StorageBucket.objects.create(name='documents')
        self.file = UploadedFile.objects.create(
            bucket=self.bucket, file_path='private.txt', file_name='private.txt', uploaded_by=self.admin,
            file_size=4, mime_type='text/plain',
        )
        AccessPolicy.objects.create(name='admin_operations', resource='document', action='*', effect='allow',
                                    priority=1, subject_condition='r.sub.user_type == "super_admin"')
        self.file_policy = AccessPolicy.objects.create(
            name='it_only', resource='document', action='*', effect='allow', priority=10,
            subject_condition='r.sub.department == "it"',
        )
        self.link = FileAccessPolicy.objects.create(
            bucket=self.bucket, uploaded_file=self.file, policy=self.file_policy, target_type='file',
        )
        self.attrs = {'user_type': 'super_admin', 'department': 'hr'}
        patcher = patch.object(casbin_service, 'get_user_attributes', side_effect=lambda user: self.attrs.copy())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.storage = Mock()
        self.storage.download_file.return_value = b'plain-text'
        patcher = patch.object(storage_views, 'get_storage_service', return_value=self.storage)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def strict(self, enabled=True):
        # Deliberately do not run commit callbacks: security mode must ignore stale caches.
        SystemSetting.objects.update_or_create(key='SUPER_ADMIN_REQUIRE_POLICY', defaults={'value': enabled})

    def test_default_off_preserves_superuser_access(self):
        self.assertFalse(get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY'))
        self.assertTrue(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])

    def test_strict_nonmatching_owner_does_not_appear_in_browse_or_list(self):
        self.strict()
        self.assertFalse(casbin_service.check_file_access_with_fallback(self.admin, 'documents', 'private.txt')[0])
        self.assertEqual(self.client.get('/api/storage/files/browse/?bucket=documents').data['files'], [])
        response = self.client.get('/api/storage/files/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])

    def test_strict_read_paths_reject_before_storage_download_even_without_middleware(self):
        self.strict()
        for action in ('preview_by_path', 'download_by_path'):
            response = self.client.get(f'/api/storage/files/{action}/?bucket=documents&path=private.txt')
            self.assertEqual(response.status_code, 403)
        response = self.client.get(f'/api/storage/files/{self.file.pk}/download/')
        self.assertIn(response.status_code, (403, 404))
        self.storage.download_file.assert_not_called()

    def test_strict_matching_attributes_can_read_plaintext(self):
        self.strict()
        self.attrs['department'] = 'it'
        # Legacy plaintext version: authorization still applies before the crypto early return.
        FileVersion.objects.create(file=self.file, file_size=10, physical_path='private.txt', cpabe_policy='')
        response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=private.txt')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'plain-text')

    def test_inherited_folder_policy_is_enforced_in_browse(self):
        self.strict()
        self.file.file_path = 'team/private.txt'
        self.file.save()
        self.link.uploaded_file = None
        self.link.target_type = 'folder'
        self.link.folder_path = 'team/'
        self.link.save()
        self.assertEqual(self.client.get('/api/storage/files/browse/?bucket=documents').data['files'], [])

    def test_file_deny_priority_is_not_lost_in_listing(self):
        self.strict()
        self.attrs['department'] = 'it'
        deny = AccessPolicy.objects.create(
            name='deny_it', resource='document', action='*', effect='deny', priority=5,
            subject_condition='r.sub.department == "it"',
        )
        FileAccessPolicy.objects.create(bucket=self.bucket, uploaded_file=self.file, policy=deny, target_type='file')
        self.assertTrue(casbin_service.check_access(self.admin, 'document', 'read'))
        self.assertFalse(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])
        self.assertEqual(self.client.get('/api/storage/files/browse/?bucket=documents').data['files'], [])

    def test_switch_off_restores_access_after_strict_denial(self):
        self.strict()
        self.assertFalse(casbin_service.check_file_access_with_fallback(self.admin, 'documents', 'private.txt')[0])
        self.strict(False)
        self.assertTrue(casbin_service.check_file_access_with_fallback(self.admin, 'documents', 'private.txt')[0])

    def test_cached_false_flag_does_not_restore_bypass(self):
        cache.set('system_setting_SUPER_ADMIN_REQUIRE_POLICY', False)
        self.strict()
        self.assertTrue(get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY'))
        self.assertFalse(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])

    def test_owner_and_explicit_grant_do_not_skip_middleware_policy_checks(self):
        self.strict()
        self.link.granted_users.add(self.admin)
        request = RequestFactory().get('/api/storage/files/preview_by_path/?bucket=documents&path=private.txt')
        request.user = self.admin
        self.assertFalse(ABACMiddleware(lambda request: None)._check_file_ownership(request, 'read'))

    def test_admin_control_plane_stays_accessible(self):
        self.strict()
        self.assertTrue(casbin_service.check_access(self.admin, 'policy', '*'))
        self.assertTrue(casbin_service.check_access(self.admin, 'user', '*'))

    def test_superadmin_profile_without_superuser_flag_also_obeys_switch(self):
        self.admin.is_superuser = False
        self.admin.save()
        self.assertTrue(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])
        self.strict()
        self.assertFalse(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])

    def test_global_document_permission_is_required_when_strict(self):
        self.strict()
        AccessPolicy.objects.all().update(is_active=False)
        self.assertFalse(casbin_service.check_access(self.admin, 'document', 'read'))

    def test_invalid_active_flag_is_treated_as_strict(self):
        self.strict('false')
        self.assertTrue(get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY'))

    @override_settings(FIELD_ENCRYPTION=True)
    def test_encrypted_paths_do_not_drop_file_policy_checks(self):
        self.strict()
        self.file.save()  # Write encrypted metadata and its real blind index with the isolated test key.
        self.assertEqual(UploadedFile.find_by_path('documents', 'private.txt').pk, self.file.pk)
        self.assertIn(self.file_policy.pk, [p.pk for p in FileAccessPolicy.get_policies_for_file(
            'documents', 'private.txt')])
        self.assertFalse(casbin_service.check_file_access_with_fallback(self.admin, 'documents', 'private.txt')[0])
        response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=private.txt')
        self.assertEqual(response.status_code, 403)
        self.storage.download_file.assert_not_called()

    def test_unregistered_storage_path_is_not_read_in_strict_mode(self):
        self.strict()
        response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=orphan.txt')
        self.assertEqual(response.status_code, 403)
        self.storage.download_file.assert_not_called()

    def test_inactive_file_policy_cannot_authorize_strict_superadmin(self):
        self.strict()
        self.attrs['department'] = 'it'
        AccessPolicy.objects.filter(pk=self.file_policy.pk).update(is_active=False)
        self.assertFalse(casbin_service.check_file_access(self.admin, 'documents', 'private.txt')[0])
