import base64
import json
import struct
import hashlib
import io
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command, CommandError
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from crypto_access.models import AccessPolicy, FileAccessPolicy, FileVersion, StorageBucket, UploadedFile, UserProfile
from crypto_access.views import storage as storage_views


def metadata(scheme='ac17', signed=False):
    return {'schema': 1, 'scheme': scheme, 'format': 'hybrid-v2', 'pqc_signed': signed, 'backend': 'native'}


class FakeCrypto:
    """Typed ciphertext boundary: rejects the exact wrong-scheme/wrong-verifier bug."""
    use_vault_plugin = False

    def encode(self, plain, scheme, signed):
        header = bytes([2, {'ac17': 0, 'tkn20': 1}[scheme]]) + b'0' * 12 + struct.pack('<Q', 1) + b'A'
        return header + json.dumps({'data': base64.b64encode(plain).decode(), 'signed': signed}).encode() + b'0' * 16

    def encrypt_buffer(self, data, policy, scheme=None):
        return self.encode(data, scheme, False)

    def encrypt_buffer_and_sign(self, data, policy, scheme=None):
        return self.encode(data, scheme, True)

    def encrypt_version(self, data, policy, scheme, pqc_signed):
        return self.encode(data, scheme, pqc_signed), metadata(scheme, pqc_signed)

    def generate_user_key(self, attrs, output_path, scheme=None):
        Path(output_path).write_bytes(b'isolated-key')

    def decode(self, data, scheme, verify):
        actual = {0: 'ac17', 1: 'tkn20'}[data[1]]
        if scheme != actual:
            raise ValueError('Wrong scheme selected for historical version')
        payload = json.loads(data[23:-16])
        if payload['signed'] != verify:
            raise ValueError('Wrong signature mode selected for historical version')
        return base64.b64decode(payload['data'])

    def decrypt_buffer(self, key, data, scheme=None):
        return self.decode(data, scheme, False)

    def decrypt_buffer_and_verify(self, key, data, scheme=None):
        return self.decode(data, scheme, True)


class VersionCryptoTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser('version_admin', email='test@example.com')
        UserProfile.objects.create(user=self.admin, user_type='super_admin')
        self.bucket = StorageBucket.objects.create(name='documents')
        self.file = UploadedFile.objects.create(bucket=self.bucket, file_path='report.txt', file_name='report.txt',
                                                file_size=2, uploaded_by=self.admin, abe_scheme='tkn20')
        self.crypto = FakeCrypto()
        original = vars(storage_views)['cpabe_service']
        storage_views.cpabe_service = self.crypto
        self.addCleanup(setattr, storage_views, 'cpabe_service', original)
        self.blobs = {}
        from unittest.mock import Mock
        self.storage = Mock()
        self.storage.download_file.side_effect = lambda bucket_name, file_path, user=None: self.blobs[file_path]
        def upload(**kwargs):
            self.blobs[kwargs['file_path']] = kwargs['file_data']
            return {}
        self.storage.upload_file.side_effect = upload
        self.storage.copy_file.side_effect = lambda bucket, source, target: self.blobs.update({target: self.blobs[source]})
        self.storage.create_signed_url.return_value = 'https://example.local/test-only'
        patcher = patch.object(storage_views, 'get_storage_service', return_value=self.storage)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def version(self, number, scheme, signed=False):
        path = f'report_v{number}.txt'
        self.blobs[path] = self.crypto.encode(f'version-{number}'.encode(), scheme, signed)
        return FileVersion.objects.create(file=self.file, version_number=number, physical_path=path, file_size=9,
                                          cpabe_policy='user_type:super_admin', crypto_metadata=metadata(scheme, signed))

    def test_historical_version_uses_its_own_scheme_on_all_download_routes(self):
        self.version(1, 'ac17')
        self.version(2, 'tkn20')
        for path in (
            f'/api/storage/files/{self.file.pk}/download/?version=1',
            '/api/storage/files/download_by_path/?bucket=documents&path=report.txt&version=1',
            '/api/storage/files/preview_by_path/?bucket=documents&path=report.txt&version=1',
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
            self.assertEqual(response.content, b'version-1')

    def test_signature_mode_does_not_follow_the_current_feature_flag(self):
        self.version(1, 'ac17', signed=True)
        self.version(2, 'tkn20', signed=False)
        for number, current_flag in ((1, False), (2, True)):
            with override_settings(ENABLE_PQC_FEATURES=current_flag):
                response = self.client.get(
                    f'/api/storage/files/preview_by_path/?bucket=documents&path=report.txt&version={number}')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, f'version-{number}'.encode())

    def test_upload_ac17_then_tkn20_retains_both_versions(self):
        self.file.delete()
        policy = AccessPolicy.objects.create(name='version_policy', subject_condition='r.sub.user_type == "super_admin"',
                                             resource='document', action='*', effect='allow')
        for number, scheme, signed in ((1, 'ac17', True), (2, 'tkn20', False)):
            with override_settings(CPABE_SCHEME=scheme, ENABLE_PQC_FEATURES=signed):
                with patch('crypto_access.services.clamav_service.clamav_service.scan_file_buffer',
                           return_value=(True, 'clean')):
                    response = self.client.post('/api/storage/files/upload/', {
                        'file': SimpleUploadedFile('report.txt', f'upload-{number}'.encode(), content_type='text/plain'),
                        'file_path': 'report.txt', 'bucket_name': 'documents', 'policy_id': policy.pk,
                    }, format='multipart')
            self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'report.txt')
        self.assertEqual(file.versions.count(), 2)
        self.assertEqual(file.versions.get(version_number=1).crypto_metadata, metadata('ac17', True))
        self.assertEqual(file.versions.get(version_number=2).crypto_metadata, metadata('tkn20', False))
        for number in (1, 2):
            response = self.client.get(
                f'/api/storage/files/preview_by_path/?bucket=documents&path=report.txt&version={number}')
            self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
            self.assertEqual(response.content, f'upload-{number}'.encode())

    def test_policy_replacement_adds_version_without_overwriting_history(self):
        original = self.version(1, 'ac17', signed=True)
        source_blob = self.blobs[original.physical_path]
        old_policy = AccessPolicy.objects.create(name='old_policy', subject_condition='r.sub.user_type == "super_admin"',
                                                 resource='document', action='*', effect='allow')
        new_policy = AccessPolicy.objects.create(name='new_policy', subject_condition='r.sub.department == "it"',
                                                 resource='document', action='*', effect='allow')
        FileAccessPolicy.objects.create(uploaded_file=self.file, bucket=self.bucket, policy=old_policy)
        with override_settings(CPABE_SCHEME='tkn20', ENABLE_PQC_FEATURES=False):
            response = self.client.post('/api/storage/files/assign_policy/', {
                'bucket_name': 'documents', 'file_path': 'report.txt', 'target_type': 'file',
                'policy_id': new_policy.pk, 'replace': True,
            }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        original.refresh_from_db()
        self.assertEqual(original.crypto_metadata, metadata('ac17', True))
        self.assertEqual(self.blobs[original.physical_path], source_blob)
        self.storage.delete_file.assert_not_called()
        self.assertEqual(self.file.versions.count(), 2)
        self.assertEqual(self.file.get_latest_version().crypto_metadata, metadata('tkn20', False))
        for number in (1, 2):
            response = self.client.get(f'/api/storage/files/{self.file.pk}/download/?version={number}')
            self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
            self.assertEqual(response.content, b'version-1')

    def test_copy_latest_version_preserves_crypto_metadata_and_policy(self):
        source = self.version(1, 'ac17', signed=True)
        policy = AccessPolicy.objects.create(name='copy_policy', subject_condition='r.sub.user_type == "super_admin"',
                                             resource='document', action='*', effect='allow')
        FileAccessPolicy.objects.create(uploaded_file=self.file, bucket=self.bucket, policy=policy)
        response = self.client.post('/api/storage/files/clipboard_action/', {
            'action': 'copy', 'bucket_name': 'documents', 'items': ['report.txt'], 'destination': 'copies',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        copied = UploadedFile.objects.exclude(pk=self.file.pk).get()
        self.assertEqual(copied.get_latest_version().crypto_metadata, source.crypto_metadata)
        self.assertTrue(copied.access_policies.filter(policy=policy, bucket=self.bucket).exists())
        response = self.client.get(f'/api/storage/files/{copied.pk}/download/')
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        self.assertEqual(response.content, b'version-1')

    def test_signed_legacy_version_is_recovered_from_verified_ciphertext_not_current_scheme(self):
        old = self.version(1, 'ac17', signed=True)
        FileVersion.objects.filter(pk=old.pk).update(crypto_metadata={})
        with override_settings(CPABE_SCHEME='tkn20', ENABLE_PQC_FEATURES=False):
            response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=report.txt')
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        old.refresh_from_db()
        self.assertEqual(old.crypto_metadata, metadata('ac17', True))

    def test_unknown_unsigned_legacy_is_not_guessed_or_returned_as_plaintext(self):
        old = self.version(1, 'ac17', signed=False)
        FileVersion.objects.filter(pk=old.pk).update(crypto_metadata={})
        response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=report.txt')
        self.assertEqual(response.status_code, 409)
        old.refresh_from_db()
        self.assertEqual(old.crypto_metadata, {})

    def test_metadata_ciphertext_mismatch_is_rejected(self):
        old = self.version(1, 'ac17')
        FileVersion.objects.filter(pk=old.pk).update(crypto_metadata=metadata('tkn20'))
        response = self.client.get('/api/storage/files/preview_by_path/?bucket=documents&path=report.txt')
        self.assertEqual(response.status_code, 409)

    def test_recovery_manifest_is_dry_run_and_checks_the_blob_hash(self):
        old = self.version(1, 'ac17')
        FileVersion.objects.filter(pk=old.pk).update(crypto_metadata={})
        manifest = [{'version_id': old.pk, 'crypto_metadata': metadata('ac17'), 'evidence': 'isolated write record',
                     'ciphertext_sha256': hashlib.sha256(self.blobs[old.physical_path]).hexdigest()}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            path.write_text(json.dumps(manifest))
            with patch('crypto_access.management.commands.backfill_crypto_metadata.get_storage_service',
                       return_value=self.storage):
                call_command('backfill_crypto_metadata', manifest=path, stdout=io.StringIO())
                old.refresh_from_db()
                self.assertEqual(old.crypto_metadata, {})
                manifest[0]['ciphertext_sha256'] = '0' * 64
                path.write_text(json.dumps(manifest))
                with self.assertRaises(CommandError):
                    call_command('backfill_crypto_metadata', manifest=path, apply=True, stdout=io.StringIO())
                old.refresh_from_db()
                self.assertEqual(old.crypto_metadata, {})
                manifest[0]['ciphertext_sha256'] = hashlib.sha256(self.blobs[old.physical_path]).hexdigest()
                path.write_text(json.dumps(manifest))
                call_command('backfill_crypto_metadata', manifest=path, apply=True, stdout=io.StringIO())
                old.refresh_from_db()
                self.assertEqual(old.crypto_metadata, metadata('ac17'))
