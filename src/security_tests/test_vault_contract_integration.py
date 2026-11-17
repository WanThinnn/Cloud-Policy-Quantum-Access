"""Opt-in CPQA/Vault integration. Run only through tests/smoke_vault_contract.py."""
import json
import os
from dataclasses import replace
from pathlib import Path
import tempfile
from unittest import skipUnless
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

import hvac
import requests
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from io import StringIO
from rest_framework.test import APIClient

from crypto_access.models import AccessPolicy, AttributeDefinition, FileVersion, StorageBucket, UploadedFile, UserAttribute, UserProfile
from crypto_access.services import cpabe_service as crypto_module
from crypto_access.services.cpabe_service import CPABEService, CPABEError
from crypto_access.services.covercrypt_config import build_covercrypt_configuration
from crypto_access.services.covercrypt_public_key import public_key_fingerprint
from crypto_access.services.vault_service import VaultService
from crypto_access.throttles import CPABEDecryptThrottle, CPABEEncryptThrottle
from crypto_access.views import storage as storage_views


@skipUnless(os.environ.get('CPQA_TEST_VAULT_ADDR'), 'requires the disposable Vault contract runner')
@override_settings(USE_VAULT_ABE_PLUGIN=True, ENABLE_PQC_FEATURES=True, CPABE_SCHEME='covercrypt',
                   VAULT_ABE_INTERNAL_DECRYPT=os.environ.get('CPQA_TEST_INTERNAL_DECRYPT') == '1')
class VaultContractIntegrationTests(TestCase):
    def setUp(self):
        address = os.environ['CPQA_TEST_VAULT_ADDR']
        if urlsplit(address).hostname != 'fixture-abe' or urlsplit(address).scheme != 'http':
            raise RuntimeError('Integration tests require the runner-owned fixture-abe Docker network alias.')
        cache.clear()
        self.vault = object.__new__(VaultService)
        self.vault.vault_addr = address
        self.vault.vault_token = os.environ['CPQA_TEST_VAULT_TOKEN']
        self.vault.secret_path = 'secret/data/isolated-contract'
        self.vault._cache = {}
        self.vault.client = hvac.Client(url=address, token=self.vault.vault_token)
        self.service = CPABEService.vault_metadata_client()
        self.service.pk_data = b''
        patcher = patch.object(crypto_module, 'vault_service', self.vault)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(storage_views, 'cpabe_service', self.service)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.department = AttributeDefinition.objects.create(
            name='department', display_name='Department', data_type='enum', allowed_values=['it', 'hr'],
        )
        self.admin = User.objects.create_superuser('contract_admin', email='test@example.com')
        UserProfile.objects.create(user=self.admin, user_type='super_admin')
        self.bucket = StorageBucket.objects.create(name='documents')
        headers = {'X-Vault-Token': self.vault.get_token}
        for scheme in ('ac17', 'tkn20'):
            self.service._ensure_classical_vault_keyset(scheme, headers, True)
        self.service._ensure_covercrypt_keyset(True, headers)
        self.storage = Mock()
        self.blobs = {}
        self.storage.upload_file.side_effect = lambda **kw: self.blobs.update({kw['file_path']: kw['file_data']}) or {}
        self.storage.download_file.side_effect = lambda bucket_name, file_path, user=None: self.blobs[file_path]
        self.storage.copy_file.side_effect = lambda bucket, source, target: self.blobs.update({target: self.blobs[source]})
        self.storage.create_signed_url.return_value = 'https://fixture.invalid/blob'
        for patcher in (patch.object(storage_views, 'get_storage_service', return_value=self.storage),
                        patch('crypto_access.services.clamav_service.clamav_service.scan_file_buffer', return_value=(True, 'fixture-clean')),
                        # Six versions exceed the default per-minute crypto throttles; rate limits are tested elsewhere.
                        patch.object(CPABEEncryptThrottle, 'allow_request', return_value=True),
                        patch.object(CPABEDecryptThrottle, 'allow_request', return_value=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def policy(self, name):
        return AccessPolicy.objects.create(name=name, subject_condition='r.sub.department == "it"',
                                           resource='document', action='*', effect='allow')

    def upload(self, policy, number=1):
        return self.client.post('/api/storage/files/upload/', {
            'file': SimpleUploadedFile('contract.txt', f'isolated-version-{number}'.encode(), content_type='text/plain'),
            'file_path': 'contract.txt', 'bucket_name': 'documents', 'policy_id': policy.pk,
            'is_new_version': str(number > 1).lower(),
        }, format='multipart')

    def test_mixed_versions_upload_download_copy_and_policy_assignment(self):
        number = 0
        for scheme in ('ac17', 'tkn20', 'covercrypt'):
            for signed in (False, True):
                number += 1
                with override_settings(CPABE_SCHEME=scheme, ENABLE_PQC_FEATURES=signed):
                    response = self.upload(self.policy(f'contract_policy_{number}'), number)
                self.assertEqual(response.status_code, 201, getattr(response, 'data', None))
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        self.assertEqual(file.versions.count(), 6)
        for version in file.versions.all():
            value = version.crypto_metadata
            self.assertEqual(value['schema'], 2)
            self.assertEqual(value['contract_version'], 1)
            self.assertEqual(len(value['keyset_id']), 64)
            response = self.client.get(f'/api/storage/files/{file.pk}/download/?version={version.version_number}')
            self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
            self.assertEqual(response.content, f'isolated-version-{version.version_number}'.encode())
        original = file.get_latest_version()
        original_metadata = dict(original.crypto_metadata)
        response = self.client.post('/api/storage/files/clipboard_action/', {
            'action': 'copy', 'bucket_name': 'documents', 'items': ['contract.txt'], 'destination': 'copies',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        copied = UploadedFile.objects.exclude(pk=file.pk).get()
        self.assertEqual(copied.get_latest_version().crypto_metadata, original_metadata)
        response = self.client.get(f'/api/storage/files/{copied.pk}/download/')
        self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
        self.assertEqual(response.content, b'isolated-version-6')
        policy = self.policy('replacement_policy')
        with override_settings(CPABE_SCHEME='ac17', ENABLE_PQC_FEATURES=False):
            response = self.client.post('/api/storage/files/assign_policy/', {
                'bucket_name': 'documents', 'file_path': 'contract.txt', 'target_type': 'file',
                'policy_id': policy.pk, 'replace': True,
            }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        original.refresh_from_db()
        self.assertEqual(original.crypto_metadata, original_metadata)
        self.assertEqual(file.get_latest_version().crypto_metadata['scheme'], 'ac17')

    def test_download_denies_regular_user_after_attribute_change(self):
        response = self.upload(self.policy('department_policy'))
        self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        reader = User.objects.create_user('contract_reader')
        UserProfile.objects.create(user=reader, user_type='data_user')
        grant = UserAttribute.objects.create(user=reader, attribute=self.department, value='it')
        self.client.force_authenticate(reader)
        url = f'/api/storage/files/{file.pk}/download/'
        result = self.client.get(url)
        self.assertEqual(result.status_code, 200, getattr(result, 'data', None))
        self.assertEqual(result.content, b'isolated-version-1')
        grant.value = 'hr'
        grant.save(update_fields=['value'])
        denied = self.client.get(url)
        self.assertIn(denied.status_code, (403, 404))

    def test_preview_and_download_do_not_use_files_or_cached_vault_keys(self):
        response = self.upload(self.policy('memory_only_policy'))
        self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        with (patch.object(storage_views.tempfile, 'NamedTemporaryFile') as key_file,
              patch.object(self.service, 'generate_user_key', side_effect=AssertionError('file-based keygen')),
              patch.object(storage_views.UploadedFileViewSet, '_native_user_key',
                           side_effect=AssertionError('existing cache must never be read in Vault mode')),
              patch.object(self.service, 'generate_user_key_bytes', wraps=self.service.generate_user_key_bytes) as keygen):
            for url in (f'/api/storage/files/{file.pk}/download/',
                        '/api/storage/files/preview_by_path/?path=contract.txt&bucket=documents'):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200, getattr(response, 'data', None))
            key_file.assert_not_called()
            self.assertEqual(keygen.call_count, 0 if os.environ.get('CPQA_TEST_INTERNAL_DECRYPT') == '1' else 2)

    @skipUnless(os.environ.get('CPQA_TEST_INTERNAL_DECRYPT') == '1', 'requires internal-decrypt plugin')
    def test_runtime_token_can_decrypt_without_user_key_export(self):
        from runpy import run_path

        provision = run_path('/tmp/fixture_vault_operator.py')['provision']
        response = self.upload(self.policy('least_privilege_policy'))
        self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        self.assertTrue(self.vault.put_secrets({
            'MASTER_FIELD_ENCRYPTION_KEY': 'fixture-field-key',
            'CPABE_MSK': 'operator-only-fixture',
        }))
        token = provision(self.vault.client, 'isolated-contract', False, [])
        runtime = object.__new__(VaultService)
        runtime.runtime_only = True
        runtime._runtime_token_verified = False
        runtime.vault_addr = self.vault.get_addr
        runtime.vault_token = token
        runtime.secret_path = 'secret/data/cpqa-runtime'
        runtime._cache = {}
        runtime.client = hvac.Client(url=runtime.vault_addr, token=token)
        self.assertEqual(runtime.get_token, token)
        self.assertEqual(runtime.get_secrets(['CPABE_MSK']), {})
        for endpoint in ('setup', 'genkey', 'decrypt', 'add_dimension'):
            denied = requests.put(f'{runtime.get_addr}/v1/abe_covercrypt/{endpoint}',
                                  headers={'X-Vault-Token': token}, json={}, timeout=5)
            self.assertEqual(denied.status_code, 403)
        with self.assertRaises(hvac.exceptions.Forbidden):
            runtime.client.secrets.kv.v2.read_secret_version(path='isolated-contract', raise_on_deleted_version=True)
        with (patch.object(crypto_module, 'vault_service', runtime),
              patch.object(self.service, 'generate_user_key_bytes', side_effect=AssertionError('USK export'))):
            downloaded = self.client.get(f'/api/storage/files/{file.pk}/download/')
        self.assertEqual(downloaded.status_code, 200, getattr(downloaded, 'data', None))
        self.assertEqual(downloaded.content, b'isolated-version-1')

    def test_failed_setup_never_uploads_plaintext(self):
        with patch.object(self.service, '_ensure_covercrypt_keyset', side_effect=CPABEError('fixture setup failure')):
            response = self.upload(self.policy('failed_setup_policy'))
        self.assertEqual(response.status_code, 500)
        self.storage.upload_file.assert_not_called()
        self.assertEqual(FileVersion.objects.count(), 0)

    def test_real_covercrypt_allow_deny_and_signature(self):
        cipher, metadata = self.service.encrypt_version(b'isolated-round-trip', 'department::it', 'covercrypt', True)
        route = self.service.verify_version_authority(metadata)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'user.key')
            for department, allowed in (('it', True), ('hr', False)):
                self.service.generate_user_key({'department': department, 'user_type': 'super_admin'}, path, scheme='covercrypt')
                key = Path(path).read_bytes()
                if allowed:
                    self.assertEqual(self.service.decrypt_buffer_and_verify(key, cipher, scheme='covercrypt'), b'isolated-round-trip')
                    wrong_verifier = self.vault.get_secret('PQC_PK_AC17')
                    wrong_route = replace(route, authority=replace(route.authority, verifier=wrong_verifier))
                    with self.assertRaises(CPABEError):
                        self.service.decrypt_buffer_and_verify(key, cipher, scheme='covercrypt', route=wrong_route)
                else:
                    with self.assertRaises(CPABEError):
                        self.service.decrypt_buffer_and_verify(key, cipher, scheme='covercrypt')

    def test_interrupted_initialization_recovers_without_setup(self):
        before = self.vault.get_secrets([crypto_module.COVERCRYPT_PUBLIC_KEY_KEY, crypto_module.COVERCRYPT_PQC_PUBLIC_KEY_KEY])
        fingerprint = public_key_fingerprint(before[crypto_module.COVERCRYPT_PUBLIC_KEY_KEY])
        configuration = build_covercrypt_configuration()
        self.assertTrue(self.vault.put_secrets({
            crypto_module.COVERCRYPT_PUBLIC_KEY_KEY: None, crypto_module.COVERCRYPT_PQC_PUBLIC_KEY_KEY: None,
            crypto_module.COVERCRYPT_MANIFEST_KEY: None,
            crypto_module.COVERCRYPT_INIT_MARKER_KEY: json.dumps({'status': 'initializing', 'config_fingerprint': configuration.fingerprint}),
        }))
        with patch.object(crypto_module.requests, 'put', side_effect=AssertionError('recovery must not call setup')):
            key = self.service._ensure_covercrypt_keyset(True, {'X-Vault-Token': self.vault.get_token}, allow_setup=False)
        self.assertEqual(public_key_fingerprint(key), fingerprint)
        self.assertEqual(self.vault.get_secret(crypto_module.COVERCRYPT_PQC_PUBLIC_KEY_KEY), before[crypto_module.COVERCRYPT_PQC_PUBLIC_KEY_KEY])

    def test_vault_outage_never_uploads_plaintext(self):
        policy = self.policy('outage_policy')
        with patch.object(crypto_module.requests, 'get', side_effect=requests.ConnectionError('isolated fixture outage')):
            response = self.upload(policy)
        self.assertEqual(response.status_code, 500)
        self.storage.upload_file.assert_not_called()
        self.assertEqual(FileVersion.objects.count(), 0)

    def test_keygen_outage_returns_service_unavailable_without_plaintext(self):
        response = self.upload(self.policy('keygen_outage_policy'))
        self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        with patch.object(crypto_module.requests, 'put', side_effect=requests.Timeout('private-fixture')):
            response = self.client.get(f'/api/storage/files/{file.pk}/download/')
        self.assertEqual(response.status_code, 503, response.data)
        self.assertNotIn(b'private-fixture', response.content)
        self.assertNotIn(b'isolated-version-1', response.content)

    @skipUnless(os.environ.get('CPQA_TEST_RESTORE_SHARE'), 'requires a disposable restore fixture')
    def test_disposable_backup_restore_drill(self):
        from django.core import serializers
        from time import monotonic, sleep

        response = self.upload(self.policy('disposable_backup_policy'))
        self.assertEqual(response.status_code, 201, response.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        version = file.get_latest_version()
        db_backup = serializers.serialize('json', [version])
        blob_backup = bytes(self.blobs[version.physical_path])
        uri = f'{self.vault.get_addr}/v1/sys/storage/raft/snapshot'
        headers = {'X-Vault-Token': self.vault.get_token}
        self.assertTrue(self.vault.put_secrets({'FIXTURE_RESTORE_GENERATION': 'saved'}))
        snapshot = requests.get(uri, headers=headers, timeout=90)
        snapshot.raise_for_status()
        self.assertTrue(self.vault.put_secrets({'FIXTURE_RESTORE_GENERATION': 'modified'}))
        self.blobs.pop(version.physical_path)
        file.versions.filter(pk=version.pk).delete()

        started = monotonic()
        restored = requests.post(uri, headers=headers, data=snapshot.content, timeout=90)
        restored.raise_for_status()
        deadline = monotonic() + 35
        while monotonic() < deadline:
            try:
                if self.vault.client.sys.is_sealed():
                    self.vault.client.sys.submit_unseal_key(os.environ['CPQA_TEST_RESTORE_SHARE'])
                if self.vault.get_secrets(['FIXTURE_RESTORE_GENERATION']).get('FIXTURE_RESTORE_GENERATION') == 'saved':
                    break
            except (hvac.exceptions.VaultError, requests.RequestException, RuntimeError):
                pass
            sleep(0.3)
        else:
            self.fail('Restored Raft snapshot did not become available')
        for obj in serializers.deserialize('json', db_backup):
            obj.save()
        self.blobs[version.physical_path] = blob_backup
        url = f'/api/storage/files/{file.pk}/download/'
        downloaded = self.client.get(url)
        self.assertEqual(downloaded.status_code, 200, getattr(downloaded, 'data', None))
        self.assertEqual(downloaded.content, b'isolated-version-1')
        reader = User.objects.create_user('restore_denied')
        UserProfile.objects.create(user=reader, user_type='data_user')
        self.client.force_authenticate(reader)
        self.assertIn(self.client.get(url).status_code, (403, 404))
        print(f'Disposable Raft snapshot + version row + blob restored and checked in {monotonic() - started:.2f}s.')

    @skipUnless(os.environ.get('CPQA_TEST_VAULT_BENCHMARK') == '1', 'opt-in load measurement')
    def test_benchmark_uncached_vault_reads(self):
        from concurrent.futures import ThreadPoolExecutor
        from math import ceil
        from statistics import median
        from time import perf_counter

        attrs = {'department': 'it', 'user_type': 'super_admin'}
        failures = 0
        for scheme in ('ac17', 'tkn20', 'covercrypt'):
            with override_settings(CPABE_SCHEME=scheme):
                compiled = self.policy(f'benchmark_{scheme}').cpabe_policy
            for size in (4096, 1024**2, 8 * 1024**2):
                plaintext = b'x' * size
                ciphertext, metadata = self.service.encrypt_version(plaintext, compiled, scheme, True)

                def read(_):
                    start = perf_counter()
                    try:
                        route = self.service.verify_version_authority(metadata)
                        key = self.service.generate_user_key_bytes(attrs, scheme=scheme, route=route)
                        data = self.service.decrypt_buffer_and_verify(key, ciphertext, scheme=scheme, route=route)
                        matches = data == plaintext
                    except (CPABEError, requests.RequestException):
                        matches = False
                    return (perf_counter() - start) * 1000, matches

                for concurrent in (1, 4):
                    with ThreadPoolExecutor(max_workers=concurrent) as pool:
                        results = list(pool.map(read, range(8)))
                    timings = sorted(elapsed for elapsed, matches in results if matches)
                    failed = len(results) - len(timings)
                    failures += failed
                    print(json.dumps({
                        'scheme': scheme, 'bytes': size, 'concurrency': concurrent, 'requests': len(results),
                        'errors': failed, 'p50_ms': round(median(timings), 1) if timings else None,
                        'p95_ms': round(timings[ceil(.95 * len(timings)) - 1], 1) if timings else None,
                    }), flush=True)
        self.assertEqual(failures, 0)

    def test_z_rotation_keeps_signed_history_and_restores_verified_ciphertext(self):
        policy = self.policy('historical_rotation_policy')
        first = self.upload(policy)
        self.assertEqual(first.status_code, 201, first.data)
        file = UploadedFile.find_by_path('documents', 'contract.txt')
        old = file.get_latest_version()
        old_bytes = self.blobs[old.physical_path]
        download = f'/api/storage/files/{file.pk}/download/'
        self.assertEqual(self.client.get(download).content, b'isolated-version-1')

        self.department.allowed_values = ['it', 'hr', 'operations']
        self.department.save()
        mount = 'abe_covercrypt_next'
        self.vault.client.sys.enable_secrets_engine(backend_type='vault-plugin-abe', path=mount)
        config = build_covercrypt_configuration()
        payload = {'scheme': 'covercrypt', 'pqc': True, 'mode': 'hybridized',
                   'config_json': config.config_json, 'create_only': True, 'public_key_format': 'reference'}
        response = requests.put(f'{self.vault.get_addr}/v1/{mount}/setup',
                                headers={'X-Vault-Token': self.vault.get_token}, json=payload, timeout=310)
        response.raise_for_status()
        with patch('crypto_access.management.commands.covercrypt_config.vault_service', self.vault):
            with self.assertRaises(CommandError):
                call_command('covercrypt_config', rotate_vault=True, keyset_id='primary', vault_mount=mount,
                             expected_fingerprint='stale', stdout=StringIO())
            output = StringIO()
            call_command('covercrypt_config', rotate_vault=True, keyset_id='primary', vault_mount=mount,
                         expected_fingerprint=old.crypto_metadata['keyset_id'], stdout=output)
            new_manifest = json.loads(output.getvalue())['keyset_manifest']
            call_command('covercrypt_config', check_vault=True, keyset_id='primary', vault_mount=mount, stdout=StringIO())
            call_command('covercrypt_config', initialize_vault=True, keyset_id='primary', stdout=StringIO())
        self.assertNotEqual(new_manifest['public_key_fingerprint'], old.crypto_metadata['keyset_id'])
        updated = self.upload(policy, 2)
        self.assertEqual(updated.status_code, 201, updated.data)
        self.assertEqual(file.get_latest_version().crypto_metadata['keyset_id'], new_manifest['public_key_fingerprint'])
        self.assertEqual(self.client.get(download).content, b'isolated-version-2')
        cache.clear()
        self.assertEqual(self.client.get(download + '?version=1').content, b'isolated-version-1')

        restore = f'/api/storage/files/{file.pk}/restore_version/'
        reader = User.objects.create_user('history_reader')
        UserProfile.objects.create(user=reader, user_type='data_user')
        UserAttribute.objects.create(user=reader, attribute=self.department, value='it')
        self.client.force_authenticate(reader)
        self.assertEqual(self.client.get(download + '?version=1').content, b'isolated-version-1')
        self.assertEqual(self.client.post(restore, {'version_number': 1}, format='json').status_code, 403)
        self.client.force_authenticate(self.admin)
        with patch.object(storage_views, 'requires_document_policy', return_value=True):
            denied = self.client.post(restore, {'version_number': 1}, format='json')
        self.assertIn(denied.status_code, (403, 404))
        self.assertEqual(file.versions.count(), 2)
        listed = self.client.get(f'/api/storage/files/{file.pk}/versions/')
        self.assertEqual([v['can_restore'] for v in listed.data['versions']], [False, True])
        with patch.object(FileVersion.objects, 'create', side_effect=RuntimeError('fixture database failure')):
            failed = self.client.post(restore, {'version_number': 1}, format='json')
        self.assertEqual(failed.status_code, 500)
        self.storage.delete_file.assert_called_once()
        self.assertEqual(file.versions.count(), 2)
        original_policy = file.get_latest_version().cpabe_policy
        file.versions.filter(version_number=2).update(cpabe_policy='department::hr')
        self.assertEqual(self.client.post(restore, {'version_number': 1}, format='json').status_code, 409)
        file.versions.filter(version_number=2).update(cpabe_policy=original_policy)

        restored = self.client.post(restore, {'version_number': 1}, format='json')
        self.assertEqual(restored.status_code, 201, restored.data)
        version = file.get_latest_version()
        self.assertEqual(version.version_number, 3)
        self.assertNotEqual(version.physical_path, old.physical_path)
        self.assertEqual(version.crypto_metadata, old.crypto_metadata)
        self.assertEqual(self.blobs[version.physical_path], old_bytes)
        self.assertEqual(self.client.get(download).content, b'isolated-version-1')

        old_metadata = old.crypto_metadata
        file.versions.filter(pk=old.pk).update(crypto_metadata={**old_metadata, 'authority_revision': 999})
        self.assertEqual(self.client.get(download + '?version=1').status_code, 409)
        without_identity = {key: value for key, value in old_metadata.items()
                            if key not in ('keyset_id', 'authority_revision', 'contract_version')}
        file.versions.filter(pk=old.pk).update(crypto_metadata={**without_identity, 'schema': 1})
        self.assertEqual(self.client.get(download + '?version=1').status_code, 409)
