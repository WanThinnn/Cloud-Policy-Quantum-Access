import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.http import Http404
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from crypto_access.models import NativeSigningRequest, UserPublicKey
from crypto_access.views.auth import crypto_agent_download
from crypto_access.views.pki import UserPublicKeyViewSet
from crypto_access.services import agent_packages, native_signing


class CryptoAgentDownloadTests(SimpleTestCase):
    @override_settings(NATIVE_SIGNING_ENABLED=True, CRYPTO_AGENT_CHROME_EXTENSION_ID='',
                       CRYPTO_AGENT_EDGE_EXTENSION_ID='', CRYPTO_AGENT_MIN_VERSION='0.2.0')
    def test_safari_is_enabled_by_the_published_macos_package(self):
        user = SimpleNamespace(is_authenticated=True, pk=1)
        with TemporaryDirectory() as directory, override_settings(CRYPTO_AGENT_PACKAGE_DIR=directory):
            root = Path(directory)
            version = '0.3.1'
            for target, bundled, enabled in [('windows-x86_64', True, False), ('macos-arm64', 'true', False),
                                              ('macos-arm64', True, True)]:
                with self.subTest(target=target, bundled=bundled):
                    name = f'cpqa-crypto-agent-{target}-{version}.zip'
                    (root / name).write_bytes(b'installer')
                    manifest = {'revision': 1, 'packages': [{
                        'target': target, 'version': version, 'filename': name, 'sha256': 'a' * 64,
                        'safari_bundled': bundled,
                    }]}
                    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
                    self.assertEqual(agent_packages.public_config(user)['safariBundled'], enabled)

    def test_only_authenticated_users_can_download_a_valid_published_installer(self):
        factory = RequestFactory()
        with TemporaryDirectory() as directory, override_settings(
            CRYPTO_AGENT_PACKAGE_DIR=directory, NATIVE_SIGNING_ENABLED=True,
            CRYPTO_AGENT_ORIGIN='https://cpqa.example',
            CRYPTO_AGENT_CHROME_EXTENSION_ID='', CRYPTO_AGENT_MIN_VERSION='0.2.0',
        ):
            package_dir = Path(directory)
            name = 'cpqa-crypto-agent-windows-x86_64-0.1.0.zip'
            package = package_dir / name
            package.write_bytes(b'approved installer')
            manifest = {
                'revision': 1,
                'packages': [{
                    'target': 'windows-x86_64', 'version': '0.1.0', 'filename': name,
                    'setup_script': 'setup.ps1',
                    'origin': 'https://cpqa.example', 'chromium_extension_id': 'a' * 32,
                    'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                }],
            }
            (package_dir / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            self.assertEqual(agent_packages.package_catalog()['windows-x86_64']['install_command'],
                             r'powershell -NoProfile -File .\setup.ps1')
            request = factory.get('/auth/keys/crypto-agent/windows-x86_64/')
            request.user = SimpleNamespace(is_authenticated=False)
            self.assertEqual(crypto_agent_download(request, 'windows-x86_64').status_code, 302)
            request.user = SimpleNamespace(is_authenticated=True)
            response = crypto_agent_download(request, 'windows-x86_64')
            try:
                self.assertIn(name, response['Content-Disposition'])
                self.assertEqual(response['Cache-Control'], 'private, no-store')
                self.assertEqual(b''.join(response.streaming_content), b'approved installer')
            finally:
                response.close()
            with self.assertRaises(Http404):
                crypto_agent_download(request, '../windows-x86_64')
            request.user.pk = 1
            self.assertEqual(agent_packages.public_config(request.user)['chromeExtensionId'], 'a' * 32)
            with override_settings(CRYPTO_AGENT_ORIGIN='https://another.example'):
                self.assertEqual(agent_packages.package_catalog(), {})
            package.write_bytes(b'tampered installer')
            with self.assertRaises(Http404):
                crypto_agent_download(request, 'windows-x86_64')


@override_settings(NATIVE_SIGNING_ENABLED=True, CRYPTO_AGENT_ORIGIN='https://testserver')
class CryptoAgentEnrollmentTests(TestCase):
    @override_settings(ROOT_URLCONF='security_tests.auth_urls')
    def test_revoke_route_disables_native_and_browser_keys_without_deleting_them(self):
        users = get_user_model().objects
        owner = users.create_user(username='key-owner')
        outsider = users.create_user(username='key-outsider')
        client = APIClient()

        for device_id in (None, uuid4()):
            with self.subTest(native=device_id is not None):
                key = UserPublicKey.objects.create(user=owner, pqc_public_key='fixture-key', native_device_id=device_id)
                url = f'/api/pki/keys/{key.pk}/revoke/'
                client.force_authenticate(outsider)
                self.assertEqual(client.post(url).status_code, 404)
                client.force_authenticate(owner)
                self.assertEqual(client.post(url).status_code, 200)
                key.refresh_from_db()
                self.assertEqual(key.status, 'revoked')
                self.assertEqual(key.pqc_public_key, 'fixture-key')

    def test_device_registration_is_single_use_and_status_is_scoped_to_account(self):
        users = get_user_model().objects
        owner = users.create_user(username='agent-owner')
        admin = users.create_superuser(username='agent-admin', password='ephemeral-password')
        factory = APIRequestFactory()

        def post(action, user, data):
            request = factory.post(f'/api/pki/keys/{action}/', data, format='json')
            force_authenticate(request, user)
            return UserPublicKeyViewSet.as_view({'post': action})(request)

        prepared = post('prepare_enrollment', owner, {})
        self.assertEqual(prepared.status_code, 201)
        payload = json.loads(prepared.data['payload'])
        self.assertEqual(payload['protocol'], native_signing.INTENT_PROTOCOL)
        data = {'request_id': str(prepared.data['request_id']), 'public_key': 'fixture-key',
                'signature': 'proof'}
        foreign_id = uuid4()
        UserPublicKey.objects.create(user=admin, pqc_public_key='foreign-key', native_device_id=foreign_id)
        with patch('crypto_access.views.pki.native_signing.verify_signature') as verifier, patch(
            'crypto_access.services.pki_service.PKIService.sign_payload', return_value='test-certificate',
        ):
            previous = {**payload, 'protocol': 'cpqa-crypto/v1'}
            requests = NativeSigningRequest.objects.filter(pk=data['request_id'])
            requests.update(payload=json.dumps(previous))
            self.assertEqual(post('complete_enrollment', owner, data).status_code, 409)
            verifier.assert_not_called()
            requests.update(payload=prepared.data['payload'])
            self.assertEqual(post('complete_enrollment', admin, data).status_code, 409)
            completed = post('complete_enrollment', owner, data)
            self.assertEqual(completed.status_code, 201)
            self.assertEqual(post('complete_enrollment', owner, data).status_code, 409)
            verifier.assert_called_once_with(
                'fixture-key', 'proof', f"{prepared.data['payload']}\nfixture-key".encode(),
            )

        request = factory.get('/api/pki/keys/signing_devices/')
        force_authenticate(request, admin)
        result = UserPublicKeyViewSet.as_view({'get': 'signing_devices'})(request)
        self.assertEqual(result.data, [{'device_id': foreign_id, 'status': 'active'}])
