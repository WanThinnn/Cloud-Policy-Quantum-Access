"""Settings access, validation, rollback, and the actual runtime consumers."""
from pathlib import Path
from datetime import timedelta
from unittest.mock import Mock, patch
import tailwind

from django.contrib.auth.models import AnonymousUser, User
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from crypto_access.models import AccessLog, ActiveSession, SystemSetting, UserProfile
from crypto_access.services.ai_policy_service import AIPolicyService
from crypto_access.services.runtime_settings import catalog, get_runtime_setting
from crypto_access.serializers.storage import FileUploadSerializer
from crypto_access.views.auth import login
from crypto_access.middleware.jwt_middleware import JWTAuthenticationMiddleware
from rest_framework_simplejwt.tokens import AccessToken
from crypto_access.views.system_settings import revision_token, system_settings_page
from crypto_access.services.runtime_secrets import SMTP_REFERENCE_KEY, get_smtp_password, store_smtp_password
from crypto_access.services.email_backend import RuntimeEmailBackend
from rest_framework.test import APIClient, force_authenticate


TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [Path(__file__).resolve().parents[1] / 'templates', Path(tailwind.__file__).parent / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {
        'libraries': {'tailwind_tags': 'tailwind.templatetags.tailwind_tags'},
        'context_processors': ['django.template.context_processors.request'],
    },
}]


@override_settings(TEMPLATES=TEMPLATES, STATIC_URL='/static/', TAILWIND_APP_NAME='theme')
class RuntimeSettingsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.admin = User.objects.create_user('settings_admin', password='test')
        UserProfile.objects.create(user=self.admin, user_type='super_admin')
        self.user = User.objects.create_user('ordinary_admin', password='test')
        UserProfile.objects.create(user=self.user, user_type='admin')

    def request(self, method='get', data=None, user=None, csrf=True):
        request = getattr(self.factory, method)('/manage/settings/', data=data or {})
        request.user = user or self.admin
        if csrf:
            request._dont_enforce_csrf_checks = True
        return system_settings_page(request)

    def payload(self, **changes):
        values = {key: get_runtime_setting(key) for key in catalog()}
        if not values['AI_FEATURES_ENABLED']:
            values.pop('AI_FEATURES_ENABLED')
        values.update(changes)
        values['revision'] = revision_token()
        return values

    def store(self, key, value):
        with self.captureOnCommitCallbacks(execute=True):
            return SystemSetting.objects.update_or_create(key=key, defaults={'value': value})[0]

    def test_access_is_role_based_for_read_and_write(self):
        for method in ('get', 'post'):
            self.assertEqual(self.request(method, user=AnonymousUser()).status_code, 302)
            self.assertEqual(self.request(method, user=self.user).status_code, 403)
        self.user.is_superuser = True
        self.user.save()
        self.assertEqual(self.request(user=self.user).status_code, 403)
        self.assertFalse(SystemSetting.objects.exists())

    def test_inactive_super_admin_denied(self):
        self.admin.profile.account_status = 'suspended'
        self.admin.profile.save()
        self.assertEqual(self.request().status_code, 403)

    def test_revoked_jwt_session_cannot_read_settings(self):
        token = AccessToken.for_user(self.admin)
        request = self.factory.get('/manage/settings/', HTTP_AUTHORIZATION=f'Bearer {token}')
        request.user = AnonymousUser()
        middleware = JWTAuthenticationMiddleware(system_settings_page)
        self.assertEqual(middleware(request).status_code, 302)
        ActiveSession.objects.create(user=self.admin, session_key=token['jti'])
        request = self.factory.get('/manage/settings/', HTTP_AUTHORIZATION=f'Bearer {token}')
        request.user = AnonymousUser()
        self.assertEqual(middleware(request).status_code, 200)

    def test_page_renders_real_template_and_does_not_seed_or_expose_secrets(self):
        with override_settings(SECRET_KEY='NEVER_SHOW_THIS_SECRET'):
            response = self.request()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'System Settings')
        self.assertContains(response, 'csrfmiddlewaretoken')
        self.assertNotContains(response, 'NEVER_SHOW_THIS_SECRET')
        self.assertIn('no-store', response['Cache-Control'])
        self.assertFalse(SystemSetting.objects.exists())

    def test_csrf_is_required(self):
        response = self.request('post', self.payload(UPLOAD_MAX_SIZE_MB=15), csrf=False)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(SystemSetting.objects.exists())

    def test_document_strict_switch_saves_and_can_be_disabled_without_losing_settings_access(self):
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request('post', self.payload(SUPER_ADMIN_REQUIRE_POLICY='on'))
        self.assertEqual(response.status_code, 200)
        self.assertIs(get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY'), True)
        self.assertEqual(self.request().status_code, 200)
        data = self.payload()
        data.pop('SUPER_ADMIN_REQUIRE_POLICY')  # Native unchecked checkbox is absent from the POST.
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request('post', data)
        self.assertEqual(response.status_code, 200)
        self.assertIs(get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY'), False)

    def test_save_typed_values_with_audit_and_immediate_cache_invalidation(self):
        self.store('UPLOAD_MAX_SIZE_MB', 12)
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request('post', self.payload(UPLOAD_MAX_SIZE_MB=15, AI_FEATURES_ENABLED='on'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 15)
        self.assertIs(get_runtime_setting('AI_FEATURES_ENABLED'), True)
        log = AccessLog.objects.get(resource_type='system_setting')
        self.assertEqual(log.user, self.admin)
        self.assertEqual(log.environment_attributes['changes']['UPLOAD_MAX_SIZE_MB'], {'before': 12, 'after': 15})

    def test_invalid_batch_writes_nothing(self):
        for changes in ({'UPLOAD_MAX_SIZE_MB': 41}, {'LOGIN_MAX_ATTEMPTS': 0},
                        {'LOGIN_LOCKOUT_SECONDS': 0}, {'IMPOSSIBLE_TRAVEL_MINUTES': -1},
                        {'OLLAMA_MODEL': 'http://127.0.0.1 bad'}, {'OLLAMA_KEEP_ALIVE': 'forever'}):
            response = self.request('post', self.payload(**changes))
            self.assertEqual(response.status_code, 400)
        self.assertFalse(SystemSetting.objects.exists())
        self.assertFalse(AccessLog.objects.exists())

    def test_unknown_and_sensitive_keys_cannot_be_written(self):
        for key in ('SECRET_KEY', 'OLLAMA_CACERT', 'EMAIL_HOST_PASSWORD', 'CPABE_SCHEME', 'ABAC_PROTECTED_ROUTES'):
            response = self.request('post', self.payload(UPLOAD_MAX_SIZE_MB=15, **{key: 'untrusted'}))
            self.assertEqual(response.status_code, 400)
        self.assertFalse(SystemSetting.objects.exists())

    def test_audit_failure_rolls_back_entire_batch(self):
        with patch('crypto_access.views.system_settings.store_smtp_password',
                   return_value='runtime-settings/smtp/' + 'f' * 32) as vault_write:
            with patch.object(AccessLog.objects, 'create', side_effect=RuntimeError('audit unavailable')):
                response = self.request('post', self.payload(
                    UPLOAD_MAX_SIZE_MB=15, LOGIN_MAX_ATTEMPTS=6, smtp_password='test-only-secret'))
        vault_write.assert_called_once_with('test-only-secret')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(SystemSetting.objects.exists())

    def test_old_form_cannot_overwrite_changes_from_another_tab(self):
        stale = self.payload(UPLOAD_MAX_SIZE_MB=20)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(self.request('post', self.payload(UPLOAD_MAX_SIZE_MB=15)).status_code, 200)
        response = self.request('post', stale)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 15)
        self.assertEqual(AccessLog.objects.filter(resource_type='system_setting').count(), 1)

    def test_cache_only_invalidates_after_commit_and_not_after_rollback(self):
        row = self.store('UPLOAD_MAX_SIZE_MB', 12)
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 12)
        with self.captureOnCommitCallbacks(execute=True):
            with self.assertRaises(RuntimeError):
                with transaction.atomic():
                    row.value = 15
                    row.save()
                    raise RuntimeError('rollback')
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 12)
        with self.captureOnCommitCallbacks(execute=True):
            row.delete()
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 10)

    def test_invalid_legacy_value_falls_back_and_inactive_record_is_ignored(self):
        self.store('LOGIN_MAX_ATTEMPTS', -1)
        self.assertEqual(get_runtime_setting('LOGIN_MAX_ATTEMPTS'), 5)
        self.store('AI_FEATURES_ENABLED', 'False')
        self.assertIs(get_runtime_setting('AI_FEATURES_ENABLED'), False)
        row = self.store('UPLOAD_MAX_SIZE_MB', 15)
        row.is_active = False
        with self.captureOnCommitCallbacks(execute=True):
            row.save()
        self.assertEqual(get_runtime_setting('UPLOAD_MAX_SIZE_MB'), 10)

    def test_upload_validator_consumes_current_limit(self):
        self.store('UPLOAD_MAX_SIZE_MB', 1)
        upload = SimpleUploadedFile('test.txt', b'x' * (1024 * 1024 + 1))
        form = FileUploadSerializer(data={'file': upload, 'bucket_name': 'documents'})
        self.assertFalse(form.is_valid())
        self.assertIn('file', form.errors)
        self.store('UPLOAD_MAX_SIZE_MB', 2)
        upload.seek(0)
        form = FileUploadSerializer(data={'file': upload, 'bucket_name': 'documents'})
        self.assertTrue(form.is_valid(), form.errors)

    def test_ai_singleton_reads_new_values_without_recreation(self):
        service = AIPolicyService()
        self.store('AI_FEATURES_ENABLED', False)
        self.assertFalse(service.enabled)
        self.store('AI_FEATURES_ENABLED', True)
        self.store('OLLAMA_MODEL', 'qwen2.5:7b')
        self.assertTrue(service.enabled)
        self.assertEqual(service.model, 'qwen2.5:7b')
        with patch('crypto_access.services.ai_policy_service.requests.get') as get:
            import requests
            get.side_effect = requests.Timeout()
            self.assertFalse(service.is_available())

    def test_login_enforces_runtime_attempt_limit_and_counter_ttl(self):
        self.store('LOGIN_MAX_ATTEMPTS', 3)
        self.store('LOGIN_LOCKOUT_SECONDS', 120)
        with patch.object(cache, 'set', wraps=cache.set) as set_cache:
            for _ in range(3):
                request = self.factory.post('/api/auth/login/', {'username': 'wrong', 'password': 'bad'})
                self.assertEqual(login(request).status_code, 401)
            set_cache.assert_any_call('failed_login_attempts_wrong', 3, 120)
        request = self.factory.post('/api/auth/login/', {'username': 'wrong', 'password': 'bad'})
        self.assertEqual(login(request).status_code, 429)
        self.assertEqual(cache.get('failed_login_attempts_wrong'), 3)

    def test_login_ip_verification_uses_runtime_window(self):
        session = ActiveSession.objects.create(user=self.user, session_key='previous', ip_address='8.8.8.8')
        ActiveSession.objects.filter(pk=session.pk).update(last_active=timezone.now() - timedelta(minutes=5))
        self.store('IMPOSSIBLE_TRAVEL_MINUTES', 10)
        request = self.factory.post('/api/auth/login/', {'username': self.user.username, 'password': 'test'},
                                    REMOTE_ADDR='1.1.1.1')
        with patch('django.core.mail.EmailMultiAlternatives.send'):
            response = login(request)
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.data['requires_otp'])
        self.store('IMPOSSIBLE_TRAVEL_MINUTES', 1)
        request = self.factory.post('/api/auth/login/', {'username': self.user.username, 'password': 'test'},
                                    REMOTE_ADDR='1.1.1.1')
        self.assertEqual(login(request).status_code, 200)

    def test_new_smtp_password_is_write_only_and_only_a_reference_is_stored(self):
        password = 'test-only-private-smtp-password'
        path = 'runtime-settings/smtp/' + 'a' * 32
        with patch('crypto_access.views.system_settings.store_smtp_password', return_value=path) as store:
            with self.captureOnCommitCallbacks(execute=True):
                response = self.request('post', self.payload(smtp_password=password))
        self.assertEqual(response.status_code, 200)
        store.assert_called_once_with(password)
        self.assertNotContains(response, password)
        self.assertEqual(SystemSetting.objects.get(key=SMTP_REFERENCE_KEY).value, path)
        self.assertNotIn(password, str(list(SystemSetting.objects.values_list('value', flat=True))))
        self.assertNotIn(password, str(AccessLog.objects.get(resource_type='system_setting').environment_attributes))
        # Empty password keeps the current override.
        with patch('crypto_access.views.system_settings.store_smtp_password') as store:
            self.assertEqual(self.request('post', self.payload()).status_code, 200)
            store.assert_not_called()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.request('post', self.payload(use_deployment_password='on'))
        self.assertEqual(response.status_code, 200)
        self.assertFalse(SystemSetting.objects.filter(key=SMTP_REFERENCE_KEY).exists())

    def test_explicit_save_adopts_environment_defaults_into_ui_managed_values(self):
        with override_settings(OLLAMA_MODEL='test-deployment:3b'):
            with self.captureOnCommitCallbacks(execute=True):
                self.assertEqual(self.request('post', self.payload()).status_code, 200)
        self.assertEqual(get_runtime_setting('OLLAMA_MODEL'), 'test-deployment:3b')
        self.assertEqual(SystemSetting.objects.filter(key__in=catalog()).count(), len(catalog()))

    def test_vault_failure_does_not_save_other_settings_or_echo_password(self):
        with patch('crypto_access.views.system_settings.store_smtp_password', side_effect=RuntimeError('unavailable')):
            response = self.request('post', self.payload(smtp_password='hidden-password', EMAIL_PORT=465))
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, 'hidden-password', status_code=400)
        self.assertFalse(SystemSetting.objects.exists())

    def test_vault_credentials_are_immutable_and_no_stale_fallback_on_failure(self):
        with patch('crypto_access.services.runtime_secrets.vault_service') as vault:
            path = store_smtp_password('private-test-value')
            vault.client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
                path=path, secret={'password': 'private-test-value'}, cas=0)
            self.store(SMTP_REFERENCE_KEY, path)
            vault.client.secrets.kv.v2.read_secret_version.return_value = {
                'data': {'data': {'password': 'private-test-value'}},
            }
            self.assertEqual(get_smtp_password(), 'private-test-value')
            vault.client.secrets.kv.v2.read_secret_version.side_effect = RuntimeError('unavailable')
            with override_settings(EMAIL_HOST_PASSWORD='stale-deployment-password'):
                with self.assertRaisesRegex(RuntimeError, 'storage is unavailable'):
                    get_smtp_password()

    def test_smtp_backend_uses_runtime_config_and_verified_tls(self):
        self.store('EMAIL_DELIVERY_MODE', 'smtp')
        self.store('EMAIL_HOST', 'smtp.example.com')
        self.store('EMAIL_PORT', 465)
        self.store('EMAIL_SECURITY', 'ssl')
        self.store('EMAIL_HOST_USER', 'sender@example.com')
        self.store('DEFAULT_FROM_EMAIL', 'cloudsafe@example.com')
        self.store('EMAIL_TIMEOUT_SECONDS', 20)
        message = Mock()
        with patch('crypto_access.services.email_backend.get_connection') as connect:
            with patch('crypto_access.services.email_backend.get_smtp_password', return_value='secret'):
                backend = RuntimeEmailBackend()
                backend.send_messages([message])
        connect.assert_called_once_with('django.core.mail.backends.smtp.EmailBackend', fail_silently=False,
                                       host='smtp.example.com', port=465, username='sender@example.com',
                                       password='secret', use_tls=False, use_ssl=True, timeout=20)
        self.assertEqual(message.from_email, 'cloudsafe@example.com')

    def test_console_backend_does_not_access_smtp_credentials(self):
        self.store('EMAIL_DELIVERY_MODE', 'console')
        with patch('crypto_access.services.email_backend.get_connection'):
            with patch('crypto_access.services.email_backend.get_smtp_password') as password:
                RuntimeEmailBackend().send_messages([Mock()])
                password.assert_not_called()

    def test_smtp_connection_test_authenticates_without_sending_or_saving(self):
        with patch('crypto_access.services.email_backend.SMTPBackend') as smtp:
            response = self.request('post', self.payload(operation='test_smtp', smtp_password='test-private-password'))
        self.assertEqual(response.status_code, 200)
        smtp.return_value.open.assert_called_once()
        smtp.return_value.close.assert_called_once()
        smtp.return_value.send_messages.assert_not_called()
        self.assertFalse(SystemSetting.objects.exists())
        self.assertNotContains(response, 'test-private-password')

    def test_smtp_connection_errors_do_not_echo_credentials_or_save(self):
        with patch('crypto_access.services.email_backend.SMTPBackend') as smtp:
            smtp.return_value.open.side_effect = RuntimeError('sensitive-test-password')
            response = self.request('post', self.payload(operation='test_smtp'))
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, 'sensitive-test-password', status_code=400)
        self.assertFalse(SystemSetting.objects.exists())

    def test_ollama_endpoint_rejects_embedded_credentials_and_non_https_urls(self):
        for url in ('http://localhost:11434', 'https://user:pass@ollama.example.com',
                    'https://ollama.example.com/api/chat', 'https://ollama.example.com/?secret=value'):
            self.assertEqual(self.request('post', self.payload(OLLAMA_BASE_URL=url)).status_code, 400)
        self.assertFalse(SystemSetting.objects.exists())

    def test_ai_request_uses_runtime_endpoint_model_keepalive_and_timeout(self):
        self.store('AI_FEATURES_ENABLED', True)
        self.store('OLLAMA_BASE_URL', 'https://ollama.example.com:11434')
        self.store('AI_REQUEST_TIMEOUT_SECONDS', 180)
        self.store('OLLAMA_KEEP_ALIVE', '5m')
        service = AIPolicyService()
        with patch.object(service, '_get_attributes_schema', return_value=[]):
            with patch.object(service, '_build_system_prompt', return_value='test prompt'):
                with patch('crypto_access.services.ai_policy_service.requests.post') as post:
                    post.return_value.json.return_value = {'message': {'content': '{}'}}
                    self.assertEqual(service.generate_policy('test'), {})
        self.assertEqual(post.call_args.args[0], 'https://ollama.example.com:11434/api/chat')
        self.assertEqual(post.call_args.kwargs['timeout'], 180)
        self.assertEqual(post.call_args.kwargs['json']['keep_alive'], '5m')

    def test_scanner_timeout_changes_rebuild_the_client(self):
        from crypto_access.services.clamav_service import ClamAVService
        service = ClamAVService()
        service.use_tls = False
        with patch('crypto_access.services.clamav_service.clamd.ClamdNetworkSocket') as client:
            client.side_effect = lambda *args, **kwargs: Mock(timeout=kwargs['timeout'])
            first = service._get_client()
            self.store('CLAMAV_TIMEOUT_SECONDS', 30)
            second = service._get_client()
        self.assertIsNot(first, second)
        self.assertEqual(second.timeout, 30)

    def test_runtime_upload_and_download_limits_are_applied_by_router(self):
        client = APIClient()
        client.force_authenticate(self.admin)
        self.store('CPABE_ENCRYPT_PER_MINUTE', 1)
        self.assertEqual(client.post('/api/storage/files/upload/', {}).status_code, 400)
        self.assertEqual(client.post('/api/storage/files/upload/', {}).status_code, 429)
        self.store('CPABE_DECRYPT_PER_MINUTE', 1)
        self.assertEqual(client.get('/api/storage/files/download_by_path/').status_code, 400)
        self.assertEqual(client.get('/api/storage/files/preview_by_path/').status_code, 429)

    def test_passkey_options_consume_runtime_display_name(self):
        from crypto_access.views.passkey import passkey_register_options
        self.store('WEBAUTHN_RP_NAME', 'Test Organization')
        request = self.factory.post('/api/auth/passkey/register/options/')
        force_authenticate(request, self.admin)
        with patch('crypto_access.views.passkey.generate_registration_options') as generate:
            generate.return_value.challenge = b'test-challenge'
            with patch('crypto_access.views.passkey.options_to_json', return_value='{}'):
                self.assertEqual(passkey_register_options(request).status_code, 200)
        self.assertEqual(generate.call_args.kwargs['rp_name'], 'Test Organization')
