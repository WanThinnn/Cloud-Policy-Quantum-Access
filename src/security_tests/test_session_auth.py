from unittest.mock import patch
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from crypto_access.authentication import CookieJWTAuthentication
from crypto_access.models import ActiveSession, UserProfile, UserPublicKey
from crypto_access.views.pki import UserPublicKeyViewSet
from crypto_access.views.storage import UploadedFileViewSet
from crypto_access.views.session_views import SessionViewSet
from crypto_access.views import auth
from crypto_access.services.session_service import issue_session_tokens


@override_settings(
    ROOT_URLCONF='security_tests.auth_urls',
    MIDDLEWARE=[
        'security_tests.auth_urls.AnonymousMiddleware',
        'crypto_access.middleware.jwt_middleware.JWTAuthenticationMiddleware',
        'crypto_access.middleware.abac_middleware.ABACMiddleware',
    ],
    ABAC_PROTECTED_ROUTES=[{
        'pattern': r'^/api/storage/files/browse/', 'resource': 'document', 'methods': {'GET': 'read'},
    }],
    SIMPLE_JWT={'ROTATE_REFRESH_TOKENS': True, 'BLACKLIST_AFTER_ROTATION': True},
)
class SessionAuthenticationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user('session_user', password='test-password')
        UserProfile.objects.create(user=self.user, user_type='data_user')
        self.other = User.objects.create_user('other_user', password='test-password')
        UserProfile.objects.create(user=self.other)
        for view in (UserPublicKeyViewSet, UploadedFileViewSet, SessionViewSet, auth.logout.cls):
            patcher = patch.object(view, 'authentication_classes', [CookieJWTAuthentication])
            patcher.start()
            self.addCleanup(patcher.stop)

    def credentials(self, owner=None, legacy=False):
        if legacy:
            refresh = RefreshToken.for_user(self.user)
            access = refresh.access_token
            session = ActiveSession.objects.create(user=owner or self.user, session_key=access['jti'])
            return str(access), str(refresh), session
        access, refresh = issue_session_tokens(self.user)
        session = ActiveSession.objects.get(session_key=AccessToken(access)['sid'])
        if owner is not None:
            session.user = owner
            session.save(update_fields=['user'])
        return access, refresh, session

    def client_for(self, access, channel):
        client = APIClient()
        if channel == 'bearer':
            client.credentials(HTTP_AUTHORIZATION='Bearer ' + access)
        else:
            client.cookies['access_token'] = access
        return client

    def test_revoked_token_is_rejected_by_pki_after_middleware(self):
        for channel in ('bearer', 'cookie'):
            access, _, session = self.credentials()
            client = self.client_for(access, channel)
            self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 200)
            session.is_active = False
            session.save(update_fields=['is_active'])
            self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 401)

    def test_session_must_belong_to_the_token_user(self):
        access, _, _ = self.credentials(owner=self.other)
        self.assertEqual(self.client_for(access, 'bearer').get('/api/pki/keys/my_keys/').status_code, 401)

    def test_signing_passkey_rebind_updates_ciphertext_and_credential_together(self):
        access, _, _ = self.credentials()
        client = self.client_for(access, 'bearer')
        signing_key = UserPublicKey.objects.create(
            user=self.user, pqc_public_key='public-fixture',
            credential_id='AQID', encrypted_pqc_sk_primary='original-fixture',
        )
        url = f'/api/pki/keys/{signing_key.pk}/'
        result = client.patch(url, {'encrypted_pqc_sk_primary': 'replacement-fixture'}, format='json')
        self.assertEqual(result.status_code, 400)
        signing_key.refresh_from_db()
        self.assertEqual(signing_key.encrypted_pqc_sk_primary, 'original-fixture')
        result = client.patch(url, {
            'credential_id': 'BAUG', 'encrypted_pqc_sk_primary': 'replacement-fixture',
        }, format='json')
        self.assertEqual(result.status_code, 200)
        active = client.get('/api/pki/keys/active_key/')
        self.assertEqual(active.data['credential_id'], 'BAUG')
        self.assertEqual(active.data['encrypted_pqc_sk_primary'], 'replacement-fixture')

    def test_active_signing_key_is_scoped_to_the_signed_in_admin(self):
        self.user.is_superuser = True
        self.user.save(update_fields=['is_superuser'])
        access, _, _ = self.credentials()
        client = self.client_for(access, 'bearer')
        own = UserPublicKey.objects.create(user=self.user, pqc_public_key='own-fixture')
        UserPublicKey.objects.create(user=self.other, pqc_public_key='other-fixture')
        active = client.get(f'/api/pki/keys/active_key/?user={self.other.pk}')
        self.assertEqual(active.status_code, 200)
        self.assertEqual(active.data['id'], own.pk)

    def test_refresh_cannot_revive_a_revoked_session(self):
        client = APIClient()
        response = client.post('/api/auth/login/', {'username': 'session_user', 'password': 'test-password'})
        self.assertEqual(response.status_code, 200)
        refresh = response.cookies['refresh_token'].value
        ActiveSession.objects.filter(user=self.user).update(is_active=False)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_revoked_token_is_denied_on_abac_route_too(self):
        for channel in ('bearer', 'cookie'):
            access, _, session = self.credentials()
            client = self.client_for(access, channel)
            with patch('crypto_access.services.casbin_service.casbin_service.check_access', return_value=True):
                self.assertEqual(client.get('/api/storage/files/browse/').status_code, 200)
            session.is_active = False
            session.save(update_fields=['is_active'])
            self.assertEqual(client.get('/api/storage/files/browse/').status_code, 401)

    def test_invalid_or_revoked_bearer_cannot_fall_back_to_valid_cookie(self):
        cookie_access, _, _ = self.credentials()
        revoked_access, _, session = self.credentials()
        session.is_active = False
        session.save(update_fields=['is_active'])
        for bearer in ('invalid-token', revoked_access):
            client = self.client_for(cookie_access, 'cookie')
            client.credentials(HTTP_AUTHORIZATION='Bearer ' + bearer)
            self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 401)

    def test_account_status_and_expiry_are_checked_for_access_and_refresh(self):
        access, refresh, _ = self.credentials()
        profile = self.user.profile
        for account_status in ('suspended', 'inactive', 'pending', 'expired'):
            profile.account_status = account_status
            profile.save()
            for channel in ('bearer', 'cookie'):
                self.assertEqual(self.client_for(access, channel).get('/api/pki/keys/my_keys/').status_code, 401)
            self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)
        profile.account_status = 'active'
        profile.account_expiry_date = timezone.now() - timedelta(seconds=1)
        profile.save()
        self.assertEqual(self.client_for(access, 'bearer').get('/api/pki/keys/my_keys/').status_code, 401)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_disabled_django_user_cannot_refresh_or_use_access(self):
        access, refresh, _ = self.credentials()
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.client_for(access, 'cookie').get('/api/pki/keys/my_keys/').status_code, 401)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_refresh_rotation_keeps_sid_and_rejects_replay(self):
        access, refresh, session = self.credentials()
        response = APIClient().post('/api/auth/token/refresh/', {'refresh': refresh})
        self.assertEqual(response.status_code, 200)
        rotated = response.data['refresh']
        self.assertNotEqual(RefreshToken(rotated)['jti'], session.refresh_jti)
        self.assertEqual(AccessToken(response.data['access'])['sid'], session.session_key)
        self.assertEqual(RefreshToken(rotated)['sid'], session.session_key)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)
        self.assertEqual(self.client_for(response.data['access'], 'bearer').get('/api/pki/keys/my_keys/').status_code, 200)
        session.is_active = False
        session.save(update_fields=['is_active'])
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': rotated}).status_code, 401)

    def test_cookie_refresh_works_with_expired_access_and_requires_csrf(self):
        access, refresh, _ = self.credentials()
        expired = AccessToken(access)
        expired['exp'] = int(timezone.now().timestamp()) - 1
        client = self.client_for(str(expired), 'cookie')
        client.cookies['refresh_token'] = refresh
        response = client.post('/api/auth/token/refresh/', {})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.cookies['access_token']['httponly'])
        self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 200)
        strict_client = APIClient(enforce_csrf_checks=True)
        strict_client.cookies['refresh_token'] = response.cookies['refresh_token'].value
        self.assertEqual(strict_client.post('/api/auth/token/refresh/', {}).status_code, 403)

    def test_refresh_must_be_bound_to_the_same_user(self):
        _, refresh, _ = self.credentials(owner=self.other)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_legacy_access_requires_session_and_legacy_refresh_requires_relogin(self):
        access, refresh, session = self.credentials(legacy=True)
        client = self.client_for(access, 'bearer')
        self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 200)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)
        session.is_active = False
        session.save(update_fields=['is_active'])
        self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 401)

    def test_logout_revokes_the_whole_session_for_bearer_and_cookie(self):
        for channel in ('bearer', 'cookie'):
            access, refresh, session = self.credentials()
            client = self.client_for(access, channel)
            self.assertEqual(client.post('/api/auth/logout/', {}).status_code, 200)
            session.refresh_from_db()
            self.assertFalse(session.is_active)
            self.assertEqual(self.client_for(access, channel).get('/api/pki/keys/my_keys/').status_code, 401)
            self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_revoke_all_other_sessions_keeps_current_sid_after_rotation(self):
        current_access, current_refresh, current_session = self.credentials()
        other_access, other_refresh, _ = self.credentials()
        response = APIClient().post('/api/auth/token/refresh/', {'refresh': current_refresh})
        client = self.client_for(response.data['access'], 'bearer')
        self.assertEqual(client.post('/api/auth/sessions/revoke_all/', {}).status_code, 200)
        current_session.refresh_from_db()
        self.assertTrue(current_session.is_active)
        self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 200)
        self.assertEqual(self.client_for(other_access, 'cookie').get('/api/pki/keys/my_keys/').status_code, 401)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': other_refresh}).status_code, 401)

    def test_expired_server_session_cannot_use_access_or_refresh(self):
        access, refresh, session = self.credentials()
        ActiveSession.objects.filter(pk=session.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client_for(access, 'bearer').get('/api/pki/keys/my_keys/').status_code, 401)
        self.assertEqual(APIClient().post('/api/auth/token/refresh/', {'refresh': refresh}).status_code, 401)

    def test_register_creates_a_session_for_its_issued_cookies(self):
        client = APIClient()
        response = client.post('/api/auth/register/', {
            'username': 'new_session_user', 'password': 'Test-password123!', 'password2': 'Test-password123!',
            'email': 'new@example.com', 'full_name': 'New Session User',
        })
        self.assertEqual(response.status_code, 201)
        self.assertEqual(client.get('/api/pki/keys/my_keys/').status_code, 200)
