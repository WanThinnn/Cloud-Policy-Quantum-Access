"""One session/account validity rule for JWT access, refresh and all login methods."""
import uuid
from datetime import datetime, timedelta, timezone as datetime_timezone

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from crypto_access.models import ActiveSession


def validate_account(user):
    try:
        active = user.is_active and user.profile.is_account_active()
    except ObjectDoesNotExist:
        active = False
    if not active:
        raise AuthenticationFailed('Account is inactive, suspended or expired.', code='account_inactive')


def session_key(token):
    # Pre-fix access tokens remain usable until expiry only if their original session is active.
    return token.get('sid') or token.get(api_settings.JTI_CLAIM)


def validate_session(user, token, *, refresh=False, lock=False):
    validate_account(user)
    if refresh and not token.get('sid'):
        raise AuthenticationFailed('Please sign in again to establish a refreshable session.')
    key = session_key(token)
    if not isinstance(key, str) or not key:
        raise AuthenticationFailed('Token is not bound to a session.')
    query = ActiveSession.objects.select_for_update() if lock else ActiveSession.objects
    session = query.filter(session_key=key, user_id=user.pk, is_active=True).first()
    if session is None or (session.expires_at is not None and session.expires_at <= timezone.now()):
        raise AuthenticationFailed('Session has expired or been revoked.', code='session_revoked')
    if refresh and (not session.refresh_jti or session.refresh_jti != token.get(api_settings.JTI_CLAIM)):
        raise AuthenticationFailed('Refresh token has already been rotated or revoked.', code='refresh_revoked')
    if not refresh and timezone.now() - session.last_active > timedelta(minutes=5):
        ActiveSession.objects.filter(pk=session.pk, is_active=True).update(last_active=timezone.now())
    return session


def token_expiry(token):
    return datetime.fromtimestamp(token['exp'], tz=datetime_timezone.utc)


@transaction.atomic
def issue_session_tokens(user, **device):
    validate_account(user)
    refresh = RefreshToken.for_user(user)
    key = uuid.uuid4().hex
    refresh['sid'] = key
    ActiveSession.objects.create(
        user=user, session_key=key, refresh_jti=refresh[api_settings.JTI_CLAIM],
        expires_at=token_expiry(refresh), **device,
    )
    return str(refresh.access_token), str(refresh)


def set_auth_cookies(response, access, refresh):
    secure = getattr(settings, 'SESSION_COOKIE_SECURE', False)
    for name, value, token_type in (
        ('access_token', access, AccessToken), ('refresh_token', refresh, RefreshToken),
    ):
        seconds = max(0, int((token_expiry(token_type(value)) - timezone.now()).total_seconds()))
        response.set_cookie(name, value, max_age=seconds, httponly=True, samesite='Lax', secure=secure)
