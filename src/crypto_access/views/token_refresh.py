from django.db import transaction
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from crypto_access.services.session_service import set_auth_cookies, token_expiry, validate_session


class SessionTokenRefreshSerializer(TokenRefreshSerializer):
    @transaction.atomic
    def validate(self, attrs):
        token = RefreshToken(attrs['refresh'])
        user = JWTAuthentication().get_user(token)
        session = validate_session(user, token, refresh=True, lock=True)
        data = super().validate(attrs)
        current_refresh = RefreshToken(data['refresh']) if 'refresh' in data else token
        session.refresh_jti = current_refresh[api_settings.JTI_CLAIM]
        session.expires_at = token_expiry(current_refresh)
        session.last_active = timezone.now()
        session.save(update_fields=['refresh_jti', 'expires_at', 'last_active'])
        return data


class SessionTokenRefreshView(TokenRefreshView):
    serializer_class = SessionTokenRefreshSerializer
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        payload = request.data.copy()
        if 'refresh' not in payload and request.COOKIES.get('refresh_token'):
            SessionAuthentication().enforce_csrf(request)
            payload['refresh'] = request.COOKIES['refresh_token']
        serializer = self.get_serializer(data=payload)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as error:
            raise InvalidToken(str(error)) from error
        data = serializer.validated_data
        response = Response(data)
        set_auth_cookies(response, data['access'], data.get('refresh', payload['refresh']))
        return response
