from rest_framework_simplejwt.authentication import JWTAuthentication

from .services.session_service import validate_session


class CookieJWTAuthentication(JWTAuthentication):
    """Bearer takes precedence; an invalid explicit token never falls back to a cookie."""

    def authenticate(self, request):
        error = getattr(request, '_jwt_auth_error', None)
        if error is not None:
            raise error
        header = self.get_header(request)
        raw_token = self.get_raw_token(header) if header is not None else None
        if raw_token is None:
            raw_token = request.COOKIES.get('access_token')
        if raw_token is None:
            return None
        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token

    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        validate_session(user, validated_token)
        return user
