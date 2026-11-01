"""Apply the same stateful JWT validation before ABAC and inside DRF."""
import logging

from django.contrib.auth.models import AnonymousUser
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken

from crypto_access.authentication import CookieJWTAuthentication

logger = logging.getLogger(__name__)


class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authenticator = CookieJWTAuthentication()

    def __call__(self, request):
        try:
            result = self.jwt_authenticator.authenticate(request)
            if result is not None:
                request.user, request.auth = result
        except (InvalidToken, AuthenticationFailed) as error:
            request.user = AnonymousUser()
            request.auth = None
            request._jwt_auth_error = error
            logger.info('JWT access rejected by session/account validation')
        # Public login/refresh endpoints validate their own credentials; protected
        # endpoints preserve this failure instead of authenticating the JWT again.
        return self.get_response(request)
