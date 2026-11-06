"""Privileged CoverCrypt configuration discovery API."""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..permissions import IsSuperAdmin
from ..services.covercrypt_config import CoverCryptConfigurationError, build_covercrypt_configuration


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsSuperAdmin])
def covercrypt_configuration(request):
    """Return the validated authority configuration to a super administrator only."""
    try:
        configuration = build_covercrypt_configuration()
        return Response(
            {
                **configuration.as_dict(),
            }
        )
    except CoverCryptConfigurationError as exc:
        return Response({"detail": str(exc)}, status=409)
