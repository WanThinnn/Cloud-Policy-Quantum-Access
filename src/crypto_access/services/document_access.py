"""Keep document bypass decisions consistent across ABAC, listing and CP-ABE."""
from django.core.exceptions import ObjectDoesNotExist

from .runtime_settings import get_runtime_setting


def is_document_administrator(user):
    if getattr(user, 'is_superuser', False):
        return True
    try:
        profile = getattr(user, 'profile', None)
        return bool(profile and profile.is_super_admin())
    except ObjectDoesNotExist:
        return False


def requires_document_policy(user):
    return is_document_administrator(user) and get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY')


def can_bypass_document_policy(user):
    return is_document_administrator(user) and not get_runtime_setting('SUPER_ADMIN_REQUIRE_POLICY')
