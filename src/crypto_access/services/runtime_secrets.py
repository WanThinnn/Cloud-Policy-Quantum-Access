"""Immutable Vault secrets with DB references; no credential values in SystemSetting or caches."""
import re
import uuid

from django.conf import settings
from django.views.decorators.debug import sensitive_variables

from .setting_service import SettingService
from .vault_service import vault_service

SMTP_REFERENCE_KEY = '_SMTP_PASSWORD_REFERENCE'
PREFIX = 'runtime-settings/smtp/'


@sensitive_variables()
def store_smtp_password(password):
    path = PREFIX + uuid.uuid4().hex
    try:
        if vault_service.client is None:
            raise RuntimeError
        vault_service.check_runtime_token()
        vault_service.client.secrets.kv.v2.create_or_update_secret(
            path=path, secret={'password': password}, cas=0,
        )
    except Exception:
        raise RuntimeError('Vault credential storage is unavailable. Settings were not saved.') from None
    return path


@sensitive_variables()
def get_smtp_password():
    reference = SettingService.get_setting(SMTP_REFERENCE_KEY)
    if reference is None:
        return getattr(settings, 'EMAIL_HOST_PASSWORD', '')
    if not isinstance(reference, str) or not re.fullmatch(re.escape(PREFIX) + r'[0-9a-f]{32}', reference):
        raise RuntimeError('Invalid SMTP credential reference.')
    try:
        vault_service.check_runtime_token()
        result = vault_service.client.secrets.kv.v2.read_secret_version(path=reference)
        password = result['data']['data']['password']
        if not isinstance(password, str):
            raise ValueError
        return password
    except Exception:
        # A configured override never falls back to a stale environment password on Vault failure.
        raise RuntimeError('SMTP credential storage is unavailable.') from None
