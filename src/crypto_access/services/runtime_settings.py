"""Allowlisted, validated runtime controls. Deployment secrets never enter this catalog."""
import os
from urllib.parse import urlsplit

from django import forms
from django.conf import settings
from django.core.validators import URLValidator

from .setting_service import SettingService

SAFE_DEFAULTS = {
    'SUPER_ADMIN_REQUIRE_POLICY': False,
    'AI_FEATURES_ENABLED': False, 'OLLAMA_MODEL': 'qwen2.5-coder:3b', 'OLLAMA_KEEP_ALIVE': '-1',
    'UPLOAD_MAX_SIZE_MB': 10, 'LOGIN_MAX_ATTEMPTS': 5, 'LOGIN_LOCKOUT_SECONDS': 900,
    'IMPOSSIBLE_TRAVEL_MINUTES': 30,
    'OLLAMA_BASE_URL': 'https://ollama-tls.cyberfortress.local:11434',
    'AI_REQUEST_TIMEOUT_SECONDS': 120, 'CLAMAV_TIMEOUT_SECONDS': 15,
    'CPABE_ENCRYPT_PER_MINUTE': 5, 'CPABE_DECRYPT_PER_MINUTE': 10,
    'EMAIL_DELIVERY_MODE': 'smtp', 'EMAIL_HOST': 'smtp.gmail.com', 'EMAIL_PORT': 587,
    'EMAIL_HOST_USER': '', 'EMAIL_SECURITY': 'starttls', 'DEFAULT_FROM_EMAIL': '',
    'EMAIL_TIMEOUT_SECONDS': 10, 'WEBAUTHN_RP_NAME': 'Cloud Policy Crypto Access',
}


def validate_ollama_endpoint(value):
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise forms.ValidationError('Use an HTTPS origin without credentials, a path, query or fragment.')


def catalog():
    """Fresh fields so forms and runtime consumers use the same validation."""
    return {
        'SUPER_ADMIN_REQUIRE_POLICY': ('Document access', forms.BooleanField(
            required=False, label='Require SuperAdmin to match document policies',
            help_text='On: SuperAdmin must match access policies, even for owned files. '
                      'Off: SuperAdmin can bypass document policies. Administration stays accessible.'), False),
        'WEBAUTHN_RP_NAME': ('Passkeys', forms.CharField(
            max_length=64, label='Passkey display name',
            help_text='Shown when registering new passkeys. The relying party ID and origin stay unchanged.'),
            getattr(settings, 'WEBAUTHN_RP_NAME', SAFE_DEFAULTS['WEBAUTHN_RP_NAME'])),
        'EMAIL_DELIVERY_MODE': ('Email', forms.ChoiceField(
            choices=[('smtp', 'SMTP delivery'), ('console', 'Development console')], label='Email delivery',
            help_text='Console mode writes messages, including OTP codes, to server logs. '
                      'Use SMTP outside development.'),
            'console' if getattr(settings, 'DEBUG', False) else 'smtp'),
        'EMAIL_HOST': ('Email', forms.RegexField(
            regex=r'^[a-zA-Z0-9][a-zA-Z0-9.:-]*$', max_length=253, label='SMTP server',
            help_text='Hostname or IP address, without a URL scheme.'),
            getattr(settings, 'EMAIL_HOST', 'smtp.gmail.com')),
        'EMAIL_PORT': ('Email', forms.IntegerField(min_value=1, max_value=65535, label='SMTP port'),
                       getattr(settings, 'EMAIL_PORT', 587)),
        'EMAIL_HOST_USER': ('Email', forms.CharField(required=False, max_length=254, label='SMTP username',
            help_text='Leave empty only if your SMTP server allows unauthenticated delivery.'),
            getattr(settings, 'EMAIL_HOST_USER', '')),
        'EMAIL_SECURITY': ('Email', forms.ChoiceField(
            choices=[('starttls', 'STARTTLS (usually port 587)'), ('ssl', 'TLS (usually port 465)')],
            label='SMTP connection security', help_text='Certificate verification remains enabled.'),
            'ssl' if getattr(settings, 'EMAIL_USE_SSL', False) else 'starttls'),
        'DEFAULT_FROM_EMAIL': ('Email', forms.EmailField(required=False, label='Sender email',
            help_text='Leave empty to use the SMTP username.'),
            getattr(settings, 'DEFAULT_FROM_EMAIL', '') or getattr(settings, 'EMAIL_HOST_USER', '')),
        'EMAIL_TIMEOUT_SECONDS': ('Email', forms.IntegerField(
            min_value=1, max_value=60, label='SMTP timeout (seconds)'), 10),
        'OLLAMA_BASE_URL': ('AI Assistant', forms.URLField(
            max_length=500, validators=[URLValidator(schemes=['https']), validate_ollama_endpoint],
            label='Ollama HTTPS endpoint',
            help_text='Connect to an existing Ollama server. Its certificate must be trusted by the deployed app.'),
            getattr(settings, 'OLLAMA_BASE_URL', SAFE_DEFAULTS['OLLAMA_BASE_URL'])),
        'AI_FEATURES_ENABLED': ('AI Assistant', forms.BooleanField(
            required=False, label='Enable AI Policy Assistant',
            help_text='Ollama must already be deployed. Enabling this does not start services or download models.'),
            getattr(settings, 'AI_FEATURES_ENABLED', False)),
        'OLLAMA_MODEL': ('AI Assistant', forms.RegexField(
            regex=r'^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$', max_length=128, label='Model identifier',
            help_text='Use an installed model identifier, for example qwen2.5-coder:3b.'),
            getattr(settings, 'OLLAMA_MODEL', 'qwen2.5-coder:3b')),
        'OLLAMA_KEEP_ALIVE': ('AI Assistant', forms.RegexField(
            regex=r'^(?:-1|[0-9]+|[0-9]+(?:\.[0-9]+)?(?:ms|s|m|h))$', max_length=20,
            label='Keep model loaded', help_text='Use -1 for indefinitely, 0 to unload, or a duration such as 5m.'),
            os.environ.get('OLLAMA_KEEP_ALIVE', '-1')),
        'AI_REQUEST_TIMEOUT_SECONDS': ('AI Assistant', forms.IntegerField(
            min_value=10, max_value=600, label='AI response timeout (seconds)'), 120),
        'UPLOAD_MAX_SIZE_MB': ('Documents', forms.IntegerField(
            min_value=1, max_value=40, label='Maximum upload size (MB)',
            help_text='Applies to new uploads, including new versions. Range: 1–40 MB.'), 10),
        'CLAMAV_TIMEOUT_SECONDS': ('Documents', forms.IntegerField(
            min_value=5, max_value=120, label='Malware scanner timeout (seconds)',
            help_text='Uploads remain blocked if scanning fails or times out.'), 15),
        'CPABE_ENCRYPT_PER_MINUTE': ('Documents', forms.IntegerField(
            min_value=1, max_value=60, label='Uploads per user per minute'), 5),
        'CPABE_DECRYPT_PER_MINUTE': ('Documents', forms.IntegerField(
            min_value=1, max_value=120, label='Downloads and previews per user per minute',
            help_text='A shared limit across download and preview endpoints.'), 10),
        'LOGIN_MAX_ATTEMPTS': ('Login protection', forms.IntegerField(
            min_value=3, max_value=20, label='Failed login attempt limit',
            help_text='An account is temporarily blocked after this many failed attempts. Range: 3–20.'), 5),
        'LOGIN_LOCKOUT_SECONDS': ('Login protection', forms.IntegerField(
            min_value=60, max_value=3600, label='Failed login window (seconds)',
            help_text='Window since the last failed attempt. Existing counters keep their expiry. '
                      'Range: 60–3600.'), 900),
        'IMPOSSIBLE_TRAVEL_MINUTES': ('Login protection', forms.IntegerField(
            min_value=1, max_value=1440, label='IP change verification window (minutes)',
            help_text='Requires email verification for a changed public IP within this window. Range: 1–1440.'), 30),
    }


def get_runtime_setting(key):
    """Reject invalid stored values; fall back to deployment value or a safe built-in default."""
    if key == 'SUPER_ADMIN_REQUIRE_POLICY':
        # This revocation control must not reuse a stale worker/Redis cache value.
        # An invalid active value is treated as strict; DB errors propagate rather than enabling bypass.
        from crypto_access.models import SystemSetting
        row = SystemSetting.objects.filter(key=key, is_active=True).first()
        return row.value is not False if row is not None else False
    _, field, default = catalog()[key]
    value = SettingService.get_setting(key, default)
    try:
        # BooleanField accepts arbitrary strings as True; stored JSON must be a real boolean.
        if isinstance(field, forms.BooleanField) and type(value) is not bool:
            raise forms.ValidationError('Expected a boolean.')
        if isinstance(field, forms.IntegerField) and isinstance(value, bool):
            raise forms.ValidationError('Expected an integer.')
        return field.clean(value)
    except forms.ValidationError:
        try:
            return field.clean(default)
        except forms.ValidationError:
            return SAFE_DEFAULTS[key]
