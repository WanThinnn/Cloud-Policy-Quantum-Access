"""Resolve delivery settings for each connection instead of mutating Django's global settings."""
from django.core.mail import get_connection
from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail.backends.smtp import EmailBackend as SMTPBackend
from django.conf import settings
from django.views.decorators.debug import sensitive_variables

from .runtime_secrets import get_smtp_password
from .runtime_settings import get_runtime_setting


@sensitive_variables()
def test_smtp_connection(values):
    """Connect and authenticate only. Never send a message or persist form values."""
    if values['EMAIL_DELIVERY_MODE'] != 'smtp':
        raise ValueError('Select SMTP delivery before testing the connection.')
    password = values.get('smtp_password')
    if not password:
        password = (getattr(settings, 'EMAIL_HOST_PASSWORD', '') if values.get('use_deployment_password')
                    else get_smtp_password())
    connection = SMTPBackend(
        host=values['EMAIL_HOST'], port=values['EMAIL_PORT'], username=values['EMAIL_HOST_USER'],
        password=password, use_tls=values['EMAIL_SECURITY'] == 'starttls',
        use_ssl=values['EMAIL_SECURITY'] == 'ssl', timeout=values['EMAIL_TIMEOUT_SECONDS'],
    )
    try:
        connection.open()
    finally:
        connection.close()


class RuntimeEmailBackend(BaseEmailBackend):
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.connection_options = kwargs
        self.connection = None

    @sensitive_variables()
    def open(self):
        if self.connection is None:
            if get_runtime_setting('EMAIL_DELIVERY_MODE') == 'console':
                self.connection = get_connection('django.core.mail.backends.console.EmailBackend',
                                                 fail_silently=self.fail_silently, **self.connection_options)
            else:
                security = get_runtime_setting('EMAIL_SECURITY')
                options = {
                    'host': get_runtime_setting('EMAIL_HOST'), 'port': get_runtime_setting('EMAIL_PORT'),
                    'username': get_runtime_setting('EMAIL_HOST_USER'), 'password': get_smtp_password(),
                    'use_tls': security == 'starttls', 'use_ssl': security == 'ssl',
                    'timeout': get_runtime_setting('EMAIL_TIMEOUT_SECONDS'),
                }
                options.update(self.connection_options)
                self.connection = get_connection('django.core.mail.backends.smtp.EmailBackend',
                                                 fail_silently=self.fail_silently, **options)
        return self.connection.open()

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def send_messages(self, email_messages):
        if not email_messages:
            return 0
        try:
            self.open()
            for message in email_messages:
                message.from_email = get_runtime_setting('DEFAULT_FROM_EMAIL') or get_runtime_setting('EMAIL_HOST_USER')
            return self.connection.send_messages(email_messages)
        finally:
            self.close()
