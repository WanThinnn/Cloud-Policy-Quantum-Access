"""Super administrator settings page, using native forms and Django CSRF protection."""
import logging

from django import forms
from django.core import signing
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.conf import settings

from crypto_access.models import AccessLog, SystemSetting
from crypto_access.services.runtime_settings import catalog, get_runtime_setting
from crypto_access.services.runtime_secrets import SMTP_REFERENCE_KEY, store_smtp_password
from crypto_access.services.email_backend import test_smtp_connection

logger = logging.getLogger('crypto_access.system')
REVISION_KEY = '_RUNTIME_SETTINGS_REVISION'


def settings_revision():
    return SystemSetting.objects.filter(key=REVISION_KEY).values_list('value', flat=True).first() or 0


def revision_token():
    return signing.dumps(settings_revision(), salt='runtime-settings')


class RuntimeSettingsForm(forms.Form):
    revision = forms.CharField(widget=forms.HiddenInput)
    smtp_password = forms.CharField(
        required=False, max_length=4096, strip=False, widget=forms.PasswordInput(render_value=False),
        label='New SMTP password',
        help_text='Leave empty to keep the current password. New passwords are stored in Vault.',
    )
    use_deployment_password = forms.BooleanField(required=False, label='Use deployment password again')

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('smtp_password') and cleaned.get('use_deployment_password'):
            raise forms.ValidationError('Choose a new SMTP password or use the deployment password, not both.')
        return cleaned

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key, (_, field, _) in catalog().items():
            self.fields[key] = field
            field.widget.attrs.update({
                'class': 'rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 '
                         'dark:border-gray-600 dark:bg-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500',
                'aria-describedby': f'id_{key}_help id_{key}_errors',
            })
            if isinstance(field, forms.BooleanField):
                field.widget.attrs['class'] = 'h-5 w-5 rounded border-gray-300 accent-blue-700'
            else:
                field.widget.attrs['class'] += ' w-full'
        self.fields['smtp_password'].widget.attrs.update({
            'autocomplete': 'new-password',
            'class': 'w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-gray-900 '
                     'dark:border-gray-600 dark:bg-gray-900 dark:text-white',
        })


@never_cache
@require_http_methods(['GET', 'POST'])
@csrf_protect
@sensitive_post_parameters('smtp_password')
def system_settings_page(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('/auth/login/?next=/manage/settings/')
    try:
        permitted = user.is_active and user.profile.is_super_admin() and user.profile.is_account_active()
    except ObjectDoesNotExist:
        permitted = False
    if not permitted:
        return HttpResponseForbidden('Only an active super administrator can manage system settings.')

    initial = {key: get_runtime_setting(key) for key in catalog()}
    initial['revision'] = revision_token()
    form = RuntimeSettingsForm(request.POST if request.method == 'POST' else None, initial=initial)
    saved = False
    connection_tested = False
    if request.method == 'POST' and form.is_valid():
        unknown = set(request.POST) - set(form.fields) - {'csrfmiddlewaretoken', 'operation'}
        if unknown:
            form.add_error(None, 'The request contains unsupported settings. Reload the page and try again.')
        elif request.POST.get('operation') == 'test_smtp':
            try:
                test_smtp_connection(form.cleaned_data)
                connection_tested = True
            except Exception:
                form.add_error(None, 'SMTP connection failed. Select SMTP delivery and check the server, port, '
                                     'TLS and credentials.')
        elif request.POST.get('operation', 'save') != 'save':
            form.add_error(None, 'Unsupported settings operation.')
        else:
            try:
                with transaction.atomic():
                    submitted_revision = signing.loads(
                        form.cleaned_data['revision'], salt='runtime-settings', max_age=86400,
                    )
                    SystemSetting.objects.get_or_create(key=REVISION_KEY, defaults={'value': 0})
                    revision = SystemSetting.objects.select_for_update().get(key=REVISION_KEY)
                    if submitted_revision != revision.value:
                        raise forms.ValidationError('Settings changed in another tab. Reload this page before saving.')
                    changes = {}
                    # All form fields are validated before writing any setting.
                    active_keys = set(SystemSetting.objects.filter(
                        key__in=catalog(), is_active=True).values_list('key', flat=True))
                    for key in catalog():
                        # An explicit Save adopts deployment defaults into UI-managed configuration.
                        if key not in form.changed_data and key in active_keys:
                            continue
                        value = form.cleaned_data[key]
                        SystemSetting.objects.update_or_create(key=key, defaults={
                            'value': value, 'is_active': True, 'description': form.fields[key].help_text,
                        })
                        changes[key] = {'before': initial[key], 'after': value}
                    if form.cleaned_data.get('smtp_password'):
                        path = store_smtp_password(form.cleaned_data['smtp_password'])
                        SystemSetting.objects.update_or_create(key=SMTP_REFERENCE_KEY, defaults={
                            'value': path, 'is_active': True,
                            'description': 'Reference to an immutable Vault credential.',
                        })
                        changes['smtp_password'] = {'before': '[redacted]', 'after': '[updated]'}
                    elif form.cleaned_data.get('use_deployment_password'):
                        deleted, _ = SystemSetting.objects.filter(key=SMTP_REFERENCE_KEY).delete()
                        if deleted:
                            changes['smtp_password'] = {'before': '[redacted]', 'after': '[deployment default]'}
                    if changes:
                        revision.value += 1
                        revision.save(update_fields=['value', 'updated_at'])
                        AccessLog.log_access(
                            user=user, resource_type='system_setting', resource_id='runtime', action='update',
                            result='allow', request_path=request.path, request_method=request.method,
                            environment_attributes={'changes': changes},
                        )
                saved = True
                public_values = {key: form.cleaned_data[key] for key in catalog()}
                form = RuntimeSettingsForm(initial={**public_values, 'revision': revision_token()})
            except (signing.BadSignature, forms.ValidationError) as error:
                form.add_error(None, error if isinstance(error, forms.ValidationError)
                               else 'This form expired or is invalid. Reload the page before saving.')
            except Exception:
                logger.exception('Unable to save runtime settings')
                form.add_error(None, 'Settings could not be saved. No changes were committed. Please try again.')

    records = {row.key for row in SystemSetting.objects.filter(key__in=form.fields, is_active=True)}
    groups = {}
    for key, (group, _, _) in catalog().items():
        groups.setdefault(group, []).append({
            'field': form[key], 'source': 'Saved setting' if key in records else 'Deployment default',
        })
    return render(request, 'admin/system_settings.html', {
        'form': form, 'groups': groups, 'saved': saved,
        'connection_tested': connection_tested,
        'smtp_password_source': 'Stored in Vault' if SystemSetting.objects.filter(
            key=SMTP_REFERENCE_KEY, is_active=True).exists() else (
                'Deployment password configured' if getattr(settings, 'EMAIL_HOST_PASSWORD', '')
                else 'No password configured'),
    }, status=400 if form.errors else 200)
