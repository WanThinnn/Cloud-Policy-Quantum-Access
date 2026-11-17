"""
Admin Page URLs (HTML templates without /api/ prefix)
"""

from django.urls import path
from django.shortcuts import render, redirect
from crypto_access.views import attributes, policy, users, audit
from crypto_access.views.system_settings import system_settings_page

app_name = 'admin_pages'

def files_page(request):
    """Render document management page"""
    from crypto_access.services.agent_packages import public_config
    from crypto_access.services.runtime_settings import get_runtime_setting
    return render(request, 'documents/files.html', {
        'upload_max_size_mb': get_runtime_setting('UPLOAD_MAX_SIZE_MB'),
        'crypto_agent': public_config(request.user),
    })

def trash_page(request):
    """Render trash management page"""
    return render(request, 'documents/trash.html')

def user_attributes_redirect(request):
    """Redirect to users page (merged functionality)"""
    return redirect('admin_pages:users_page')

urlpatterns = [
    path('settings/', system_settings_page, name='system_settings'),
    # Admin template pages (HTML)
    path('users/', users.users_page, name='users_page'),
    path('user-types/', attributes.user_types_page, name='user_types_page'),
    path('attributes/', attributes.attributes_page, name='attributes_page'),
    path('user-attributes/', user_attributes_redirect, name='user_attributes_page'),  # Redirects to users
    path('policies/', policy.policies_page, name='policies_page'),
    path('files/', files_page, name='files_page'),
    path('trash/', trash_page, name='trash_page'),
    path('audit/', audit.audit_logs_page, name='audit_logs_page'),
    path('keys/', audit.key_revocations_page, name='key_revocations_page'),
]
