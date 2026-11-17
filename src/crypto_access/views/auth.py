"""
Authentication Views - Registration, Login, Password Management
"""
from django.contrib.auth.decorators import login_required
from rest_framework import status, generics
from rest_framework.decorators import api_view, permission_classes, throttle_classes, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.http import FileResponse, Http404
from django.urls import reverse
from django.utils import timezone
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from django.conf import settings
from datetime import timedelta
import hashlib
import secrets
import logging
import uuid

logger = logging.getLogger('crypto_access.auth')


class AuthRateThrottle(AnonRateThrottle):
    """Rate limit: 20 attempts per minute for auth endpoints"""
    rate = '20/min'

from ..serializers import (
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserDetailSerializer,
    VerifyOTPSerializer,
)
from ..models import UserProfile, ActiveSession, AccessLog
from ..services import agent_packages
from ..services.session_service import issue_session_tokens, session_key, set_auth_cookies

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# Template views
def login_page(request):
    """Render login page"""
    return render(request, 'accounts/login.html')


def register_page(request):
    """Render register page"""
    return render(request, 'accounts/register.html')

@login_required(login_url='/auth/login/')
def user_profile(request):
    """Render user profile page"""
    from django.shortcuts import render
    return render(request, 'accounts/profile.html', {
        'page_title': 'My Profile'
    })

@login_required(login_url='/auth/login/')
def manage_keys_page(request):
    """Render manage keys page"""
    context = {'page_title': 'Manage Security Keys'}
    context['crypto_agent'] = agent_packages.public_config(request.user)
    if context['crypto_agent']:
        context['agent_packages'] = [
            {
                'label': package['label'],
                'version': package['version'],
                'sha256': package['sha256'],
                'install_command': package.get('install_command'),
                'target': target,
                'url': reverse('crypto_agent_download', args=[target]),
            }
            for target, package in agent_packages.package_catalog().items()
        ]
    return render(request, 'accounts/keys.html', context)


@login_required(login_url='/auth/login/')
@require_safe
def crypto_agent_download(request, target):
    """Stream only an approved installer whose digest matches the catalog."""
    if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False):
        raise Http404()
    package = agent_packages.package_catalog().get(target)
    if package is None:
        raise Http404()
    try:
        stream = package['path'].open('rb')
    except OSError:
        raise Http404() from None
    try:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        if digest.hexdigest() != package['sha256']:
            raise Http404()
        stream.seek(0)
        response = FileResponse(stream, as_attachment=True, filename=package['filename'],
                                content_type='application/octet-stream')
    except Exception:
        stream.close()
        raise
    response['Cache-Control'] = 'private, no-store'
    return response


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([AuthRateThrottle])
def register(request):
    """
    Register new user
    
    POST /api/auth/register/
    Body:
    {
        "username": "nva_it",
        "email": "user@example.com",
        "password": "SecurePass123!",
        "password2": "SecurePass123!",
        "full_name": "Nguyễn Văn A",
        "phone": "0123456789"
    }
    """
    serializer = RegisterSerializer(data=request.data)
    
    if serializer.is_valid():
        user = serializer.save()
        
        # Generate JWT tokens
        access_token, refresh_token = issue_session_tokens(user, ip_address=get_client_ip(request))
        
        logger.info(f"User registered successfully: {user.username} ({user.email})", extra={'user.name': user.username, 'user.id': user.id})
        
        response = Response({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'full_name': user.profile.full_name,
            }
        }, status=status.HTTP_201_CREATED)
        
        # Set HttpOnly cookies
        set_auth_cookies(response, access_token, refresh_token)
        
        return response
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def vpn_auth_verify(request):
    """
    Verify username and password for OpenVPN auth-user-pass
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({'error': 'Missing credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
    user = authenticate(username=username, password=password)
    
    if user is not None and user.is_active:
        logger.info(f"VPN Auth SUCCESS for user: {username}")
        return Response({'message': 'OK'}, status=status.HTTP_200_OK)
    
    logger.warning(f"VPN Auth FAILED for user: {username}")
    return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([AuthRateThrottle])
def login(request):
    """
    Login user
    
    POST /api/auth/login/
    Body:
    {
        "username": "nva_it",
        "password": "SecurePass123!"
    }
    """
    serializer = LoginSerializer(data=request.data)
    
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        from django.core.cache import cache
        
        cache_key = f"failed_login_attempts_{username}"
        attempts = cache.get(cache_key, 0)
        from ..services.runtime_settings import get_runtime_setting
        max_attempts = get_runtime_setting('LOGIN_MAX_ATTEMPTS')
        lockout_seconds = get_runtime_setting('LOGIN_LOCKOUT_SECONDS')
        
        if attempts >= max_attempts:
            logger.warning(f"Login blocked due to too many failed attempts for username: {username}", extra={'user.name': username})
            return Response({
                'error': 'Account locked temporarily due to too many failed attempts. Please try again later.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Check if user account exists and is active BEFORE attempting authentication
        try:
            user_obj = User.objects.get(username=username)
            if not user_obj.is_active:
                logger.warning(f"Login attempt for disabled account: {username}", extra={'user.name': username})
                return Response({
                    'error': 'Account is disabled'
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            pass  # Don't reveal whether username exists
        
        user = authenticate(username=username, password=password)
        
        if user is None:
            cache.set(cache_key, attempts + 1, lockout_seconds)
            logger.warning(f"Failed login attempt for username: {username} from IP: {get_client_ip(request)}", extra={'user.name': username})
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
            
        # Reset failed attempts on success
        cache.delete(cache_key)
        
        # Check account status
        if hasattr(user, 'profile'):
            if not user.profile.is_account_active():
                return Response({
                    'error': f'Account is {user.profile.account_status}'
                }, status=status.HTTP_403_FORBIDDEN)
        
        # Generate JWT tokens
        
        # --- Session Management & Impossible Travel ---
        ip_address = get_client_ip(request)
        user_agent_str = request.META.get('HTTP_USER_AGENT', '')
        
        browser = "Unknown Browser"
        os_name = "Unknown OS"
        if "Chrome" in user_agent_str: browser = "Chrome"
        elif "Firefox" in user_agent_str: browser = "Firefox"
        elif "Safari" in user_agent_str and "Chrome" not in user_agent_str: browser = "Safari"
        elif "Edge" in user_agent_str: browser = "Edge"
        
        if "Windows" in user_agent_str: os_name = "Windows"
        elif "Mac OS" in user_agent_str: os_name = "macOS"
        elif "Linux" in user_agent_str: os_name = "Linux"
        elif "Android" in user_agent_str: os_name = "Android"
        elif "iPhone" in user_agent_str or "iPad" in user_agent_str: os_name = "iOS"
        
        # Impossible Travel Check
        # Check SystemSetting for threshold, default 30 mins (1800s)
        import json
        threshold_minutes = get_runtime_setting('IMPOSSIBLE_TRAVEL_MINUTES')
        
        last_session = ActiveSession.objects.filter(user=user, is_active=True).order_by('-last_active').first()
        if last_session and last_session.ip_address and ip_address:
            is_local = lambda ip: ip.startswith('172.') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.')
            if not is_local(ip_address) and not is_local(last_session.ip_address):
                if ip_address != last_session.ip_address:
                    time_diff = timezone.now() - last_session.last_active
                    if time_diff.total_seconds() < (threshold_minutes * 60):
                        # Generate OTP
                        otp_code = f"{secrets.randbelow(1000000):06d}"
                        temp_token = str(uuid.uuid4())
                        
                        cache.set(f"otp_{temp_token}", {
                            "user_id": user.id,
                            "otp": otp_code,
                            "ip_address": ip_address,
                            "user_agent_str": user_agent_str,
                            "browser": browser,
                            "os_name": os_name
                        }, timeout=300)
                        
                        # Send Email
                        from django.core.mail import EmailMultiAlternatives
                        from django.template.loader import render_to_string
                        
                        context = {
                            'user': user,
                            'otp_code': otp_code,
                            'ip_address': ip_address,
                            'browser': browser,
                            'os_name': os_name,
                        }
                        
                        try:
                            html_content = render_to_string('accounts/otp_email.html', context)
                            text_content = render_to_string('accounts/otp_email.txt', context)
                            
                            msg = EmailMultiAlternatives(
                                subject="New Device Login Verification - OTP Code",
                                body=text_content,
                                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@cloudsafe.local'),
                                to=[user.email]
                            )
                            msg.attach_alternative(html_content, "text/html")
                            msg.send(fail_silently=True)
                        except Exception as e:
                            logger.error(f"Failed to send OTP email: {e}")
                        
                        AccessLog.log_access(
                            user=user,
                            resource_type='account',
                            action='login',
                            result='error',  # using 'error' or 'deny' since 'warning' is not in RESULT_CHOICES
                            error_message=f'Impossible Travel detected. OTP requested for IP: {ip_address}'
                        )
                        return Response({
                            'message': 'Login attempt from new IP address. Please check your email for the OTP code.',
                            'requires_otp': True,
                            'temp_token': temp_token
                        }, status=status.HTTP_202_ACCEPTED)
        
        access_token, refresh_token = issue_session_tokens(
            user, ip_address=ip_address, browser=browser, os_name=os_name, device_name=user_agent_str[:200],
        )

        response = Response({
            'message': 'Login successful',
            'user': UserDetailSerializer(user).data
        })
        
        # Set HttpOnly cookies
        set_auth_cookies(response, access_token, refresh_token)
        
        return response
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([AuthRateThrottle])
def verify_otp(request):
    """
    Verify OTP for Impossible Travel login
    
    POST /api/auth/verify-otp/
    Body:
    {
        "temp_token": "uuid-here",
        "otp": "123456"
    }
    """
    serializer = VerifyOTPSerializer(data=request.data)
    
    if serializer.is_valid():
        from django.core.cache import cache
        temp_token = serializer.validated_data['temp_token']
        otp = serializer.validated_data['otp']
        
        cached_data = cache.get(f"otp_{temp_token}")
        
        if not cached_data:
            return Response({
                'error': 'OTP has expired. Please login again.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # OTP attempt counter — lock after 5 failed attempts
        otp_attempts_key = f"otp_attempts_{temp_token}"
        otp_attempts = cache.get(otp_attempts_key, 0)
        if otp_attempts >= 5:
            cache.delete(f"otp_{temp_token}")
            return Response({
                'error': 'Too many failed OTP attempts. Please login again.'
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        if cached_data['otp'] != otp:
            cache.set(otp_attempts_key, otp_attempts + 1, 300)
            return Response({
                'error': 'Invalid OTP code.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Valid OTP -> Process Login
        user = User.objects.get(id=cached_data['user_id'])
        cache.delete(f"otp_{temp_token}")
        
        # Log successful verify
        AccessLog.log_access(
            user=user,
            resource_type='account',
            action='verify_otp',
            result='allow',
            error_message=f"OTP verification successful for IP: {cached_data['ip_address']}"
        )
        
        access_token, refresh_token = issue_session_tokens(
            user, ip_address=cached_data['ip_address'], browser=cached_data['browser'],
            os_name=cached_data['os_name'], device_name=cached_data['user_agent_str'][:200],
        )

        response = Response({
            'message': 'Login successful',
            'user': UserDetailSerializer(user).data
        })
        
        # Set HttpOnly cookies
        set_auth_cookies(response, access_token, refresh_token)
        
        return response
        
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """Revoke the authenticated session, including every access/refresh token bound to it."""
    if request.auth is not None:
        ActiveSession.objects.filter(
            user=request.user, session_key=session_key(request.auth),
        ).update(is_active=False)
    response = Response({'message': 'Logout successful'})
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change password for authenticated user
    
    POST /api/auth/change-password/
    Body:
    {
        "old_password": "OldPass123!",
        "new_password": "NewPass123!",
        "new_password2": "NewPass123!"
    }
    """
    serializer = ChangePasswordSerializer(data=request.data)
    
    if serializer.is_valid():
        user = request.user
        
        # Check old password
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({
                'error': 'Old password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({
            'message': 'Password changed successfully'
        })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
@throttle_classes([AuthRateThrottle])
def password_reset_request(request):
    """
    Request password reset (send reset token)
    
    POST /api/auth/password-reset/request/
    Body:
    {
        "email": "user@example.com"
    }
    """
    serializer = PasswordResetRequestSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email=email)
            profile = user.profile
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            profile.password_reset_token = reset_token
            profile.password_reset_expires = timezone.now() + timedelta(hours=1)
            profile.save()
            
            # TODO: Send email with reset link
            # send_password_reset_email(user.email, reset_token)
            
            logger.info(f"[AUTH] Password reset token generated for {email}")
            
            return Response({
                'message': 'Password reset instructions sent to email'
            })
            
        except User.DoesNotExist:
            # Don't reveal if email exists
            return Response({
                'message': 'If email exists, reset instructions will be sent'
            })
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([])
def password_reset_confirm(request):
    """
    Confirm password reset with token
    
    POST /api/auth/password-reset/confirm/
    Body:
    {
        "token": "<reset_token>",
        "new_password": "NewPass123!",
        "new_password2": "NewPass123!"
    }
    """
    serializer = PasswordResetConfirmSerializer(data=request.data)
    
    if serializer.is_valid():
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']
        
        try:
            profile = UserProfile.objects.get(password_reset_token=token)
            
            # Check token expiry
            if profile.password_reset_expires < timezone.now():
                return Response({
                    'error': 'Reset token has expired'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Reset password
            user = profile.user
            user.set_password(new_password)
            user.save()
            
            # Clear reset token
            profile.password_reset_token = None
            profile.password_reset_expires = None
            profile.save()
            
            return Response({
                'message': 'Password reset successfully'
            })
            
        except UserProfile.DoesNotExist:
            return Response({
                'error': 'Invalid reset token'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """
    Get current user profile
    
    GET /api/auth/profile/
    """
    serializer = UserDetailSerializer(request.user)
    return Response(serializer.data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_permissions(request):
    """
    Get current user's permissions and role info
    Used by frontend to show/hide admin menu items and control features
    
    GET /api/auth/permissions/
    """
    user = request.user
    
    # Default permissions
    permissions = {
        'is_authenticated': True,
        'is_admin': False,
        'is_super_admin': False,
        'user_type': None,
        'can_manage_users': False,
        'can_manage_policies': False,
        'can_manage_files': False,
        'can_view_audit_logs': False,
        # File permissions (for files manager)
        'can_upload_files': False,
        'can_download_files': False,
        'can_delete_files': False,
    }
    
    if hasattr(user, 'profile') and user.profile:
        profile = user.profile
        user_type = profile.get_user_type_code()
        
        # Import casbin service to evaluate ABAC policies
        from crypto_access.services.casbin_service import casbin_service
        from crypto_access.services.casbin_service import casbin_service
        
        permissions.update({
            'user_type': user_type,
            'is_admin': profile.is_admin(),
            'is_super_admin': profile.is_super_admin(),
            # Base Admin UI toggles (Requires at least admin status)
            'can_access_admin': profile.is_admin() or profile.is_super_admin(),
            # ABAC-based Management Permissions
            'can_manage_users': casbin_service.check_access(user, 'user', '*'),
            'can_manage_policies': casbin_service.check_access(user, 'policy', '*'),
            'can_manage_keys': casbin_service.check_access(user, 'key', '*'),
            'can_view_audit_logs': casbin_service.check_access(user, 'audit', 'read'),
            'can_manage_attributes': casbin_service.check_access(user, 'attribute', '*'),
            # File system generic checks
            'can_manage_files': user_type in ['super_admin', 'admin', 'data_owner'],
            # File permissions based on ABAC
            'can_upload_files': casbin_service.check_access(user, 'document', 'upload'),
            'can_download_files': casbin_service.check_access(user, 'document', 'download'),
            'can_delete_files': casbin_service.check_access(user, 'document', 'delete'),
        })
    
    return Response(permissions)
