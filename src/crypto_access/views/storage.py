"""
Storage Views - API endpoints for file operations
"""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import APIException, NotFound, PermissionDenied, ValidationError
from crypto_access.permissions import IsSuperAdmin
from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta
import uuid
import logging
import hashlib
import json
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q
import tempfile
import os
import urllib.parse

from ..models import StorageBucket, UploadedFile, FileAccessPolicy, AccessPolicy, FileVersion, UserPublicKey
from ..serializers import (
    StorageBucketSerializer,
    UploadedFileSerializer,
    FileUploadSerializer,
    SignedUrlRequestSerializer
)
from ..serializers.storage import (
    FileAccessPolicySerializer,
    DocumentSignatureRequestSerializer,
    AssignPolicyToFileSerializer,
    PolicyListForAssignmentSerializer,
    RestoreFileVersionSerializer,
)
from ..serializers.policy import AccessPolicySerializer
from ..services.storage.factory import get_storage_service
from ..services import native_signing
from ..services.cpabe_service import CPABEAccessDenied, CPABEVaultUnavailable, cpabe_service
from ..services.casbin_service import casbin_service
from ..services.tkn20_policy import bypass_attributes
from ..services.document_access import can_bypass_document_policy, is_document_administrator, requires_document_policy
from ..services.version_crypto import (
    CryptoMetadataError, PLAINTEXT_METADATA, metadata_for_read, persist_verified_metadata, validate_metadata,
)
from ..throttles import CPABEDecryptThrottle, CPABEEncryptThrottle
import time

def get_db_file_by_path(bucket_name, file_path):
    from crypto_access.models import UploadedFile
    return UploadedFile.find_by_path(bucket_name, file_path)

logger = logging.getLogger('crypto_access.storage')


class CryptoServiceUnavailable(APIException):
    status_code = 503
    default_detail = 'The Vault crypto service is temporarily unavailable.'
    default_code = 'crypto_service_unavailable'


class StorageBucketViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing storage buckets
    """
    queryset = StorageBucket.objects.all()
    serializer_class = StorageBucketSerializer
    permission_classes = [IsAuthenticated, IsSuperAdmin]
    
    @action(detail=True, methods=['post'])
    def create_in_supabase(self, request, pk=None):
        """Create bucket in Supabase Storage"""
        bucket = self.get_object()
        storage = get_storage_service()
        
        try:
            result = storage.create_bucket(
                bucket_name=bucket.name,
                public=(bucket.bucket_type == 'public'),
                allowed_mime_types=bucket.allowed_mime_types if bucket.allowed_mime_types else None,
                file_size_limit=bucket.max_file_size
            )
            return Response({
                'message': f"Bucket '{bucket.name}' created in Supabase",
                'result': result
            })
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def list_supabase_buckets(self, request):
        """List all buckets from Supabase"""
        storage = get_storage_service()
        try:
            buckets = storage.list_buckets()
            return Response({'buckets': buckets})
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class UploadedFileViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing uploaded files
    """
    queryset = UploadedFile.objects.select_related('bucket', 'uploaded_by').all()
    serializer_class = UploadedFileSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def _prepare_inline_policy(self, request, data):
        """Validate a global policy without persisting it or extending file-owner rights."""
        if not data.get('create_new_policy'):
            return None
        # Match the policy management API's role and ABAC requirements.
        if not IsSuperAdmin().has_permission(request, self) or not casbin_service.check_access(
            request.user, 'policy', '*'
        ):
            raise PermissionDenied("You do not have permission to create global access policies.")
        serializer = AccessPolicySerializer(data={
            'name': data['new_policy_name'],
            'description': data.get('new_policy_description', ''),
            'subject_condition': data['new_policy_subject_condition'],
            'resource': data.get('new_policy_resource', 'document'),
            'action': data.get('new_policy_action', 'read'),
            'effect': data.get('new_policy_effect', 'allow'),
            'priority': data.get('new_policy_priority', 100),
        }, context={'request': request})
        serializer.is_valid(raise_exception=True)
        policy = AccessPolicy(**serializer.validated_data, created_by=request.user)
        policy.cpabe_policy = policy._generate_cpabe_policy()
        return policy
    
    def _decrypt_file_if_needed(self, file_data, bucket_name, file_path, user, is_owner=False,
                                cpabe_policy_str=None, access_action='read', file_version=None):
        """Helper to decrypt file if it has a CP-ABE policy"""
        strict = requires_document_policy(user)
        if strict:
            self._require_document_read(user, bucket_name, file_path, access_action)

        if file_version is not None:
            cpabe_policy_str = file_version.cpabe_policy
        if cpabe_policy_str is not None:
            is_encrypted = bool(cpabe_policy_str)
            policies_to_parse = [cpabe_policy_str] if is_encrypted else []
        else:
            file_policies = FileAccessPolicy.get_policies_for_file(bucket_name, file_path)
            is_encrypted = any(p.cpabe_policy for p in file_policies)
            policies_to_parse = [p.cpabe_policy for p in file_policies if p.cpabe_policy]
        
        if not is_encrypted and file_version is None:
            return file_data
        from django.conf import settings
        backend = 'vault' if getattr(settings, 'USE_VAULT_ABE_PLUGIN', False) else 'native'
        crypto_metadata, legacy_metadata = metadata_for_read(file_version, file_data, backend=backend)
        if crypto_metadata['format'] == 'plaintext':
            persist_verified_metadata(file_version, crypto_metadata)
            return file_data
        abe_scheme = crypto_metadata['scheme']
        route = None
        if crypto_metadata['schema'] == 2 or (backend == 'vault' and abe_scheme == 'covercrypt'):
            try:
                route = cpabe_service.verify_version_authority(crypto_metadata)
            except CPABEVaultUnavailable:
                raise CryptoServiceUnavailable() from None
        crypto_options = {'route': route} if route is not None else {}

        user_attrs = casbin_service.get_user_attributes(user)
        
        # CP-ABE Bypass for SuperAdmin and File Owner
        # Only an already-authorized non-strict bypass may request a satisfying key.
        privileged_bypass = not strict and (can_bypass_document_policy(user) or is_owner)
        if privileged_bypass and abe_scheme == 'tkn20':
            user_attrs = bypass_attributes(user_attrs, policies_to_parse)
        elif privileged_bypass and abe_scheme == 'covercrypt':
            from ..services.covercrypt_policy import bypass_attributes as covercrypt_bypass_attributes
            try:
                user_attrs = covercrypt_bypass_attributes(
                    user_attrs, policies_to_parse, configuration=route.configuration if route else None,
                )
            except ValueError as exc:
                raise PermissionDenied('CoverCrypt policy cannot be satisfied by a valid bypass key.') from exc
        elif privileged_bypass:
            import re
            for p_str in policies_to_parse:
                if p_str:
                    tokens = re.findall(r'[a-zA-Z0-9_]+:[a-zA-Z0-9_]+', p_str)
                    for token in tokens:
                        k, v = token.split(':', 1)
                        if k not in user_attrs:
                            user_attrs[k] = []
                        if isinstance(user_attrs[k], list):
                            if v not in user_attrs[k]:
                                user_attrs[k].append(v)
                        else:
                            if user_attrs[k] != v:
                                user_attrs[k] = [user_attrs[k], v]
        
        try:
            internal_decrypt = backend == 'vault' and getattr(settings, 'VAULT_ABE_INTERNAL_DECRYPT', False)
            if internal_decrypt:
                key = None
            elif backend == 'vault':
                key = cpabe_service.generate_user_key_bytes(user_attrs, scheme=abe_scheme, **crypto_options)
            else:
                key = self._native_user_key(user, user_attrs, abe_scheme, strict, privileged_bypass)
            decrypt = (cpabe_service.decrypt_buffer_and_verify if crypto_metadata['pqc_signed']
                       else cpabe_service.decrypt_buffer)
            try:
                if internal_decrypt:
                    decrypted = cpabe_service.decrypt_with_attributes(user_attrs, file_data, crypto_metadata, **crypto_options)
                else:
                    decrypted = decrypt(key, file_data, scheme=abe_scheme, **crypto_options)
            except CPABEAccessDenied:
                if legacy_metadata:
                    raise CryptoMetadataError('Historical crypto metadata could not be verified; recovery is required.') from None
                raise
            except CPABEVaultUnavailable:
                raise
            except Exception as exc:
                logger.error('CP-ABE decryption failed (%s).', type(exc).__name__)
                if legacy_metadata:
                    raise CryptoMetadataError('Historical crypto metadata could not be verified; recovery is required.') from None
                raise Exception("You don't have permission to see this file!") from None
            finally:
                del key
        except CPABEVaultUnavailable:
            raise CryptoServiceUnavailable() from None
        except CPABEAccessDenied as exc:
            raise PermissionDenied(str(exc)) from exc

        if legacy_metadata:
            persist_verified_metadata(file_version, crypto_metadata)
        return decrypted

    def _native_user_key(self, user, user_attrs, abe_scheme, strict, privileged_bypass):
        from ..models import KeyRevocation

        revocation_id = KeyRevocation.user_cache_generation(user.id)
        # Calculate cache key based on attributes
        attrs_str = json.dumps(user_attrs, sort_keys=True)
        attrs_hash = hashlib.sha3_256(attrs_str.encode('utf-8')).hexdigest()
        cache_key = f"cpabe_key_{abe_scheme}_{user.id}_{attrs_hash}"
        if strict:
            # Never reuse an attribute-forged key generated before the switch was enabled.
            cache_key = f"cpabe_key_{abe_scheme}_strict_v1_{user.id}_{attrs_hash}"
        if privileged_bypass and abe_scheme == 'tkn20':
            # Old keys may contain silently overwritten duplicate TKN20 labels.
            cache_key = f"cpabe_key_{abe_scheme}_bypass_v2_{user.id}_{attrs_hash}"
        if privileged_bypass and abe_scheme == 'covercrypt':
            cache_key = f"cpabe_key_covercrypt_bypass_v1_{user.id}_{attrs_hash}"
        if abe_scheme == 'covercrypt':
            # User keys are authority/configuration specific; do not reuse a cache
            # entry after an operator changes CoverCrypt dimensions or keyset.
            cache_key += f'_authority_{cpabe_service.covercrypt_cache_identity()}'
        cache_key += '_meta_v1_native'
        if revocation_id:
            identity = f'{cache_key}:{revocation_id}::'
            cache_key = f'cpabe_key_{abe_scheme}_scoped_{user.id}_{hashlib.sha256(identity.encode()).hexdigest()}'
        encrypted_cached_key = cache.get(cache_key)
        
        cached_key_data = None
        from ..models.fields import encrypt_bytes, decrypt_bytes
        cache_info = f"cpabe_cache_{user.id}".encode('utf-8')
        cache_aad = cache_key.encode('utf-8')
        
        if encrypted_cached_key:
            try:
                cached_key_data = decrypt_bytes(encrypted_cached_key, info=cache_info, aad=cache_aad)
            except Exception:
                logger.warning('Failed to decrypt cached native CP-ABE key, regenerating.')
                cached_key_data = None
        
        if cached_key_data:
            return cached_key_data
        with tempfile.NamedTemporaryFile(delete=False) as key_file:
            path = key_file.name
        try:
            cpabe_service.generate_user_key(user_attrs, path, scheme=abe_scheme)
            with open(path, 'rb') as key_file:
                key = key_file.read()
        finally:
            if os.path.exists(path):
                os.remove(path)
        cache.set(cache_key, encrypt_bytes(key, info=cache_info, aad=cache_aad), timeout=3600)
        return key

    def get_queryset(self):
        """Filter files by user, bucket, and ABAC policies"""
        from crypto_access.models.storage import UploadedFile, StorageBucket, FileAccessPolicy, FileVersion
        from crypto_access.services.casbin_service import casbin_service
        
        queryset = super().get_queryset().filter(is_deleted=False)
        
        # Filter by bucket
        bucket_name = self.request.query_params.get('bucket', None)
        if bucket_name:
            queryset = queryset.filter(bucket__name=bucket_name)
        
        # Filter by file type
        file_type = self.request.query_params.get('type', None)
        if file_type:
            queryset = queryset.filter(file_type=file_type)
            
        # Secure Search by file_name (via Blind Index)
        search_name = self.request.query_params.get('search_name', None)
        if search_name:
            from django.conf import settings
            if getattr(settings, 'FIELD_ENCRYPTION', False):
                from crypto_access.models.fields import get_encryption_key
                import hmac
                import hashlib
                key = get_encryption_key(info=b"blind_index")
                h = hmac.new(key, str(search_name).encode('utf-8'), hashlib.sha3_256)
                hash_value = h.hexdigest()
                queryset = queryset.filter(file_name_hash=hash_value)
            else:
                queryset = queryset.filter(file_name__icontains=search_name)
        
        # Filter by user
        my_files = self.request.query_params.get('my_files', None)
        if my_files and self.request.user.is_authenticated:
            queryset = queryset.filter(uploaded_by=self.request.user)
        
        # ABAC Post-filtering: only return files the user is allowed to see
        if self.request.user.is_authenticated and requires_document_policy(self.request.user):
            # Reuse the authoritative evaluator, including inherited policies and deny priority.
            policy_action = 'download' if getattr(self, 'action', None) == 'download' else 'read'
            allowed_ids = [row.pk for row in queryset if casbin_service.check_file_access_with_fallback(
                self.request.user, row.bucket.name, row.file_path, policy_action
            )[0]]
            return queryset.filter(pk__in=allowed_ids)
        if self.request.user.is_authenticated and not can_bypass_document_policy(self.request.user):
            # Step 1: Pre-evaluate which policies this user satisfies
            allowed_policy_ids = casbin_service.get_allowed_policies_for_user(
                self.request.user, 'read'
            )
            
            # Step 2: Check if user has general read access via ABAC
            has_general_read = casbin_service.check_access(
                self.request.user, 'document', 'read'
            )
            
            # Step 3: Build Q filter conditions
            # Condition A: User is the file owner (always allowed)
            condition = Q(uploaded_by=self.request.user)
            
            # Condition B: File has a policy that matches user's allowed policies
            if allowed_policy_ids:
                condition |= Q(access_policies__policy_id__in=allowed_policy_ids)
            
            # Condition C: File has no policy assigned AND user has general read access
            if has_general_read:
                condition |= Q(access_policies__isnull=True)
            
            queryset = queryset.filter(condition).distinct()
        
        return queryset
    
    def _require_document_read(self, user, bucket_name, file_path, action='read'):
        if requires_document_policy(user):
            allowed, _ = casbin_service.check_file_access_with_fallback(user, bucket_name, file_path, action)
            if not allowed:
                raise PermissionDenied('Your attributes do not grant access to this document.')

    @action(detail=False, methods=['post'], throttle_classes=[CPABEEncryptThrottle])
    def prepare_document_signature(self, request):
        if not casbin_service.check_access(request.user, 'document', 'upload'):
            raise PermissionDenied('Document upload permission is required.')
        serializer = DocumentSignatureRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        value = serializer.validated_data
        bucket = StorageBucket.objects.filter(name=value['bucket_name']).first()
        if bucket is None:
            raise NotFound()
        key = UserPublicKey.objects.filter(
            user=request.user, native_device_id=value['device_id'], status='active',
        ).first()
        if key is None:
            raise PermissionDenied('The signing device is not authorized.')
        existing = UploadedFile.find_by_path(bucket.name, value['file_path'])
        if bool(existing) != value['is_new_version']:
            raise native_signing.SigningConflict()
        if existing and existing.uploaded_by_id != request.user.pk and not request.user.is_superuser:
            raise PermissionDenied('Only the owner can submit a new version.')
        latest = existing.get_latest_version() if existing else None
        version = latest.version_number + 1 if latest else (2 if existing else 1)
        intent = native_signing.issue(
            request, 'sign_document', key=key, device_id=str(key.native_device_id),
            key_id=key.pk, sha3_256=value['sha3_256'],
            **native_signing.version_target(bucket, value['file_path'], existing, version),
        )
        return Response({'request_id': intent.pk, 'payload': intent.payload}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['post'], throttle_classes=[CPABEEncryptThrottle])
    @transaction.atomic
    def upload(self, request):
        """
        Upload file to Supabase Storage
        Protected by ABAC middleware - requires 'upload' permission on 'document'
        
        POST /api/files/upload/
        Content-Type: multipart/form-data
        
        Body:
        - file: File to upload
        - bucket_name: Target bucket name
        - file_path: Optional custom path (auto-generated if not provided)
        - description: Optional description
        - tags: Optional tags (JSON array)
        - is_public: Boolean (default: False)
        """
        from ..services.abe_schemes import UnsupportedABEScheme, validate_scheme
        try:
            validate_scheme()
        except UnsupportedABEScheme as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = FileUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        from django.conf import settings
        signing_request_id = serializer.validated_data.get('signing_request_id')
        if getattr(settings, 'NATIVE_SIGNING_REQUIRED', False) and not signing_request_id:
            raise PermissionDenied('A native document signature is required.')
        if signing_request_id and not getattr(settings, 'NATIVE_SIGNING_ENABLED', False):
            raise PermissionDenied('Native signing is disabled.')
        new_policy = self._prepare_inline_policy(request, serializer.validated_data)
        
        file = serializer.validated_data['file']
        bucket_name = serializer.validated_data['bucket_name']
        description = serializer.validated_data.get('description', '')
        tags = serializer.validated_data.get('tags', [])
        is_public = serializer.validated_data.get('is_public', False)
        user_signature = serializer.validated_data.get('user_signature', None)
        
        
        # Metadata extraction
        custom_metadata = request.data.get('metadata', '{}')
        if isinstance(custom_metadata, str):
            import json
            try:
                custom_metadata = json.loads(custom_metadata)
            except:
                custom_metadata = {}
        
        # Auto-detect context
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0]
            
        uploader_info = {}
        if request.user.is_authenticated:
            uploader_info['uploader_username'] = request.user.username
            uploader_info['uploader_email'] = request.user.email
            try:
                profile = getattr(request.user, 'profile', None)
                if profile:
                    uploader_info['uploader_name'] = profile.full_name
                    uploader_info['uploader_role'] = profile.get_user_type_code()
            except Exception:
                pass
            
        file_metadata = {
            'original_filename': file.name,
            'client_ip': client_ip,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'upload_source': 'web_api',
            'file_size_bytes': file.size,
            'mime_type': file.content_type,
            **uploader_info,
            **custom_metadata
        }
        policy_id = serializer.validated_data.get('policy_id')
        policy_obj = None
        cpabe_policy_str = None
        
        if serializer.validated_data.get('create_new_policy'):
            policy_obj = new_policy
            cpabe_policy_str = policy_obj.cpabe_policy
        elif policy_id:
            try:
                policy_obj = AccessPolicy.objects.get(id=policy_id)
                cpabe_policy_str = policy_obj.cpabe_policy
            except AccessPolicy.DoesNotExist:
                pass
        
        # Get or create bucket
        try:
            bucket = StorageBucket.objects.select_for_update().get(name=bucket_name)
        except StorageBucket.DoesNotExist:
            return Response(
                {'error': f"Bucket '{bucket_name}' not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Determine logical file_path
        file_path = serializer.validated_data.get('file_path')
        if not file_path:
            ext = file.name.split('.')[-1] if '.' in file.name else ''
            unique_name = f"{uuid.uuid4()}.{ext}" if ext else str(uuid.uuid4())
            file_path = f"{timezone.now().strftime('%Y/%m/%d')}/{unique_name}"
            
        # Check if file exists for versioning
        from django.conf import settings
        field_encryption = getattr(settings, 'FIELD_ENCRYPTION', False)
        
        if field_encryption:
            from crypto_access.models.fields import get_encryption_key
            import hmac
            key = get_encryption_key(info=b"blind_index")
            h = hmac.new(key, str(file_path).encode('utf-8'), hashlib.sha3_256)
            hash_value = h.hexdigest()
            existing_file = UploadedFile.objects.select_for_update().filter(bucket=bucket, file_path_hash=hash_value).first()
        else:
            existing_file = UploadedFile.objects.select_for_update().filter(bucket=bucket, file_path=file_path).first()
            
        is_new_version_val = request.data.get('is_new_version', 'false')
        #print(f"DEBUG: is_new_version received = {is_new_version_val} (type: {type(is_new_version_val)})")
        is_new_version = str(is_new_version_val).lower() == 'true'
        #print(f"DEBUG: is_new_version parsed = {is_new_version}")
        
        version_number = 1
        
        # Obfuscate physical path if encryption is enabled
        parts = file_path.split('/')
        folder_path = '/'.join(parts[:-1]) if len(parts) > 1 else ''
        ext = parts[-1].split('.')[-1] if '.' in parts[-1] else ''
        
        if field_encryption:
            unique_name = f"{uuid.uuid4()}.{ext}" if ext else str(uuid.uuid4())
            physical_path = f"{folder_path}/{unique_name}" if folder_path else unique_name
        else:
            physical_path = file_path
        
        if existing_file:
            if not is_new_version:
                return Response(
                    {'error': 'This file already exists. Please rename the file before uploading a new one, or right-click the existing file and select "Upload New Version".'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # SECURITY CHECK: Only the file owner (or superuser) can upload a new version
            if existing_file.uploaded_by != request.user and not request.user.is_superuser:
                return Response(
                    {'error': 'Permission denied. Only the owner of this file can upload a new version.'},
                    status=status.HTTP_403_FORBIDDEN
                )
                
            latest_version = existing_file.get_latest_version()
            version_number = (latest_version.version_number + 1) if latest_version else 2
            if not field_encryption:
                physical_path = f"{file_path}_v{version_number}"
        
        # Upload to Supabase
        storage = get_storage_service()
        
        # Check inherited policies from folders if no direct policy_id was provided
        if not cpabe_policy_str:
            inherited_policies = FileAccessPolicy.get_policies_for_file(bucket_name, file_path)
            for p in inherited_policies:
                if p.cpabe_policy:
                    cpabe_policy_str = p.cpabe_policy
                    logger.info(f"Inheriting CP-ABE policy from folder: {cpabe_policy_str}")
                    break
        
        try:
            # OPTIMIZATION: Chunked Hashing (Avoid duplicating massive buffers in RAM)
            import hashlib
            plaintext_hasher = hashlib.sha3_256()
            for chunk in file.chunks():
                plaintext_hasher.update(chunk)
            plaintext_file_hash = plaintext_hasher.hexdigest()
            
            # Reset file pointer for reading into buffer for CP-ABE
            file.seek(0)
            plaintext_data = file.read()
            signer_key = None
            signing_payload = ''
            if signing_request_id:
                if not user_signature or not serializer.validated_data.get('file_path'):
                    raise ValidationError('A native signing request requires a signature and an explicit file path.')
                target = native_signing.version_target(bucket, file_path, existing_file, version_number)
                signer_key, signing_payload = native_signing.verify_upload(
                    request, signing_request_id, user_signature, plaintext_file_hash, target,
                )
            elif user_signature:
                signer_key = request.user.pqc_keys.filter(status='active', native_device_id__isnull=True).first()
                if signer_key is None:
                    raise ValidationError('An active browser signing key is required.')
                native_signing.verify_signature(signer_key.pqc_public_key, user_signature, plaintext_data)
            
            # SYNCHRONOUS MALWARE SCAN (EARLY REJECTION)
            # Quét virus ngay lập tức trước khi thực hiện mã hóa CP-ABE nặng nề
            from ..services.clamav_service import clamav_service
            is_safe, msg = clamav_service.scan_file_buffer(plaintext_data)
            if not is_safe:
                transaction.set_rollback(True)
                logger.warning(f"Upload rejected by Anti-Virus: {msg}")
                return Response(
                    {'error': f'Upload failed: malware detected ({msg})'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            file_metadata['clamav_scan'] = 'clean'
            
            # Encrypt if policy has cpabe_policy
            from django.conf import settings
            current_scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
            crypto_metadata = dict(PLAINTEXT_METADATA)
            if cpabe_policy_str:
                # Attempt to encrypt with CP-ABE before uploading
                logger.info(f"Encrypting file with CP-ABE policy: {cpabe_policy_str} (Scheme: {current_scheme})", extra={"user.name": request.user.username, "user.id": request.user.id})
                file_data, crypto_metadata = cpabe_service.encrypt_version(
                    plaintext_data, cpabe_policy_str, scheme=current_scheme,
                    pqc_signed=bool(getattr(settings, 'ENABLE_PQC_FEATURES', False)),
                )
            else:
                file_data = plaintext_data

            upload_result = storage.upload_file(
                bucket_name=bucket_name,
                file_path=physical_path,
                file_data=file_data,
                content_type=file.content_type,
                upsert=True,
                user=request.user
            )
            
            # Get URL (Note: For public files, we use the physical path)
            if bucket.bucket_type == 'public':
                file_url = storage.get_public_url(bucket_name, physical_path)
                signed_url = None
                signed_url_expires_at = None
            else:
                file_url = None
                signed_url = storage.create_signed_url(bucket_name, physical_path, expires_in=3600)
                signed_url_expires_at = timezone.now() + timedelta(seconds=3600)
            
            # Save to database
            if existing_file:
                uploaded_file = existing_file
                uploaded_file.file_size = file.size
                uploaded_file.is_deleted = False
                uploaded_file.deleted_at = None
                
                # Merge existing metadata with new metadata
                if not isinstance(uploaded_file.metadata, dict):
                    uploaded_file.metadata = {}
                uploaded_file.metadata.update(file_metadata)
                
                # If file is encrypted, update its scheme to the current one
                if cpabe_policy_str:
                    uploaded_file.abe_scheme = current_scheme
                
                uploaded_file.save(update_fields=['file_size', 'updated_at', 'is_deleted', 'deleted_at', 'metadata', 'abe_scheme'])
            else:
                uploaded_file = UploadedFile.objects.create(
                    bucket=bucket,
                    file_path=file_path,
                    file_name=file.name,
                    file_type=UploadedFile.detect_file_type(file.content_type),
                    mime_type=file.content_type,
                    file_size=file.size,
                    public_url=file_url,
                    signed_url=signed_url,
                    signed_url_expires_at=signed_url_expires_at,
                    uploaded_by=request.user if request.user.is_authenticated else None,
                    description=description,
                    tags=tags,
                    metadata=file_metadata,
                    abe_scheme=current_scheme if cpabe_policy_str else 'ac17'
                )
                
            # Create FileVersion
            trusted_timestamp = None
            tsa_signature = None
            
            if user_signature and request.user.is_authenticated:
                # Generate Trusted Timestamp
                from ..services.pki_service import PKIService
                trusted_timestamp = timezone.now()
                file_hash = plaintext_file_hash  # Use pre-computed hash (no plaintext retained)
                tsa_payload = {
                    "file_hash": file_hash,
                    "user_signature": user_signature,
                    "timestamp": trusted_timestamp.isoformat(),
                    "issuer": "CyberFortress-TSA"
                }
                try:
                    tsa_signature = PKIService.sign_payload(tsa_payload)
                except Exception as e:
                    logger.error(f"TSA signing failed: {e}")

            FileVersion.objects.create(
                file=uploaded_file,
                version_number=version_number,
                physical_path=physical_path,
                file_size=file.size,
                cpabe_policy=cpabe_policy_str,
                crypto_metadata=crypto_metadata,
                uploaded_by=request.user if request.user.is_authenticated else None,
                user_signature=user_signature,
                signing_payload=signing_payload,
                signer_public_key=signer_key,
                trusted_timestamp=trusted_timestamp,
                tsa_signature=tsa_signature
            )
            
            if policy_obj:
                if policy_obj.pk is None:
                    policy_obj.save()
                FileAccessPolicy.objects.get_or_create(
                    uploaded_file=uploaded_file,
                    policy=policy_obj,
                    defaults={'bucket': bucket, 'target_type': 'file', 'assigned_by': request.user},
                )
            
            return Response(
                UploadedFileSerializer(uploaded_file).data,
                status=status.HTTP_201_CREATED
            )
            
        except APIException:
            raise
        except Exception as e:
            transaction.set_rollback(True)
            return Response(
                {'error': f"Upload failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'], throttle_classes=[CPABEDecryptThrottle])
    def download(self, request, pk=None):
        """Download file from Supabase Storage"""
        uploaded_file = self.get_object()
        self._require_document_read(request.user, uploaded_file.bucket.name, uploaded_file.file_path, 'download')
        
        # Check if file is infected
        if uploaded_file.metadata and uploaded_file.metadata.get('clamav_scan') == 'infected':
            msg = uploaded_file.metadata.get('clamav_msg', 'Unknown malware')
            return Response({'error': f'File đã bị khóa do chứa mã độc: {msg}.'}, status=status.HTTP_403_FORBIDDEN)
            
        storage = get_storage_service()
        version_param = request.query_params.get('version')
        
        try:
            # Determine which version to serve
            if version_param:
                file_version = uploaded_file.versions.filter(version_number=version_param).first()
                if not file_version:
                    return Response({'error': f'Version {version_param} not found'}, status=status.HTTP_404_NOT_FOUND)
            else:
                file_version = uploaded_file.get_latest_version()
                
            physical_path = file_version.physical_path if file_version else uploaded_file.file_path
            cpabe_policy_str = file_version.cpabe_policy if file_version else None
            
            file_data = storage.download_file(
                bucket_name=uploaded_file.bucket.name,
                file_path=physical_path,
                user=request.user
            )
            
            # Check if user is owner
            is_owner = uploaded_file.uploaded_by == request.user
            
            # Decrypt if necessary
            file_data = self._decrypt_file_if_needed(
                file_data, 
                uploaded_file.bucket.name, 
                uploaded_file.file_path, 
                request.user,
                is_owner=is_owner,
                cpabe_policy_str=cpabe_policy_str,
                access_action='download',
                file_version=file_version,
            )
            
            response = HttpResponse(file_data, content_type=uploaded_file.mime_type)
            # Add version to filename if not latest
            if version_param and file_version and file_version != uploaded_file.get_latest_version():
                ext = uploaded_file.file_name.split('.')[-1] if '.' in uploaded_file.file_name else ''
                base = uploaded_file.file_name[:-(len(ext)+1)] if ext else uploaded_file.file_name
                file_name = f"{base}_v{version_param}.{ext}" if ext else f"{base}_v{version_param}"
            else:
                file_name = uploaded_file.file_name
                
            # Sanitize filename to prevent header injection
            safe_name = file_name.replace('"', '').replace('\r', '').replace('\n', '')
            encoded_name = urllib.parse.quote(safe_name)
            response['Content-Disposition'] = f"attachment; filename=\"{safe_name}\"; filename*=UTF-8''{encoded_name}"
            return response
            
        except APIException:
            raise
        except Exception as e:
            return Response(
                {'error': f"Download failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['get'])
    def versions(self, request, pk=None):
        """Get version history for a file"""
        uploaded_file = self.get_object()
        
        try:
            # Auto-create v1 for legacy files that have no version records
            if uploaded_file.versions.count() == 0:
                # Try to get existing CP-ABE policy from FileAccessPolicy
                existing_policy = None
                file_policy = uploaded_file.access_policies.first()
                if file_policy and file_policy.policy and file_policy.policy.cpabe_policy:
                    existing_policy = file_policy.policy.cpabe_policy
                    
                FileVersion.objects.create(
                    file=uploaded_file,
                    version_number=1,
                    physical_path=uploaded_file.file_path,
                    file_size=uploaded_file.file_size,
                    cpabe_policy=existing_policy,
                    uploaded_by=uploaded_file.uploaded_by
                )
                logger.info(f"Auto-created v1 FileVersion for legacy file: {uploaded_file.file_name} (id={uploaded_file.id})")
            
            versions = list(uploaded_file.versions.select_related('uploaded_by').order_by('-version_number'))
            can_restore = (
                (uploaded_file.uploaded_by_id == request.user.pk or is_document_administrator(request.user))
                and casbin_service.check_access(request.user, 'document', 'update')
            )
            result = []
            latest = versions[0] if versions else None
            for v in versions:
                try:
                    restorable = can_restore and self._compatible_restore_metadata(v, latest) is not None
                except CryptoMetadataError:
                    restorable = False
                result.append({
                    'version_number': v.version_number,
                    'file_size': v.file_size,
                    'cpabe_policy': v.cpabe_policy,
                    'crypto_metadata': v.crypto_metadata,
                    'uploaded_by': v.uploaded_by.username if v.uploaded_by else 'Unknown',
                    'created_at': v.created_at,
                    'can_restore': restorable,
                })
            return Response({'versions': result})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def _compatible_restore_metadata(source, latest):
        if source.pk == latest.pk or (source.cpabe_policy or '') != (latest.cpabe_policy or ''):
            return None
        metadata = validate_metadata(source.crypto_metadata)
        current = validate_metadata(latest.crypto_metadata)
        if (metadata['scheme'] != current['scheme'] or metadata['backend'] != current['backend'] or
                current['pqc_signed'] and not metadata['pqc_signed']):
            return None
        return metadata

    @action(detail=True, methods=['post'], throttle_classes=[CPABEDecryptThrottle])
    def restore_version(self, request, pk=None):
        """Publish verified historical bytes as a new version under the same policy."""
        from ..services.clamav_service import clamav_service

        serializer = RestoreFileVersionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        file_id = self.get_object().pk
        version_number = serializer.validated_data['version_number']
        storage = get_storage_service()
        destination = None
        try:
            with transaction.atomic():
                file = UploadedFile.objects.select_for_update().filter(pk=file_id, is_deleted=False).first()
                if file is None:
                    raise NotFound()
                bucket = file.bucket.name
                owner = file.uploaded_by_id == request.user.pk
                if not (owner or is_document_administrator(request.user)):
                    raise PermissionDenied('Only the owner or an administrator can restore a version.')
                if not casbin_service.check_access(request.user, 'document', 'update'):
                    raise PermissionDenied('You do not have permission to update this document.')
                self._require_document_read(request.user, bucket, file.file_path, 'update')
                self._require_document_read(request.user, bucket, file.file_path, 'download')
                if (file.metadata or {}).get('clamav_scan') == 'infected':
                    raise PermissionDenied('This document is blocked by malware scanning.')
                latest = file.get_latest_version()
                source = file.versions.filter(version_number=version_number).first()
                if source is None:
                    raise NotFound('The selected version does not exist.')
                source_crypto = self._compatible_restore_metadata(source, latest)
                if source_crypto is None:
                    return Response({'error': 'Restore requires an older version with the same policy, scheme and backend, and preserves signature verification.'},
                                    status=status.HTTP_409_CONFLICT)
                current_crypto = validate_metadata(latest.crypto_metadata)
                if source_crypto['scheme'] == 'covercrypt' and source_crypto['backend'] == 'vault' and (
                    source_crypto.get('keyset_id'), source_crypto.get('authority_revision')
                ) != (current_crypto.get('keyset_id'), current_crypto.get('authority_revision')):
                    source_route = cpabe_service.verify_version_authority(source_crypto)
                    current_route = cpabe_service.verify_version_authority(current_crypto)
                    source_dimensions = {d['name']: set(d['attributes']) for d in source_route.configuration.dimensions}
                    current_dimensions = {d['name']: set(d['attributes']) for d in current_route.configuration.dimensions}
                    if source_dimensions.keys() != current_dimensions.keys() or any(
                        not values <= current_dimensions[name] for name, values in source_dimensions.items()
                    ):
                        return Response({'error': 'The historical CoverCrypt configuration is incompatible with the current version.'},
                                        status=status.HTTP_409_CONFLICT)
                data = storage.download_file(bucket, source.physical_path, user=request.user)
                plaintext = self._decrypt_file_if_needed(
                    data, bucket, file.file_path, request.user, is_owner=owner,
                    access_action='download', file_version=source,
                )
                safe, _ = clamav_service.scan_file_buffer(plaintext)
                if not safe:
                    raise PermissionDenied('The selected version did not pass malware scanning.')
                del plaintext

                folder = file.file_path.rpartition('/')[0]
                filename = f'{uuid.uuid4().hex}_v{latest.version_number + 1}'
                destination = f'{folder}/{filename}' if folder else filename
                storage.upload_file(
                    bucket_name=bucket, file_path=destination, file_data=data,
                    content_type=file.mime_type or 'application/octet-stream', upsert=False, user=request.user,
                )
                restored = FileVersion.objects.create(
                    file=file, version_number=latest.version_number + 1, physical_path=destination,
                    file_size=source.file_size, cpabe_policy=source.cpabe_policy, crypto_metadata=source_crypto,
                    uploaded_by=request.user, user_signature=source.user_signature,
                    signing_payload=source.signing_payload,
                    signer_public_key=source.signer_public_key, trusted_timestamp=source.trusted_timestamp,
                    tsa_signature=source.tsa_signature,
                )
                file.file_size = source.file_size
                file.abe_scheme = source_crypto['scheme'] or 'ac17'
                file.metadata = {**(file.metadata or {}), 'file_size_bytes': source.file_size, 'clamav_scan': 'clean'}
                file.signed_url = None
                file.signed_url_expires_at = None
                if file.bucket.bucket_type == 'public':
                    file.public_url = storage.get_public_url(bucket, destination)
                file.save(update_fields=['file_size', 'abe_scheme', 'metadata', 'signed_url',
                                         'signed_url_expires_at', 'public_url', 'updated_at'])
        except Exception as exc:
            if destination is not None:
                try:
                    storage.delete_file(bucket, [destination], user=request.user)
                except Exception:
                    logger.error('Could not remove a failed restore object for file %s.', file_id)
            if isinstance(exc, APIException):
                raise
            logger.error('File version restore failed for file %s (%s).', file_id, type(exc).__name__)
            return Response({'error': 'Version restore failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'version_number': restored.version_number, 'restored_from': version_number},
                        status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['post'])
    def create_signed_url(self, request, pk=None):
        """Create a temporary signed URL for private file"""
        uploaded_file = self.get_object()
        
        if uploaded_file.bucket.bucket_type == 'public':
            return Response(
                {'public_url': uploaded_file.public_url},
                status=status.HTTP_200_OK
            )
        
        expires_in = request.data.get('expires_in', 3600)
        storage = get_storage_service()
        
        try:
            file_version = uploaded_file.get_latest_version()
            physical_path = file_version.physical_path if file_version else uploaded_file.file_path
            
            signed_url = storage.create_signed_url(
                bucket_name=uploaded_file.bucket.name,
                file_path=physical_path,
                expires_in=expires_in
            )
            
            # Update database
            uploaded_file.signed_url = signed_url
            uploaded_file.signed_url_expires_at = timezone.now() + timedelta(seconds=expires_in)
            uploaded_file.save()
            
            return Response({
                'signed_url': signed_url,
                'expires_at': uploaded_file.signed_url_expires_at,
                'expires_in': expires_in
            })
            
        except Exception as e:
            return Response(
                {'error': f"Failed to create signed URL: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['delete'])
    def delete_from_storage(self, request, pk=None):
        """Soft delete file (move to trash)"""
        uploaded_file = self.get_object()
        
        try:
            # Soft delete in database
            file_name = uploaded_file.file_name
            uploaded_file.is_deleted = True
            uploaded_file.deleted_at = timezone.now()
            uploaded_file.save()
            
            return Response({
                'message': f"File '{file_name}' moved to trash successfully"
            })
            
        except Exception as e:
            return Response(
                {'error': f"Delete failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(detail=False, methods=['get'])
    def trash(self, request):
        """List soft-deleted files (Admin only)"""
        if not request.user.profile.is_admin():
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
        trashed_files = UploadedFile.objects.filter(is_deleted=True).select_related('bucket', 'uploaded_by')
        return Response(UploadedFileSerializer(trashed_files, many=True).data)
        
    @action(detail=True, methods=['post'])
    def restore(self, request, pk=None):
        """Restore soft-deleted file (Admin only)"""
        if not request.user.profile.is_admin():
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk, is_deleted=True)
            uploaded_file.is_deleted = False
            uploaded_file.deleted_at = None
            uploaded_file.save()
            
            return Response({
                'message': f"File '{uploaded_file.file_name}' restored successfully"
            })
        except UploadedFile.DoesNotExist:
            return Response({'error': 'File not found in trash'}, status=status.HTTP_404_NOT_FOUND)
            
    @action(detail=True, methods=['delete'])
    def hard_delete(self, request, pk=None):
        """Permanently delete file from DB and Supabase (SuperAdmin only)"""
        if not request.user.profile.is_super_admin():
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk, is_deleted=True)
            file_name = uploaded_file.file_name
            # This will trigger post_delete signal to remove from Supabase
            uploaded_file.delete()
            
            return Response({
                'message': f"File '{file_name}' permanently deleted"
            })
        except UploadedFile.DoesNotExist:
            return Response({'error': 'File not found in trash'}, status=status.HTTP_404_NOT_FOUND)
    
    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Get storage statistics"""
        from django.db.models import Sum, Count
        
        user = request.user
        
        size_result = UploadedFile.objects.aggregate(total_size=Sum('file_size'))
        
        stats = {
            'total_files': UploadedFile.objects.count(),
            'my_files': UploadedFile.objects.filter(uploaded_by=user).count() if user.is_authenticated else 0,
            'total_size': size_result['total_size'] or 0,
            'by_type': {}
        }
        
        # Count by file type in a single query
        type_counts = UploadedFile.objects.values('file_type').annotate(count=Count('id'))
        for entry in type_counts:
            stats['by_type'][entry['file_type']] = entry['count']
        
        return Response(stats)
    
    @action(detail=False, methods=['get'])
    def browse(self, request):
        """
        Browse files directly from Supabase storage bucket
        GET /api/storage/files/browse/?path=public
        """
        storage = get_storage_service()
        bucket_name = request.query_params.get('bucket', 'documents')
        path = request.query_params.get('path', '')
        
        try:
            # Get all files from Database for this bucket (using ABAC filtered queryset)
            db_files = self.get_queryset().filter(bucket__name=bucket_name)
            
            result = []
            folders_set = set()
            
            for db_file in db_files:
                parts = db_file.file_path.split('/')
                file_dir = '/'.join(parts[:-1]) if len(parts) > 1 else ''
                
                if db_file.file_name == '.folder':
                    # It's an empty folder placeholder
                    folder_name = parts[-2] if len(parts) > 1 else parts[0]
                    folder_dir = '/'.join(parts[:-2]) if len(parts) > 2 else ''
                    
                    if folder_dir == path and folder_name not in folders_set:
                        folders_set.add(folder_name)
                        f_path = f"{path}/{folder_name}" if path else folder_name
                        result.append({
                            'name': folder_name,
                            'type': 'folder',
                            'size': None,
                            'id': db_file.id,
                            'created_at': db_file.uploaded_at,
                            'updated_at': db_file.updated_at,
                            'path': f_path
                        })
                else:
                    # It's a regular file
                    if file_dir == path:
                        meta = dict(db_file.metadata) if db_file.metadata else {}
                        for name in ('user_signature', 'signing_payload', 'signer_public_key', 'tsa_signature', 'trusted_timestamp'):
                            meta.pop(name, None)
                        latest_version = db_file.get_latest_version()
                        if latest_version:
                            if latest_version.user_signature:
                                meta['user_signature'] = latest_version.user_signature
                                meta['signing_payload'] = latest_version.signing_payload
                            if latest_version.signer_public_key:
                                meta['signer_public_key'] = latest_version.signer_public_key.pqc_public_key
                            if latest_version.tsa_signature:
                                meta['tsa_signature'] = latest_version.tsa_signature
                            if latest_version.trusted_timestamp:
                                meta['trusted_timestamp'] = latest_version.trusted_timestamp.isoformat()
                        
                        result.append({
                            'name': db_file.file_name,
                            'type': 'file',
                            'size': db_file.file_size,
                            'id': db_file.id,
                            'created_at': db_file.uploaded_at,
                            'updated_at': db_file.updated_at,
                            'path': db_file.file_path,
                            'metadata': meta
                        })
                    elif db_file.file_path.startswith(path + '/') or (not path and '/' in db_file.file_path):
                        # It's in a subdirectory, so we infer a logical folder
                        relative = db_file.file_path[len(path)+1:] if path else db_file.file_path
                        subfolder_name = relative.split('/')[0]
                        if subfolder_name not in folders_set:
                            folders_set.add(subfolder_name)
                            f_path = f"{path}/{subfolder_name}" if path else subfolder_name
                            result.append({
                                'name': subfolder_name,
                                'type': 'folder',
                                'size': None,
                                'id': None,
                                'created_at': db_file.uploaded_at,
                                'updated_at': db_file.updated_at,
                                'path': f_path
                            })
            
            return Response({
                'path': path,
                'bucket': bucket_name,
                'files': result
            })
            
        except Exception as e:
            return Response(
                {'error': f"Failed to list files: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'], throttle_classes=[CPABEDecryptThrottle])
    def download_by_path(self, request):
        """
        Download file by path from Supabase
        GET /api/storage/files/download_by_path/?path=public/company-policy.md
        Protected by ABAC middleware - requires 'download' permission on 'document'
        
        Note: File owner can always download their own files regardless of ABAC policy
        """
        storage = get_storage_service()
        bucket_name = request.query_params.get('bucket', 'documents')
        file_path = request.query_params.get('path', '')
        
        if not file_path:
            return Response(
                {'error': 'path parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user is owner of this file (can bypass ABAC for their own files)
        # This is already passed ABAC middleware, but we track ownership for audit
        uploaded_file = get_db_file_by_path(bucket_name, file_path)
        
        # Check if file is infected
        if uploaded_file and uploaded_file.metadata and uploaded_file.metadata.get('clamav_scan') == 'infected':
            msg = uploaded_file.metadata.get('clamav_msg', 'Unknown malware')
            return Response({'error': f'File đã bị khóa do chứa mã độc: {msg}.'}, status=status.HTTP_403_FORBIDDEN)
            
        self._require_document_read(request.user, bucket_name, file_path, 'download')
        is_owner = uploaded_file and uploaded_file.uploaded_by == request.user
        
        version_param = request.query_params.get('version')
        
        try:
            physical_path = file_path
            cpabe_policy_str = None
            file_version = None
            
            if uploaded_file:
                if version_param:
                    file_version = uploaded_file.versions.filter(version_number=version_param).first()
                    if not file_version:
                        return Response({'error': f'Version {version_param} not found'}, status=status.HTTP_404_NOT_FOUND)
                else:
                    file_version = uploaded_file.get_latest_version()
                    
                if file_version:
                    physical_path = file_version.physical_path
                    cpabe_policy_str = file_version.cpabe_policy
                    
            file_data = storage.download_file(bucket_name, physical_path, user=request.user)
            
            # Decrypt if necessary
            file_data = self._decrypt_file_if_needed(
                file_data, 
                bucket_name, 
                file_path, 
                request.user,
                is_owner=is_owner,
                cpabe_policy_str=cpabe_policy_str,
                access_action='download',
                file_version=file_version,
            )
            
            file_name = file_path.split('/')[-1]
            if version_param and file_version and file_version != uploaded_file.get_latest_version():
                ext = file_name.split('.')[-1] if '.' in file_name else ''
                base = file_name[:-(len(ext)+1)] if ext else file_name
                file_name = f"{base}_v{version_param}.{ext}" if ext else f"{base}_v{version_param}"
            
            # Guess content type
            ext = file_name.split('.')[-1].lower() if '.' in file_name else ''
            content_types = {
                'md': 'text/markdown',
                'txt': 'text/plain',
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg', 
                'png': 'image/png',
                'gif': 'image/gif',
            }
            content_type = content_types.get(ext, 'application/octet-stream')
            
            response = HttpResponse(file_data, content_type=content_type)
            # Sanitize filename to prevent header injection
            safe_name = file_name.replace('"', '').replace('\r', '').replace('\n', '')
            encoded_name = urllib.parse.quote(safe_name)
            response['Content-Disposition'] = f"attachment; filename=\"{safe_name}\"; filename*=UTF-8''{encoded_name}"
            return response
            
        except APIException:
            raise
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(detail=False, methods=['get'], throttle_classes=[CPABEDecryptThrottle])
    def preview_by_path(self, request):
        """
        Preview file by path from Supabase (displays in browser instead of downloading)
        GET /api/storage/files/preview_by_path/?path=public/company-policy.md
        Protected by ABAC middleware - requires 'read' permission on 'document'
        """
        storage = get_storage_service()
        bucket_name = request.query_params.get('bucket', 'documents')
        file_path = request.query_params.get('path', '')
        
        if not file_path:
            return Response(
                {'error': 'path parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if user is owner of this file (can bypass ABAC for their own files)
        uploaded_file = get_db_file_by_path(bucket_name, file_path)
        self._require_document_read(request.user, bucket_name, file_path)
        is_owner = uploaded_file and uploaded_file.uploaded_by == request.user
        
        version_param = request.query_params.get('version')
        
        try:
            physical_path = file_path
            cpabe_policy_str = None
            file_version = None
            
            if uploaded_file:
                if version_param:
                    file_version = uploaded_file.versions.filter(version_number=version_param).first()
                    if not file_version:
                        return Response({'error': f'Version {version_param} not found'}, status=status.HTTP_404_NOT_FOUND)
                else:
                    file_version = uploaded_file.get_latest_version()
                    
                if file_version:
                    physical_path = file_version.physical_path
                    cpabe_policy_str = file_version.cpabe_policy
                    
            file_data = storage.download_file(bucket_name, physical_path, user=request.user)
            
            # Decrypt if necessary
            file_data = self._decrypt_file_if_needed(
                file_data, 
                bucket_name, 
                file_path, 
                request.user,
                is_owner=is_owner,
                cpabe_policy_str=cpabe_policy_str,
                file_version=file_version,
            )
            file_name = file_path.split('/')[-1]
            if version_param and file_version and file_version != uploaded_file.get_latest_version():
                ext = file_name.split('.')[-1] if '.' in file_name else ''
                base = file_name[:-(len(ext)+1)] if ext else file_name
                file_name = f"{base}_v{version_param}.{ext}" if ext else f"{base}_v{version_param}"
            
            # Guess content type
            ext = file_name.split('.')[-1].lower() if '.' in file_name else ''
            content_types = {
                'md': 'text/markdown',
                'txt': 'text/plain',
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'jpg': 'image/jpeg',
                'jpeg': 'image/jpeg', 
                'png': 'image/png',
                'gif': 'image/gif',
            }
            content_type = content_types.get(ext, 'application/octet-stream')
            
            response = HttpResponse(file_data, content_type=content_type)
            # Sanitize filename to prevent header injection
            safe_name = file_name.replace('"', '').replace('\r', '').replace('\n', '')
            encoded_name = urllib.parse.quote(safe_name)
            response['Content-Disposition'] = f"inline; filename=\"{safe_name}\"; filename*=UTF-8''{encoded_name}"
            return response
            
        except APIException:
            raise
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['delete'])
    def delete_by_path(self, request):
        """
        Delete file by path from Supabase
        DELETE /api/storage/files/delete_by_path/?path=public/file.md&bucket=documents
        Protected by ABAC middleware - requires 'delete' permission on 'document'
        """
        storage = get_storage_service()
        bucket_name = request.query_params.get('bucket', 'documents')
        file_path = request.query_params.get('path', '')
        
        if not file_path:
            return Response(
                {'error': 'path parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        is_folder = request.query_params.get('is_folder', 'false').lower() == 'true'
        
        try:
            if is_folder:
                from crypto_access.models.storage import UploadedFile, StorageBucket
                bucket = StorageBucket.objects.get(name=bucket_name)
                db_files = UploadedFile.objects.filter(bucket=bucket, is_deleted=False)
                count = 0
                for db_file in db_files:
                    if db_file.file_path == f"{file_path}/.folder" or db_file.file_path.startswith(f"{file_path}/"):
                        db_file.is_deleted = True
                        db_file.deleted_at = timezone.now()
                        db_file.save(update_fields=['is_deleted', 'deleted_at'])
                        count += 1
                return Response({'message': f"Folder '{file_path}' and {count} items deleted successfully"})
            else:
                # Soft delete logic
                uploaded_file = get_db_file_by_path(bucket_name, file_path)
                
                if uploaded_file:
                    uploaded_file.is_deleted = True
                    uploaded_file.deleted_at = timezone.now()
                    uploaded_file.save(update_fields=['is_deleted', 'deleted_at'])
                
                return Response({
                    'message': f"File '{file_path}' deleted successfully"
                })
            
        except Exception as e:
            return Response(
                {'error': f"Delete failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def clipboard_action(self, request):
        """
        Handle Copy/Cut & Paste
        POST /api/storage/files/clipboard_action/
        Body: { "action": "copy"|"cut", "items": ["path1", "path2"], "destination": "dest", "bucket_name": "documents" }
        """
        action = request.data.get('action')
        items = request.data.get('items', [])
        destination = request.data.get('destination', '')
        bucket_name = request.data.get('bucket_name', 'documents')
        
        if not action or not items:
            return Response({'error': 'action and items are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        storage = get_storage_service()
        
        try:
            from crypto_access.models.storage import UploadedFile, StorageBucket, FileVersion
            bucket = StorageBucket.objects.get(name=bucket_name)
            
            # Helper for renaming
            def get_unique_name(target_path, target_name):
                base_name = target_name
                ext = ''
                if '.' in target_name and not target_name.startswith('.'):
                    parts = target_name.rsplit('.', 1)
                    base_name = parts[0]
                    ext = '.' + parts[1]
                
                counter = 1
                new_name = target_name
                new_path = f"{target_path}/{new_name}" if target_path else new_name
                
                from django.conf import settings
                field_encryption = getattr(settings, 'FIELD_ENCRYPTION', False)
                def check_exists(path_to_check):
                    if field_encryption:
                        from crypto_access.models.fields import get_encryption_key
                        import hmac, hashlib
                        key = get_encryption_key(info=b"blind_index")
                        h = hmac.new(key, str(path_to_check).encode('utf-8'), hashlib.sha3_256)
                        return UploadedFile.objects.filter(bucket=bucket, file_path_hash=h.hexdigest(), is_deleted=False).exists()
                    else:
                        return UploadedFile.objects.filter(bucket=bucket, file_path=path_to_check, is_deleted=False).exists()
                
                while check_exists(new_path):
                    new_name = f"{base_name} ({counter}){ext}"
                    new_path = f"{target_path}/{new_name}" if target_path else new_name
                    counter += 1
                    
                return new_name, new_path
            
            from django.conf import settings
            field_encryption = getattr(settings, 'FIELD_ENCRYPTION', False)
            def compute_hash(val):
                if not field_encryption: return None
                from crypto_access.models.fields import get_encryption_key
                import hmac, hashlib
                key = get_encryption_key(info=b"blind_index")
                h = hmac.new(key, str(val).encode('utf-8'), hashlib.sha3_256)
                return h.hexdigest()
                
            success_count = 0
            all_files = list(UploadedFile.objects.filter(bucket=bucket, is_deleted=False))
            
            for item_path in items:
                item_files = []
                is_folder = False
                
                for f in all_files:
                    if f.file_path == item_path:
                        item_files.append((f, False))
                    elif f.file_path == f"{item_path}/.folder":
                        item_files.append((f, True))
                        is_folder = True
                    elif f.file_path.startswith(f"{item_path}/"):
                        item_files.append((f, False))
                        is_folder = True
                
                if not item_files:
                    continue
                
                item_name = item_path.split('/')[-1]
                new_root_name, new_root_path = get_unique_name(destination, item_name)
                
                # ABAC Verification before processing
                from crypto_access.services.casbin_service import casbin_service
                
                # Check write permission for destination
                if not casbin_service.check_access(request.user, 'document', 'write'):
                    return Response({'error': "You do not have permission to paste here."}, status=status.HTTP_403_FORBIDDEN)
                
                for db_file, is_placeholder in item_files:
                    if not is_placeholder:
                        if db_file.uploaded_by != request.user:
                            required_action = 'read' if action == 'copy' else 'write'
                            has_access, _ = casbin_service.check_file_access_with_fallback(request.user, bucket_name, db_file.file_path, required_action)
                            if not has_access:
                                return Response({'error': f"Access denied for: {db_file.file_name}"}, status=status.HTTP_403_FORBIDDEN)
                
                # Sort files so that if we copy, we don't mess up. (Not strictly needed since we fetch them to memory)
                for db_file, is_placeholder in item_files:
                    if db_file.file_path == item_path or db_file.file_path == f"{item_path}/.folder":
                        new_file_path = new_root_path if not is_placeholder else f"{new_root_path}/.folder"
                        new_file_name = new_root_name if not is_placeholder else ".folder"
                    else:
                        relative_path = db_file.file_path[len(item_path):]
                        new_file_path = new_root_path + relative_path
                        new_file_name = new_file_path.split('/')[-1]
                    
                    physical_path_to_use = db_file.file_path
                    latest_version = db_file.get_latest_version()
                    if latest_version:
                        physical_path_to_use = latest_version.physical_path
                    
                    new_physical_path = new_file_path
                    if latest_version and physical_path_to_use != db_file.file_path:
                        # Append a timestamp or version marker to avoid physical collision if needed,
                        # but normally a new file path is unique. So using new_file_path as physical_path is fine.
                        pass
                        
                    if action == 'copy':
                        # Copy physical file with retry for orphaned files
                        copy_counter = 1
                        base_name = new_file_name
                        ext = ''
                        if '.' in new_file_name and not new_file_name.startswith('.'):
                            parts = new_file_name.rsplit('.', 1)
                            base_name = parts[0]
                            ext = '.' + parts[1]
                        
                        while True:
                            try:
                                storage.copy_file(bucket_name, physical_path_to_use, new_physical_path)
                                break
                            except Exception as e:
                                if 'Duplicate' in str(e) or 'already exists' in str(e):
                                    new_file_name = f"{base_name} ({copy_counter}){ext}"
                                    new_file_path = f"{destination}/{new_file_name}" if destination else new_file_name
                                    new_physical_path = new_file_path
                                    copy_counter += 1
                                else:
                                    raise
                        
                        # Copy DB record
                        new_file = UploadedFile.objects.get(pk=db_file.pk)
                        new_file.pk = None
                        new_file.file_path = new_file_path
                        new_file.file_name = new_file_name
                        new_file.file_path_hash = compute_hash(new_file_path)
                        new_file.file_name_hash = compute_hash(new_file_name)
                        new_file.uploaded_by = request.user
                        if latest_version:
                            new_file.file_size = latest_version.file_size
                            new_file.abe_scheme = latest_version.crypto_metadata.get('scheme') or db_file.abe_scheme
                        new_file.save()
                        
                        # Copy latest version
                        if latest_version:
                            new_version = FileVersion.objects.get(pk=latest_version.pk)
                            new_version.pk = None
                            new_version.file = new_file
                            new_version.physical_path = new_physical_path
                            new_version.version_number = 1
                            new_version.uploaded_by = request.user
                            new_version.save()
                            
                        # Re-assign Access Policies
                        for policy_link in db_file.access_policies.all():
                            from crypto_access.models.storage import FileAccessPolicy
                            new_policy_link = FileAccessPolicy.objects.create(
                                uploaded_file=new_file,
                                policy=policy_link.policy,
                                bucket=bucket,
                                target_type=policy_link.target_type,
                                assigned_by=policy_link.assigned_by,
                                notes=policy_link.notes
                            )
                            new_policy_link.granted_users.set(policy_link.granted_users.all())
                            
                    elif action == 'cut':
                        # Move physical file with retry
                        move_counter = 1
                        base_name = new_file_name
                        ext = ''
                        if '.' in new_file_name and not new_file_name.startswith('.'):
                            parts = new_file_name.rsplit('.', 1)
                            base_name = parts[0]
                            ext = '.' + parts[1]
                        
                        while True:
                            try:
                                storage.move_file(bucket_name, physical_path_to_use, new_physical_path, user=request.user)
                                break
                            except Exception as e:
                                if 'Duplicate' in str(e) or 'already exists' in str(e):
                                    new_file_name = f"{base_name} ({move_counter}){ext}"
                                    new_file_path = f"{destination}/{new_file_name}" if destination else new_file_name
                                    new_physical_path = new_file_path
                                    move_counter += 1
                                else:
                                    raise
                        
                        # Update DB record
                        db_file.file_path = new_file_path
                        db_file.file_name = new_file_name
                        db_file.file_path_hash = compute_hash(new_file_path)
                        db_file.file_name_hash = compute_hash(new_file_name)
                        db_file.save(update_fields=['file_path', 'file_name', 'file_path_hash', 'file_name_hash'])
                        
                        if latest_version:
                            latest_version.physical_path = new_physical_path
                            latest_version.save(update_fields=['physical_path'])
                
                success_count += 1
                
            return Response({'message': f"Successfully {action}ed {success_count} item(s)"})
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def create_folder(self, request):
        """
        Create a folder in Supabase Storage
        POST /api/storage/files/create_folder/
        Body: { "folder_name": "hr", "bucket_name": "documents", "parent_path": "" }
        """
        bucket_name = request.data.get('bucket_name', 'documents')
        folder_name = request.data.get('folder_name', '')
        parent_path = request.data.get('parent_path', '')
        
        if not folder_name:
            return Response(
                {'error': 'folder_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate folder name
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', folder_name):
            return Response(
                {'error': 'Folder name can only contain letters, numbers, underscore and hyphen'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        storage = get_storage_service()
        
        try:
            # Create folder by uploading a placeholder file
            # Supabase creates folders implicitly when files are uploaded
            folder_path = f"{parent_path}/{folder_name}/.folder" if parent_path else f"{folder_name}/.folder"
            
            storage.upload_file(
                bucket_name=bucket_name,
                file_path=folder_path,
                file_data=b'',  # Empty placeholder
                content_type='text/plain',
                user=request.user
            )
            
            # Create UploadedFile record for logical empty folder tracking
            from crypto_access.models.storage import UploadedFile, StorageBucket
            bucket = StorageBucket.objects.get(name=bucket_name)
            
            from django.conf import settings
            field_encryption = getattr(settings, 'FIELD_ENCRYPTION', False)
            def get_hash(val):
                if not field_encryption: return None
                from crypto_access.models.fields import get_encryption_key
                import hmac, hashlib
                key = get_encryption_key(info=b"blind_index")
                h = hmac.new(key, str(val).encode('utf-8'), hashlib.sha3_256)
                return h.hexdigest()
                
            UploadedFile.objects.create(
                bucket=bucket,
                file_name='.folder',
                file_path=folder_path,
                file_name_hash=get_hash('.folder'),
                file_path_hash=get_hash(folder_path),
                file_type='other',
                mime_type='application/x-directory',
                file_size=0,
                uploaded_by=request.user if hasattr(request, 'user') and request.user.is_authenticated else None
            )
            
            return Response({
                'message': f"Folder '{folder_name}' created successfully",
                'path': folder_path.replace('/.folder', '')
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            error_msg = str(e).lower()
            if 'duplicate' in error_msg or 'already exists' in error_msg or '409' in error_msg:
                return Response(
                    {'error': f"A folder named '{folder_name}' already exists"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            return Response(
                {'error': f"Failed to create folder: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def rename_item(self, request):
        """
        Rename a file or folder
        POST /api/storage/files/rename/
        Body: { "old_path": "hr/file.txt", "new_name": "new_file.txt", "type": "file|folder", "bucket_name": "documents" }
        """
        old_path = request.data.get('old_path', '')
        new_name = request.data.get('new_name', '')
        item_type = request.data.get('type', 'file')
        bucket_name = request.data.get('bucket_name', 'documents')
        
        if not old_path or not new_name:
            return Response(
                {'error': 'old_path and new_name are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate new name
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]+$', new_name):
            return Response(
                {'error': 'Name can only contain letters, numbers, dot, underscore and hyphen'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            bucket = StorageBucket.objects.get(name=bucket_name)
        except StorageBucket.DoesNotExist:
            return Response({'error': f"Bucket '{bucket_name}' not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Check permissions
        is_admin = hasattr(request.user, 'profile') and request.user.profile.is_admin()
        is_data_owner = hasattr(request.user, 'profile') and request.user.profile.user_type_ref and request.user.profile.user_type_ref.code == 'data_owner'
        
        if not (is_admin or is_data_owner):
            return Response({'error': 'You do not have permission to rename items'}, status=status.HTTP_403_FORBIDDEN)
            
        # Helper for encryption hashing
        from django.conf import settings
        field_encryption = getattr(settings, 'FIELD_ENCRYPTION', False)
        def get_hash(val):
            if not field_encryption: return None
            from crypto_access.models.fields import get_encryption_key
            import hmac
            import hashlib
            key = get_encryption_key(info=b"blind_index")
            h = hmac.new(key, str(val).encode('utf-8'), hashlib.sha3_256)
            return h.hexdigest()

        try:
            with transaction.atomic():
                if item_type == 'file':
                    # Find file
                    if field_encryption:
                        file_obj = UploadedFile.objects.filter(bucket=bucket, file_path_hash=get_hash(old_path)).first()
                    else:
                        file_obj = UploadedFile.objects.filter(bucket=bucket, file_path=old_path).first()
                        
                    if not file_obj:
                        return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
                    
                    # Ensure only owner or admin can rename
                    if not is_admin and file_obj.uploaded_by_id != request.user.id:
                        return Response({'error': 'You can only rename your own files'}, status=status.HTTP_403_FORBIDDEN)
                    
                    parts = old_path.split('/')
                    folder_path = '/'.join(parts[:-1]) if len(parts) > 1 else ''
                    new_path = f"{folder_path}/{new_name}" if folder_path else new_name
                    
                    # Check if new path already exists
                    if field_encryption:
                        exists = UploadedFile.objects.filter(bucket=bucket, file_path_hash=get_hash(new_path)).exists()
                    else:
                        exists = UploadedFile.objects.filter(bucket=bucket, file_path=new_path).exists()
                        
                    if exists:
                        return Response({'error': 'A file with this name already exists'}, status=status.HTTP_400_BAD_REQUEST)
                    
                    file_obj.file_name = new_name
                    file_obj.file_path = new_path
                    if field_encryption:
                        file_obj.file_name_hash = get_hash(new_name)
                        file_obj.file_path_hash = get_hash(new_path)
                    file_obj.save()
                    
                    return Response({'message': f"File renamed to '{new_name}'", 'new_path': new_path})
                    
                elif item_type == 'folder':
                    old_folder_path = old_path.rstrip('/')
                    parts = old_folder_path.split('/')
                    parent_path = '/'.join(parts[:-1]) if len(parts) > 1 else ''
                    new_folder_path = f"{parent_path}/{new_name}" if parent_path else new_name
                    
                    # Get all files in this bucket
                    all_files = UploadedFile.objects.filter(bucket=bucket)
                    
                    # Process files in the folder
                    files_to_update = []
                    for f in all_files:
                        if f.file_path.startswith(f"{old_folder_path}/") or f.file_path == f"{old_folder_path}/.folder":
                            if not is_admin and f.uploaded_by_id != request.user.id:
                                return Response({'error': 'You can only rename folders where you own all the files inside'}, status=status.HTTP_403_FORBIDDEN)
                            files_to_update.append(f)
                            
                    # Check if new folder name already exists (by checking if a .folder exists)
                    if field_encryption:
                        exists = UploadedFile.objects.filter(bucket=bucket, file_path_hash=get_hash(f"{new_folder_path}/.folder")).exists()
                    else:
                        exists = UploadedFile.objects.filter(bucket=bucket, file_path=f"{new_folder_path}/.folder").exists()
                    
                    if exists:
                        return Response({'error': 'A folder with this name already exists'}, status=status.HTTP_400_BAD_REQUEST)
                        
                    # Update all files
                    storage = get_storage_service()
                    for f in files_to_update:
                        old_fpath = f.file_path
                        new_fpath = old_fpath.replace(old_folder_path, new_folder_path, 1)
                        f.file_path = new_fpath
                        if field_encryption:
                            f.file_path_hash = get_hash(new_fpath)
                        f.save()
                    # Update Folder Policies
                    policies = FileAccessPolicy.objects.filter(uploaded_file__isnull=True, target_type='folder')
                    for p in policies:
                        if p.folder_path == old_folder_path + '/':
                            p.folder_path = new_folder_path + '/'
                            p.save()
                        elif p.folder_path.startswith(old_folder_path + '/'):
                            p.folder_path = p.folder_path.replace(old_folder_path + '/', new_folder_path + '/', 1)
                            p.save()
                            
                    # Move .folder object in Supabase
                    try:
                        storage = get_storage_service()
                        old_supa_folder = f"{old_folder_path}/.folder"
                        new_supa_folder = f"{new_folder_path}/.folder"
                        storage.move_file(bucket_name, old_supa_folder, new_supa_folder, user=request.user)
                    except Exception as e:
                        error_msg = str(e).lower()
                        if 'duplicate' in error_msg or 'already exists' in error_msg or '409' in error_msg:
                            raise Exception(f"A folder named '{new_name}' already exists")
                        raise e
                        
                    return Response({'message': f"Folder renamed to '{new_name}'", 'new_path': new_folder_path})
                else:
                    return Response({'error': 'Invalid item type'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            msg = str(e)
            if msg.startswith("A folder named"):
                return Response({'error': msg}, status=status.HTTP_400_BAD_REQUEST)
            return Response({'error': f"Failed to rename: {msg}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ============= FILE ACCESS POLICY MANAGEMENT =============
    
    @action(detail=False, methods=['get'])
    def available_policies(self, request):
        """
        Get list of available policies for assignment.
        Filters policies that are applicable to documents/files.
        """
        policies = AccessPolicy.objects.filter(
            is_active=True,
            resource__in=['document', '*']  # Only document-related policies
        ).order_by('priority', 'name')
        
        serializer = PolicyListForAssignmentSerializer(policies, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def file_policies(self, request):
        """
        Get policies assigned to a specific file or folder.
        Query params: path, bucket (default: documents)
        """
        file_path = request.GET.get('path', '')
        bucket_name = request.GET.get('bucket', 'documents')
        
        if not file_path:
            return Response(
                {'error': 'File path is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            bucket = StorageBucket.objects.get(name=bucket_name)
        except StorageBucket.DoesNotExist:
            return Response(
                {'error': f"Bucket '{bucket_name}' not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get direct file policies
        file_record = get_db_file_by_path(bucket.name, file_path)
        
        file_policies = []
        if file_record:
            file_policies = FileAccessPolicy.objects.filter(
                uploaded_file=file_record
            ).select_related('policy', 'assigned_by')
        
        # Get folder policies that apply to this path
        folder_policies = []
        path_parts = file_path.split('/')
        for i in range(len(path_parts)):
            folder_path = '/'.join(path_parts[:i+1]) + '/'
            fp = FileAccessPolicy.objects.filter(
                bucket=bucket,
                folder_path=folder_path,
                target_type='folder'
            ).select_related('policy', 'assigned_by')
            folder_policies.extend(list(fp))
        
        return Response({
            'file_path': file_path,
            'bucket': bucket_name,
            'direct_policies': FileAccessPolicySerializer(file_policies, many=True).data,
            'inherited_folder_policies': FileAccessPolicySerializer(folder_policies, many=True).data
        })
    
    @action(detail=False, methods=['post'])
    @transaction.atomic
    def assign_policy(self, request):
        """
        Assign a policy to a file or folder.
        Can use existing policy or create a new one.
        """
        serializer = AssignPolicyToFileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        file_path = data['file_path']
        bucket_name = data['bucket_name']
        target_type = data['target_type']
        
        try:
            bucket = StorageBucket.objects.get(name=bucket_name)
        except StorageBucket.DoesNotExist:
            return Response(
                {'error': f"Bucket '{bucket_name}' not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create FileAccessPolicy
        file_record = None
        folder_path = None
        
        if target_type == 'file':
            file_record = get_db_file_by_path(bucket.name, file_path)
            
            if not file_record:
                return Response(
                    {'error': f"File '{file_path}' not found in bucket '{bucket_name}'"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:  # folder
            folder_path = file_path if file_path.endswith('/') else file_path + '/'
        
        # Determine replace mode
        replace_policies = self.request.data.get('replace', False) or self.request.query_params.get('replace', 'false').lower() == 'true'
        
        # Check ownership/admin rights for modifying policies
        is_admin = getattr(request.user, 'is_superuser', False)
        if hasattr(request.user, 'profile') and request.user.profile.user_type_ref:
            if request.user.profile.user_type_ref.code in ['super_admin', 'admin']:
                is_admin = True
                
        is_owner = file_record and file_record.uploaded_by == request.user
        
        if not (is_owner or is_admin):
            return Response(
                {'error': 'Only the file owner or an administrator can modify its policy.'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Authorize both the target and global policy creation before any DB write.
        policy = self._prepare_inline_policy(request, data)
        if policy is None:
            try:
                policy = AccessPolicy.objects.get(id=data['policy_id'])
            except AccessPolicy.DoesNotExist:
                return Response(
                    {'error': f"Policy ID {data['policy_id']} not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

        existing = (
            FileAccessPolicy.objects.filter(policy=policy, bucket=bucket)
            if policy.pk else FileAccessPolicy.objects.none()
        )
        if target_type == 'file':
            existing = existing.filter(uploaded_file=file_record)
        else:
            existing = existing.filter(folder_path=folder_path)
        
        if existing.exists() and not replace_policies:
            return Response(
                {'error': 'This policy is already assigned to this file/folder'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if policy.pk is None:
            policy.save()
        
        # Handle Encryption / Re-encryption
        if target_type == 'file':
            storage = get_storage_service()
            try:
                # Find all existing policies to check if already encrypted
                existing_all = FileAccessPolicy.objects.filter(
                    uploaded_file=file_record
                )
                was_already_encrypted = any(p.policy.cpabe_policy for p in existing_all)
                
                needs_encryption_update = False
                file_data = None
                
                if replace_policies:
                    # If replacing, we must download, decrypt, and re-encrypt
                    needs_encryption_update = True
                    latest_version = file_record.get_latest_version()
                    physical_path = latest_version.physical_path if latest_version else file_path
                    cpabe_policy_str = latest_version.cpabe_policy if latest_version else None
                    
                    # Get plaintext bytes
                    file_data = storage.download_file(bucket_name, physical_path, user=request.user)
                    if was_already_encrypted:
                        file_data = self._decrypt_file_if_needed(
                            file_data, bucket_name, file_path, request.user, is_owner=True, cpabe_policy_str=cpabe_policy_str, file_version=latest_version,
                        )
                    
                    # Delete old policies
                    existing_all.delete()
                    policy_to_encrypt = policy.cpabe_policy

                else:
                    latest_version = file_record.get_latest_version()
                    physical_path = latest_version.physical_path if latest_version else file_path
                    cpabe_policy_str = latest_version.cpabe_policy if latest_version else None
                    
                    if policy.cpabe_policy:
                        needs_encryption_update = True
                        if was_already_encrypted:
                            # Add operation: Combine all existing CP-ABE policies with the new one
                            all_cpabe = [p.policy.cpabe_policy for p in existing_all if p.policy.cpabe_policy]
                            all_cpabe.append(policy.cpabe_policy)
                            policy_to_encrypt = " or ".join(f"({p})" for p in all_cpabe)
                            
                            # Decrypt existing file data first
                            enc_data = storage.download_file(bucket_name, physical_path, user=request.user)
                            file_data = self._decrypt_file_if_needed(
                                enc_data, bucket_name, file_path, request.user, is_owner=True, cpabe_policy_str=cpabe_policy_str, file_version=latest_version,
                            )
                        else:
                            file_data = storage.download_file(bucket_name, physical_path, user=request.user)
                            policy_to_encrypt = policy.cpabe_policy
                        
                old_physical_path = None
                if needs_encryption_update:
                    import time
                    import os
                    old_physical_path = physical_path
                    base, ext = os.path.splitext(physical_path)
                    base_no_v = base.split('_v')[0]
                    new_physical_path = f"{base_no_v}_v{uuid.uuid4().hex}{ext}"
                    physical_path = new_physical_path

                # Create the assignment
                file_access_policy = FileAccessPolicy.objects.create(
                    uploaded_file=file_record,
                    bucket=bucket,
                    target_type=target_type,
                    policy=policy,
                    assigned_by=request.user,
                    notes=data.get('notes', '')
                )
                
                if needs_encryption_update:
                    from django.conf import settings
                    if policy_to_encrypt:
                        current_scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
                        enc_data, crypto_metadata = cpabe_service.encrypt_version(
                            file_data, policy_to_encrypt, scheme=current_scheme,
                            pqc_signed=bool(getattr(settings, 'ENABLE_PQC_FEATURES', False)),
                        )
                    else:
                        enc_data, crypto_metadata = file_data, dict(PLAINTEXT_METADATA)
                        current_scheme = 'ac17'
                    storage.upload_file(
                        bucket_name=bucket_name, file_path=physical_path, file_data=enc_data,
                        content_type=file_record.mime_type or 'application/octet-stream',
                        upsert=False, user=request.user,
                    )
                    # Re-encryption is a new immutable version. Keep every old blob and
                    # its crypto metadata, including legacy sources whose mode is unknown.
                    if latest_version is None:
                        latest_version = FileVersion.objects.create(
                            file=file_record, version_number=1, physical_path=old_physical_path,
                            file_size=file_record.file_size, cpabe_policy=cpabe_policy_str,
                            uploaded_by=file_record.uploaded_by,
                        )
                    FileVersion.objects.create(
                        file=file_record, version_number=latest_version.version_number + 1,
                        physical_path=physical_path, file_size=file_record.file_size,
                        cpabe_policy=policy_to_encrypt or '', crypto_metadata=crypto_metadata,
                        uploaded_by=request.user, user_signature=latest_version.user_signature,
                        signing_payload=latest_version.signing_payload,
                        signer_public_key=latest_version.signer_public_key,
                        trusted_timestamp=latest_version.trusted_timestamp, tsa_signature=latest_version.tsa_signature,
                    )
                    file_record.abe_scheme = current_scheme
                    file_record.save(update_fields=['abe_scheme'])
            except APIException:
                transaction.set_rollback(True)
                raise
            except Exception as e:
                transaction.set_rollback(True)
                logger.error(f"Failed to update encryption for file {file_path}: {e}")
                return Response({'error': f"Failed to update encryption: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Create the assignment for folder
            if replace_policies:
                FileAccessPolicy.objects.filter(
                    folder_path=folder_path,
                    bucket=bucket,
                    target_type=target_type
                ).delete()
                
            file_access_policy = FileAccessPolicy.objects.create(
                folder_path=folder_path,
                bucket=bucket,
                target_type=target_type,
                policy=policy,
                assigned_by=request.user,
                notes=data.get('notes', '')
            )
        
        return Response({
            'message': 'Policy assigned successfully',
            'assignment': FileAccessPolicySerializer(file_access_policy).data
        }, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['delete'])
    def remove_policy(self, request):
        """
        Remove a policy assignment from a file/folder.
        Query params: assignment_id
        """
        assignment_id = request.GET.get('assignment_id')
        
        if not assignment_id:
            return Response(
                {'error': 'assignment_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            assignment = FileAccessPolicy.objects.get(id=assignment_id)
            
            # Check if user is owner or admin
            file_owner = None
            if assignment.uploaded_file:
                file_owner = assignment.uploaded_file.uploaded_by
            
            if not (request.user.is_superuser or 
                    assignment.assigned_by == request.user or 
                    file_owner == request.user):
                return Response(
                    {'error': 'You do not have permission to remove this policy assignment'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            assignment.delete()
            return Response({'message': 'Policy assignment removed successfully'})
            
        except FileAccessPolicy.DoesNotExist:
            return Response(
                {'error': f"Assignment ID {assignment_id} not found"},
                status=status.HTTP_404_NOT_FOUND
            )

