"""
PKI Views - API endpoints for ML-DSA-87 Public Key Management
"""
import uuid

from django.conf import settings
from django.db import transaction
from rest_framework import serializers, viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied, ValidationError

from ..models import UserPublicKey
from ..serializers.pki import UserPublicKeySerializer
from ..services import native_signing


class EnrollmentProofSerializer(serializers.Serializer):
    request_id = serializers.UUIDField()
    public_key = serializers.CharField(max_length=3456)
    signature = serializers.CharField(max_length=6172)


class UserPublicKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing user PQC keys for Dual-Layer Signatures.
    """
    serializer_class = UserPublicKeySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Users can only see their own keys, unless they are an admin
        if self.request.user.is_superuser:
            qs = UserPublicKey.objects.all()
            user_id = self.request.query_params.get('user')
            if user_id:
                qs = qs.filter(user_id=user_id)
            return qs
        return UserPublicKey.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def my_keys(self, request):
        """Get all keys belonging to the current user"""
        keys = self.get_queryset()
        serializer = self.get_serializer(keys, many=True)
        return Response(serializer.data)
        
    @action(detail=False, methods=['get'])
    def active_key(self, request):
        """Get the current active key for the user"""
        key = UserPublicKey.objects.filter(
            user=request.user, status='active', native_device_id__isnull=True,
        ).order_by('-created_at').first()
        if not key:
            return Response({'error': 'No active key found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(key)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def prepare_enrollment(self, request):
        intent = native_signing.issue(request, 'enroll_signing_key', device_id=str(uuid.uuid4()))
        return Response({'request_id': intent.pk, 'payload': intent.payload}, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=['get'])
    def signing_devices(self, request):
        if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False):
            raise PermissionDenied('Native signing is disabled.')
        devices = UserPublicKey.objects.filter(user=request.user, native_device_id__isnull=False).values_list(
            'native_device_id', 'status',
        )
        return Response([{'device_id': device_id, 'status': state} for device_id, state in devices])

    @action(detail=False, methods=['post'])
    @transaction.atomic
    def complete_enrollment(self, request):
        if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False):
            raise PermissionDenied('Native signing is disabled.')
        data = EnrollmentProofSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        values = data.validated_data
        intent, payload = native_signing.pending(request, values['request_id'], 'enroll_signing_key')
        public_key = values['public_key']
        native_signing.verify_signature(
            public_key, values['signature'], f"{intent.payload}\n{public_key}".encode('utf-8'),
        )
        native_signing.consume(intent)
        serializer = self.get_serializer(data={'pqc_public_key': public_key, 'device_name': 'CPQA Crypto Agent'})
        serializer.is_valid(raise_exception=True)
        key = serializer.save(native_device_id=payload['device_id'])
        return Response({'id': key.pk, 'device_id': key.native_device_id}, status=status.HTTP_201_CREATED)

    def perform_destroy(self, instance):
        if instance.native_device_id:
            raise ValidationError('Revoke this device to retain verification of its historical signatures.')
        super().perform_destroy(instance)
        
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Revoke a specific key"""
        key = self.get_object()
        if key.status == 'revoked':
            return Response({'message': 'Key is already revoked'}, status=status.HTTP_400_BAD_REQUEST)
            
        key.revoke()
        return Response({'message': 'Key revoked successfully'})
