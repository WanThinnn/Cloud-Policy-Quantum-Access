"""
PKI Serializers
"""
from rest_framework import serializers
from ..models import UserPublicKey


class UserPublicKeySerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = UserPublicKey
        fields = [
            'id', 'user', 'username', 'pqc_public_key',
            'encrypted_pqc_sk_primary', 'encrypted_pqc_sk_recovery',
            'credential_id', 'status', 'device_name', 'ca_signature', 'created_at', 'updated_at', 'native_device_id'
        ]
        read_only_fields = ['user', 'status', 'ca_signature', 'created_at', 'updated_at', 'native_device_id']

    def validate(self, attrs):
        if self.instance and self.instance.native_device_id:
            raise serializers.ValidationError('Native signing keys can only be revoked.')
        primary_field = 'encrypted_pqc_sk_primary'
        credential_field = 'credential_id'
        if self.instance is not None and (primary_field in attrs or credential_field in attrs):
            if (primary_field not in attrs or credential_field not in attrs or
                    bool(attrs[primary_field]) != bool(attrs[credential_field])):
                raise serializers.ValidationError('Update the signing passkey credential ID and encrypted key together.')
        return attrs

    def update(self, instance, validated_data):
        # A phrase replacement must not overwrite a concurrent passkey rebind (or vice versa).
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if validated_data:
            instance.save(update_fields=[*validated_data, 'updated_at'])
        return instance

    def create(self, validated_data):
        from ..services.pki_service import PKIService
        from django.utils import timezone
        
        # Set the user to the current request user
        user = self.context['request'].user
        validated_data['user'] = user
        
        # We could potentially revoke all other keys for this user, 
        # or just allow multiple active keys per user. 
        # For now, allow multiple, but let's say the newest one is primary.
        
        # Generate JSON Certificate and Sign it
        cert_payload = {
            "user": user.username,
            "public_key": validated_data.get('pqc_public_key'),
            "issuer": "CyberFortress-RootCA"
        }
        
        try:
            ca_signature = PKIService.sign_payload(cert_payload)
            validated_data['ca_signature'] = ca_signature
        except Exception as e:
            # If signing fails, we might still want to create the key, or maybe fail the request.
            # For security, we should fail the request.
            raise serializers.ValidationError(f"Failed to generate CA certificate: {str(e)}")
            
        return super().create(validated_data)
