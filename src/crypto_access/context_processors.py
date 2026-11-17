import os
from django.conf import settings

def root_ca_public_key():
    # Raw ML-DSA-87 public key (2592 bytes) encoded as base64
    raw_pk_path = os.path.join(settings.BASE_DIR, '..', 'config', 'certs', 'root_ca_raw_pk.b64')
    root_ca_pk_b64 = ""
    if os.path.exists(raw_pk_path):
        with open(raw_pk_path, 'r') as f:
            root_ca_pk_b64 = f.read().strip()
            
    return root_ca_pk_b64


def pqc_settings(request):
    return {
        'ENABLE_PQC_FEATURES': getattr(settings, 'ENABLE_PQC_FEATURES', True),
        'ROOT_CA_PUBLIC_KEY': root_ca_public_key()
    }

def policy_choices(request):
    """Expose AccessPolicy choices to all templates"""
    from crypto_access.models import AccessPolicy
    return {
        'POLICY_RESOURCE_CHOICES': AccessPolicy.RESOURCE_CHOICES,
        'POLICY_ACTION_CHOICES': AccessPolicy.ACTION_CHOICES,
        'POLICY_EFFECT_CHOICES': AccessPolicy.EFFECT_CHOICES,
    }

