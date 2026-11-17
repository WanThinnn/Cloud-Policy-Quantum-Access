"""CPQA one-use ML-DSA-87 enrollment and upload authorization."""
import base64
import ctypes
from datetime import timedelta
from functools import lru_cache
import hashlib
import hmac
import json
from pathlib import Path
import platform
import uuid
from urllib.parse import urlsplit

from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import APIException, PermissionDenied, ValidationError

from ..models import NativeSigningRequest


PUBLIC_KEY_BYTES = 2592
SIGNATURE_BYTES = 4627


class SigningUnavailable(APIException):
    status_code = 503
    default_detail = 'The ML-DSA verification service is unavailable.'


class SigningConflict(APIException):
    status_code = 409
    default_detail = 'The signing request expired, was used, or the upload target changed.'


def decode_blob(value, expected_length):
    try:
        if not isinstance(value, str) or len(value) != 4 * ((expected_length + 2) // 3):
            raise ValueError()
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != expected_length:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValidationError('Invalid ML-DSA-87 public key or signature encoding.') from None
    return decoded


@lru_cache(maxsize=1)
def _verifier():
    import os

    suffix = {'Windows': 'dll', 'Darwin': 'dylib', 'Linux': 'so'}[platform.system()]
    directory = Path(os.environ.get('CPABE_LIBRARY_DIR', settings.BASE_DIR / 'lib'))
    library = ctypes.CDLL(str((directory / f'libhybrid-pq-cp-abe.{suffix}').resolve(strict=True)))
    verify = library.ml_dsa_87_verify
    verify.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
    verify.restype = ctypes.c_int
    return verify


def verify_signature(public_key, signature, message):
    key = decode_blob(public_key, PUBLIC_KEY_BYTES)
    sig = decode_blob(signature, SIGNATURE_BYTES)
    try:
        verify = _verifier()
    except (AttributeError, KeyError, OSError):
        raise SigningUnavailable() from None
    if verify(message, len(message), sig, len(sig), key) != 0:
        raise ValidationError('ML-DSA-87 signature verification failed.')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def signing_origin(request):
    origin = getattr(settings, 'CRYPTO_AGENT_ORIGIN', '') or request.build_absolute_uri('/').rstrip('/')
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or parsed.netloc != request.get_host() or origin != f'https://{parsed.netloc}':
        raise PermissionDenied('Native signing requires the configured HTTPS origin.')
    return origin


def target_fingerprint(bucket, path):
    data = _canonical([bucket.pk, path]).encode('ascii')
    return hmac.new(settings.SECRET_KEY.encode(), data, hashlib.sha256).hexdigest()


def version_target(bucket, path, file, version):
    return {'target': target_fingerprint(bucket, path), 'file_id': file.pk if file else None, 'version': version}


def issue(request, kind, *, key=None, **details):
    if not getattr(settings, 'NATIVE_SIGNING_ENABLED', False):
        raise PermissionDenied('Native signing is disabled.')
    now = timezone.now()
    NativeSigningRequest.objects.filter(user=request.user, expires_at__lte=now).delete()
    nonce = uuid.uuid4()
    expires = now + timedelta(minutes=3)
    payload = _canonical({
        'protocol': 'cpqa-crypto/v1', 'operation': kind, 'request_id': str(nonce),
        'user_id': request.user.pk, 'origin': signing_origin(request), 'expires_at': int(expires.timestamp()),
        **details,
    })
    return NativeSigningRequest.objects.create(
        id=nonce, user=request.user, key=key, expires_at=expires, payload=payload,
    )


def pending(request, request_id, kind):
    now = timezone.now()
    intent = NativeSigningRequest.objects.select_for_update().filter(
        id=request_id, user=request.user, consumed_at__isnull=True, expires_at__gt=now,
    ).first()
    if intent is None:
        raise SigningConflict()
    value = json.loads(intent.payload)
    if value['operation'] != kind or value['origin'] != signing_origin(request):
        raise SigningConflict()
    return intent, value


def consume(intent):
    now = timezone.now()
    if not NativeSigningRequest.objects.filter(
        pk=intent.pk, consumed_at__isnull=True, expires_at__gt=now,
    ).update(consumed_at=now):
        raise SigningConflict()


def verify_upload(request, request_id, signature, digest, target):
    from ..models import UserPublicKey

    intent, value = pending(request, request_id, 'sign_document')
    if value['sha3_256'] != digest or any(value[name] != item for name, item in target.items()):
        raise SigningConflict()
    key = UserPublicKey.objects.select_for_update().filter(
        pk=intent.key_id, user=request.user, status='active', native_device_id__isnull=False,
    ).first()
    if key is None or value['device_id'] != str(key.native_device_id):
        raise PermissionDenied('The signing device is no longer authorized.')
    verify_signature(key.pqc_public_key, signature, intent.payload.encode('ascii'))
    consume(intent)
    return key, intent.payload
