from rest_framework.throttling import UserRateThrottle
from .services.runtime_settings import get_runtime_setting

class CPABEDecryptThrottle(UserRateThrottle):
    """
    Throttle for CP-ABE decryption endpoints (download, preview).
    These operations are CPU intensive, so we limit them strictly.
    Default: 10 requests per minute per user.
    """
    scope = 'cpabe_decrypt'

    def get_rate(self):
        return f"{get_runtime_setting('CPABE_DECRYPT_PER_MINUTE')}/min"


class CPABEEncryptThrottle(UserRateThrottle):
    """
    Throttle for CP-ABE encryption endpoints (upload).
    Default: 5 requests per minute per user.
    """
    scope = 'cpabe_encrypt'

    def get_rate(self):
        return f"{get_runtime_setting('CPABE_ENCRYPT_PER_MINUTE')}/min"
