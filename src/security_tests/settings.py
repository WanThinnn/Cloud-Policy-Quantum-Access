"""Test-only settings. Never import deployment settings or its .env file.

Run in src (or /app):
python -m django test security_tests --settings=security_tests.settings --noinput
"""
import atexit
import base64
import os
import tempfile
from pathlib import Path

_sandbox = tempfile.TemporaryDirectory(prefix='cpqa-security-tests-')
atexit.register(_sandbox.cleanup)
# Even an accidental lazy crypto initialization must stay inside the sandbox.
BASE_DIR = Path(_sandbox.name)
SECRET_KEY = 'isolated-security-regression-tests-only'
DEBUG = False
USE_TZ = True
ALLOWED_HOSTS = ['testserver']
ROOT_URLCONF = 'security_tests.urls'
MIDDLEWARE = []
INSTALLED_APPS = [
    'django.contrib.auth', 'django.contrib.contenttypes',
    'rest_framework_simplejwt.token_blacklist', 'crypto_access',
]
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
MIGRATION_MODULES = {'crypto_access': None}
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
REST_FRAMEWORK = {'DEFAULT_AUTHENTICATION_CLASSES': [], 'DEFAULT_THROTTLE_CLASSES': []}
MEDIA_ROOT = Path(_sandbox.name) / 'media'
STORAGE_VENDOR = 'local_disk'
MEDIA_URL = '/media/'
FIELD_ENCRYPTION = False
ENABLE_PQC_FEATURES = False
WEBAUTHN_RP_ID = 'testserver'
WEBAUTHN_ORIGIN = 'http://testserver'
WEBAUTHN_RP_NAME = 'Security tests'
# Services also read os.environ directly. Isolate those lookups from deployment secrets.
os.environ['VAULT_ADDR'] = ''
os.environ['VAULT_TOKEN'] = ''
os.environ['KEYS_DIR'] = str(Path(_sandbox.name) / 'keys')
os.environ['MASTER_FIELD_ENCRYPTION_KEY'] = base64.urlsafe_b64encode(b't' * 32).decode()
