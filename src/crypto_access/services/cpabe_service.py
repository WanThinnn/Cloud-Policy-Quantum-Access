import os
import platform
import ctypes
import tempfile
import logging
import json
from typing import List, TYPE_CHECKING
from django.conf import settings
from crypto_access.services.vault_service import vault_service
import base64
import requests
import urllib3
import hashlib
import threading
from dataclasses import dataclass
from .covercrypt_public_key import public_key_fingerprint
from .vault_abe_contract import PublicAuthority

if TYPE_CHECKING:
    from .covercrypt_config import CoverCryptConfiguration

logger = logging.getLogger(__name__)

COVERCRYPT_KEYSET_ID = "primary"
COVERCRYPT_VAULT_MOUNT = "abe_covercrypt"
COVERCRYPT_PUBLIC_KEY_KEY = "CPABE_PK_COVERCRYPT"
COVERCRYPT_PQC_PUBLIC_KEY_KEY = "PQC_PK_COVERCRYPT"
COVERCRYPT_MANIFEST_KEY = "COVERCRYPT_KEYSET_MANIFEST_primary"
COVERCRYPT_INIT_MARKER_KEY = "COVERCRYPT_KEYSET_INITIALIZING_primary"
COVERCRYPT_MOUNT_CREATED_KEY = "COVERCRYPT_MOUNT_CREATED"
COVERCRYPT_NATIVE_KEYSET_ID = "primary-native"
COVERCRYPT_NATIVE_PK_KEY = "CPABE_PK_COVERCRYPT_NATIVE"
COVERCRYPT_NATIVE_MSK_KEY = "CPABE_MSK_COVERCRYPT_NATIVE"
COVERCRYPT_NATIVE_PQC_PK_KEY = "PQC_PK_COVERCRYPT_NATIVE"
COVERCRYPT_NATIVE_PQC_SK_KEY = "PQC_SK_COVERCRYPT_NATIVE"
_COVERCRYPT_ENV_LOCK = threading.RLock()

class CPABEError(Exception):
    pass


class CPABEAccessDenied(CPABEError):
    pass


@dataclass(frozen=True)
class CoverCryptVaultRoute:
    mount: str
    configuration: 'CoverCryptConfiguration'
    authority: PublicAuthority


class CPABEService:
    """Wrapper for libhybrid-cp-abe using ctypes"""

    @classmethod
    def vault_metadata_client(cls):
        """Connection-only client for operator inspection; never initializes keys."""
        service = object.__new__(cls)
        service.use_vault_plugin = True
        vault_ca = os.environ.get('VAULT_CACERT')
        service._vault_verify = vault_ca if vault_ca and os.path.exists(vault_ca) else True
        return service
    
    def __init__(self):
        self.use_vault_plugin = getattr(settings, 'USE_VAULT_ABE_PLUGIN', False)
        from .abe_schemes import validate_scheme
        validate_scheme(backend='vault' if self.use_vault_plugin else 'native')
        
        system = platform.system()
        if system == 'Windows':
            lib_name = 'libhybrid-pq-cp-abe.dll'
        else:
            lib_name = 'libhybrid-pq-cp-abe.so'
            
        # Docker artifacts live outside /app so the development bind mount
        # cannot mask them or reuse an anonymous volume from an older image.
        library_dir = os.environ.get('CPABE_LIBRARY_DIR', os.path.join(settings.BASE_DIR, 'lib'))
        self.dll_path = os.path.join(library_dir, lib_name)
        self.keys_dir = os.path.join(settings.BASE_DIR, 'config', 'keys')
        self.msk_path = os.path.join(self.keys_dir, 'cpabe_msk.key')
        self.pk_path = os.path.join(self.keys_dir, 'cpabe_pk.key')
        self.pqc_sk_path = os.path.join(self.keys_dir, 'pqc_sk.key')
        self.pqc_pk_path = os.path.join(self.keys_dir, 'pqc_pk.key')
        
        self._lib = None
        if not self.use_vault_plugin:
            try:
                self._lib = ctypes.CDLL(self.dll_path)
                self._setup_bindings()
            except Exception as e:
                logger.error(f"Failed to initialize CPABE library: {e}")
                
        # Vault CA cert for TLS verification on plugin API calls
        vault_ca = os.environ.get('VAULT_CACERT')
        self._vault_verify = vault_ca if (vault_ca and os.path.exists(vault_ca)) else True

        self._ensure_keys_exist()
        if (not self.use_vault_plugin and
                getattr(settings, 'CPABE_SCHEME', 'ac17').strip().lower() == 'covercrypt'):
            self._ensure_covercrypt_native_keyset()
            
    def _setup_bindings(self):
        """Define C function signatures"""
        byte_ptr = ctypes.POINTER(ctypes.c_ubyte)
        size_ptr = ctypes.POINTER(ctypes.c_size_t)
        self._setup_scheme_func = getattr(self._lib, 'hybrid_cpabe_setupBuffer_with_scheme', None)
        self._setup_scheme_pqc_func = getattr(self._lib, 'hybrid_cpabe_setupBuffer_with_pqc_scheme', None)
        self._genkey_scheme_func = getattr(self._lib, 'hybrid_cpabe_genkeyBuffer_with_scheme', None)
        self._encrypt_scheme_func = getattr(self._lib, 'hybrid_cpabe_encryptBuffer_with_scheme', None)
        self._encrypt_sign_scheme_func = getattr(self._lib, 'hybrid_cpabe_encryptBuffer_and_sign_with_scheme', None)
        if self._setup_scheme_func:
            self._setup_scheme_func.argtypes = [ctypes.POINTER(byte_ptr), size_ptr,
                ctypes.POINTER(byte_ptr), size_ptr, ctypes.c_int]
            self._setup_scheme_func.restype = ctypes.c_int
        if self._setup_scheme_pqc_func:
            self._setup_scheme_pqc_func.argtypes = [ctypes.POINTER(byte_ptr), size_ptr,
                ctypes.POINTER(byte_ptr), size_ptr, ctypes.POINTER(byte_ptr), size_ptr,
                ctypes.POINTER(byte_ptr), size_ptr, ctypes.c_int]
            self._setup_scheme_pqc_func.restype = ctypes.c_int
        if self._genkey_scheme_func:
            self._genkey_scheme_func.argtypes = [byte_ptr, ctypes.c_size_t, ctypes.c_char_p,
                ctypes.POINTER(byte_ptr), size_ptr, ctypes.c_int]
            self._genkey_scheme_func.restype = ctypes.c_int
        if self._encrypt_scheme_func:
            self._encrypt_scheme_func.argtypes = [byte_ptr, ctypes.c_size_t, byte_ptr, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.POINTER(byte_ptr), size_ptr, ctypes.c_int]
            self._encrypt_scheme_func.restype = ctypes.c_int
        if self._encrypt_sign_scheme_func:
            self._encrypt_sign_scheme_func.argtypes = [byte_ptr, ctypes.c_size_t, byte_ptr, ctypes.c_size_t,
                byte_ptr, ctypes.c_size_t, ctypes.c_char_p, ctypes.POINTER(byte_ptr), size_ptr, ctypes.c_int]
            self._encrypt_sign_scheme_func.restype = ctypes.c_int

        # int setup(const char *path)
        self._lib.setup.argtypes = [ctypes.c_char_p]
        self._lib.setup.restype = ctypes.c_int
        
        # int generateSecretKey(const char *masterKeyFile, const char *attributes, const char *privateKeyFile)
        self._lib.generateSecretKey.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        self._lib.generateSecretKey.restype = ctypes.c_int
        
        # int AC17encrypt(const char *publicKeyFile, const char *plaintextFile, const char *policy, const char *ciphertextFile)
        self._encrypt_func = getattr(self._lib, 'AC17encrypt', getattr(self._lib, 'hybrid_cpabe_encrypt', None))
        if self._encrypt_func:
            self._encrypt_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            self._encrypt_func.restype = ctypes.c_int
        
        # int hybrid_cpabe_decrypt(const char *privateKeyFile, const char *ciphertextFile, const char *recovertextFile)
        self._decrypt_func = getattr(self._lib, 'AC17decrypt', getattr(self._lib, 'hybrid_cpabe_decrypt', None))
        if self._decrypt_func:
            self._decrypt_func.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            self._decrypt_func.restype = ctypes.c_int
            
        # Buffer-based Operations
        self._encrypt_buffer_func = getattr(self._lib, 'AC17encryptBuffer', getattr(self._lib, 'hybrid_cpabe_encryptBuffer', None))
        if self._encrypt_buffer_func:
            self._encrypt_buffer_func.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # publicKey, pkLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # plaintext, ptLen
                ctypes.c_char_p,                                 # policy
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t) # ciphertext, ctLen
            ]
            self._encrypt_buffer_func.restype = ctypes.c_int
            
        self._decrypt_buffer_func = getattr(self._lib, 'AC17decryptBuffer', getattr(self._lib, 'hybrid_cpabe_decryptBuffer', None))
        if self._decrypt_buffer_func:
            self._decrypt_buffer_func.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # privateKey, skLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # ciphertext, ctLen
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t) # plaintext, ptLen
            ]
            self._decrypt_buffer_func.restype = ctypes.c_int
            
        # void freeBuffer(unsigned char *buffer)
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
            self._lib.freeBuffer.restype = None
            
        # PQC functions
        self._setup_pqc_func = getattr(self._lib, 'hybrid_cpabe_setup_with_pqc', None)
        if self._setup_pqc_func:
            self._setup_pqc_func.argtypes = [ctypes.c_char_p]
            self._setup_pqc_func.restype = ctypes.c_int

        self._encrypt_buffer_sign_func = getattr(self._lib, 'hybrid_cpabe_encryptBuffer_and_sign', None)
        if self._encrypt_buffer_sign_func:
            self._encrypt_buffer_sign_func.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # publicKey, pkLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # masterKey, mskLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # plaintext, ptLen
                ctypes.c_char_p,                                 # policy
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t) # ciphertext, ctLen
            ]
            self._encrypt_buffer_sign_func.restype = ctypes.c_int

        self._decrypt_buffer_verify_func = getattr(self._lib, 'hybrid_cpabe_decryptBuffer_and_verify', None)
        if self._decrypt_buffer_verify_func:
            self._decrypt_buffer_verify_func.argtypes = [
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # privateKey, skLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # publicKey, pkLen
                ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, # ciphertext, ctLen
                ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t) # plaintext, ptLen
            ]
            self._decrypt_buffer_verify_func.restype = ctypes.c_int
            
        # const char* getVersion(void)
        if hasattr(self._lib, 'getVersion'):
            self._lib.getVersion.argtypes = []
            self._lib.getVersion.restype = ctypes.c_char_p
        
        # const char* getErrorMessage(int errorCode)
        self._lib.getErrorMessage.argtypes = [ctypes.c_int]
        self._lib.getErrorMessage.restype = ctypes.c_char_p
        
    def _read_vault_authority(self, scheme, headers, configuration=None, public_key_format='reference', *, mount=None):
        from .vault_abe_contract import parse_public_authority
        response = requests.get(
            f"{vault_service.get_addr}/v1/{mount or f'abe_{scheme}'}/authority", headers=headers,
            params={'public_key_format': public_key_format}, verify=self._vault_verify, timeout=120,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return parse_public_authority(response.json()['data'], scheme, configuration)

    def _verify_vault_setup_contract(self, scheme, headers):
        from .vault_abe_contract import verify_create_only_help
        # Vault's SDK help proves create_only is understood before a write.
        # A 404 on authority alone is also returned by obsolete plugins.
        help_response = requests.get(
            f"{vault_service.get_addr}/v1/abe_{scheme}/setup", headers=headers,
            params={'help': '1'}, verify=self._vault_verify, timeout=30,
        )
        help_response.raise_for_status()
        verify_create_only_help(help_response.json())

    def _create_vault_authority(self, scheme, headers, pqc_enabled, configuration=None):
        from .vault_abe_contract import parse_public_authority
        payload = {'scheme': scheme, 'pqc': bool(pqc_enabled), 'create_only': True,
                   'public_key_format': 'reference' if scheme == 'covercrypt' else 'base64'}
        if configuration is not None:
            payload.update(config_json=configuration.config_json, mode='hybridized')
        response = requests.put(
            f"{vault_service.get_addr}/v1/abe_{scheme}/setup", headers=headers,
            json=payload, verify=self._vault_verify, timeout=310 if scheme == 'covercrypt' else 120,
        )
        response.raise_for_status()
        authority = parse_public_authority(response.json()['data'], scheme, configuration)
        if authority.pqc != bool(pqc_enabled):
            raise CPABEError('Vault setup returned a different signature state.')
        return authority

    @staticmethod
    def _covercrypt_record(route):
        from .covercrypt_config import build_keyset_manifest, canonical_json

        authority = route.authority
        manifest = build_keyset_manifest(COVERCRYPT_KEYSET_ID, route.mount, route.configuration, authority.fingerprint)
        manifest.update(pqc_enabled=authority.pqc, contract_version=1,
                        authority_revision=authority.revision, public_key_format=authority.public_key_format)
        return {
            COVERCRYPT_PUBLIC_KEY_KEY: authority.public_key,
            COVERCRYPT_PQC_PUBLIC_KEY_KEY: authority.verifier,
            COVERCRYPT_MANIFEST_KEY: canonical_json(manifest),
            COVERCRYPT_INIT_MARKER_KEY: 'initialized',
        }

    def _verify_covercrypt_record(self, record, headers):
        from .covercrypt_config import configuration_from_manifest, parse_keyset_manifest, validate_vault_mount

        manifest = parse_keyset_manifest(record.get(COVERCRYPT_MANIFEST_KEY))
        mount = validate_vault_mount(manifest.get('vault_mount'))
        configuration = configuration_from_manifest(manifest)
        authority = self._read_vault_authority('covercrypt', headers, configuration, mount=mount)
        if authority is None:
            raise CPABEError('The recorded CoverCrypt mount has no available authority.')
        route = CoverCryptVaultRoute(mount, configuration, authority)
        verified = self._covercrypt_record(route)
        if (manifest != parse_keyset_manifest(verified[COVERCRYPT_MANIFEST_KEY]) or any(
            record.get(key) != verified[key] for key in (COVERCRYPT_PUBLIC_KEY_KEY, COVERCRYPT_PQC_PUBLIC_KEY_KEY)
        )):
            raise CPABEError('The recorded CoverCrypt authority differs from its approved metadata.')
        return route

    @staticmethod
    def _covercrypt_authority_state():
        from .covercrypt_config import AUTHORITY_HISTORY_KEY

        return vault_service.get_secrets([
            COVERCRYPT_MANIFEST_KEY, COVERCRYPT_PUBLIC_KEY_KEY, COVERCRYPT_PQC_PUBLIC_KEY_KEY,
            COVERCRYPT_INIT_MARKER_KEY, AUTHORITY_HISTORY_KEY,
        ])

    def rotate_covercrypt_authority(self, mount, expected_fingerprint):
        """Promote an independently provisioned mount and retain the previous authority."""
        from .covercrypt_config import AUTHORITY_HISTORY_KEY, build_covercrypt_configuration, validate_vault_mount

        mount = validate_vault_mount(mount)
        headers = {'X-Vault-Token': vault_service.get_token}
        state = self._covercrypt_authority_state()
        previous = self._verify_covercrypt_record(state, headers)
        if previous.authority.fingerprint != expected_fingerprint:
            raise CPABEError('The active CoverCrypt fingerprint changed before promotion.')
        history = state.get(AUTHORITY_HISTORY_KEY, {})
        if not isinstance(history, dict):
            raise CPABEError('CoverCrypt authority history is malformed.')
        if mount == previous.mount or any(
            self._covercrypt_record_mount(entry) == mount for entry in history.values()
        ):
            raise CPABEError('Rotation requires a separate, unused CoverCrypt mount.')
        configuration = build_covercrypt_configuration()
        authority = self._read_vault_authority('covercrypt', headers, configuration, mount=mount)
        if authority is None:
            raise CPABEError('Provision the candidate authority before promotion.')
        if authority.fingerprint == previous.authority.fingerprint or any(
            key.startswith(f'{authority.fingerprint}:') for key in history
        ):
            raise CPABEError('Rotation requires a new authority identity.')
        if getattr(settings, 'ENABLE_PQC_FEATURES', False) and not authority.pqc:
            raise CPABEError('The candidate authority cannot sign new ciphertext.')
        record = self._covercrypt_record(CoverCryptVaultRoute(mount, configuration, authority))
        previous_identity = f'{previous.authority.fingerprint}:{previous.authority.revision}'
        record[AUTHORITY_HISTORY_KEY] = {**history, previous_identity: self._covercrypt_record(previous)}
        expected = {key: state.get(key) for key in record}
        if not vault_service.compare_and_put_secrets(expected, record):
            raise CPABEError('The CoverCrypt registry changed during promotion; verify it before retrying.')
        return json.loads(record[COVERCRYPT_MANIFEST_KEY])

    @staticmethod
    def _covercrypt_record_mount(record):
        from .covercrypt_config import parse_keyset_manifest, validate_vault_mount

        return validate_vault_mount(parse_keyset_manifest(record[COVERCRYPT_MANIFEST_KEY]).get('vault_mount'))

    def _ensure_covercrypt_keyset(self, pqc_enabled, headers, *, allow_setup=True, return_route=False):
        """Verify contract v1; reconcile only a recorded identity/first-setup guard.

        Reconciliation reads authority and atomically publishes public KV metadata.
        It never retries setup after an interrupted attempt or a missing KV record.
        """
        from .covercrypt_config import (
            AUTHORITY_HISTORY_KEY, build_covercrypt_configuration, parse_keyset_manifest, validate_vault_mount,
            verify_keyset_manifest,
        )
        from .vault_abe_contract import VaultABEContractError
        if not vault_service.is_authenticated():
            raise CPABEError('Vault authentication is required to verify the CoverCrypt keyset.')
        configuration = build_covercrypt_configuration()
        state = vault_service.get_secrets([
            COVERCRYPT_PUBLIC_KEY_KEY, COVERCRYPT_PQC_PUBLIC_KEY_KEY, COVERCRYPT_MANIFEST_KEY,
            COVERCRYPT_INIT_MARKER_KEY, COVERCRYPT_MOUNT_CREATED_KEY, AUTHORITY_HISTORY_KEY,
        ])
        public_key = state.get(COVERCRYPT_PUBLIC_KEY_KEY)
        verifier = state.get(COVERCRYPT_PQC_PUBLIC_KEY_KEY)
        manifest_raw = state.get(COVERCRYPT_MANIFEST_KEY)
        if manifest_raw is None and state.get(AUTHORITY_HISTORY_KEY) is not None:
            raise CPABEError('The active CoverCrypt manifest is missing from a rotated registry.')
        marker_raw = state.get(COVERCRYPT_INIT_MARKER_KEY)
        partial = any(value is not None for value in (public_key, verifier, marker_raw))
        stored_manifest = None
        mount = COVERCRYPT_VAULT_MOUNT
        try:
            known_fingerprint = public_key_fingerprint(public_key) if public_key else None
            if manifest_raw is not None:
                if not public_key:
                    raise CPABEError('CoverCrypt manifest exists but its recorded public key is missing.')
                mount = validate_vault_mount(parse_keyset_manifest(manifest_raw).get('vault_mount'))
                stored_manifest = verify_keyset_manifest(
                    manifest_raw, COVERCRYPT_KEYSET_ID, mount, configuration,
                    public_key_fingerprint=known_fingerprint,
                )
                if type(stored_manifest.get('pqc_enabled')) is not bool or stored_manifest['pqc_enabled'] != bool(verifier):
                    raise CPABEError('CoverCrypt signature state does not match its recorded manifest.')
            elif partial:
                marker = json.loads(marker_raw) if isinstance(marker_raw, str) else marker_raw
                if (not isinstance(marker, dict) or marker.get('status') != 'initializing' or
                        marker.get('config_fingerprint') != configuration.fingerprint or
                        state.get(COVERCRYPT_MOUNT_CREATED_KEY) != COVERCRYPT_VAULT_MOUNT):
                    raise CPABEError('CoverCrypt initialization guard is incompatible; operator reconciliation is required.')
                if ('pqc_enabled' in marker and
                        (type(marker['pqc_enabled']) is not bool or marker['pqc_enabled'] != bool(pqc_enabled))):
                    raise CPABEError('CoverCrypt initialization guard has a different signature state.')

            authority = self._read_vault_authority('covercrypt', headers, configuration, mount=mount)
            if authority is None:
                if not allow_setup and manifest_raw is None and not partial:
                    raise CPABEError('CoverCrypt requires first-time initialization via covercrypt_config --initialize-vault.')
                if manifest_raw is not None or partial or not allow_setup:
                    raise CPABEError('CoverCrypt authority is unavailable or the plugin needs upgrading; setup was not repeated.')
                if state.get(COVERCRYPT_MOUNT_CREATED_KEY) != COVERCRYPT_VAULT_MOUNT:
                    raise CPABEError('CoverCrypt mount was not recorded as newly created; refusing setup.')
                self._verify_vault_setup_contract('covercrypt', headers)
                marker = json.dumps({'status': 'initializing', 'config_fingerprint': configuration.fingerprint,
                                     'pqc_enabled': bool(pqc_enabled)})
                if not vault_service.claim_secret(COVERCRYPT_INIT_MARKER_KEY, marker):
                    raise CPABEError('CoverCrypt initialization guard could not be acquired; retry later.')
                state[COVERCRYPT_INIT_MARKER_KEY] = marker
                authority = self._create_vault_authority('covercrypt', headers, pqc_enabled, configuration)
            elif manifest_raw is None and not partial:
                raise CPABEError('An unrecorded CoverCrypt authority exists; restore its approved metadata before recovery.')
            elif manifest_raw is None and authority.pqc != bool(pqc_enabled):
                raise CPABEError('Recovered CoverCrypt signature state differs from the interrupted initialization.')

            if known_fingerprint and known_fingerprint != authority.fingerprint:
                raise CPABEError('Vault CoverCrypt authority differs from the recorded public key.')
            if verifier and verifier != authority.verifier:
                raise CPABEError('Vault CoverCrypt verification key differs from the recorded verifier.')
            if stored_manifest is not None:
                if stored_manifest['pqc_enabled'] != authority.pqc:
                    raise CPABEError('Vault CoverCrypt signature state differs from its recorded manifest.')
                revision = stored_manifest.get('authority_revision')
                if revision is not None and (type(revision) is not int or revision != authority.revision):
                    raise CPABEError('Vault CoverCrypt authority revision changed; operator reconciliation is required.')
            if pqc_enabled and not authority.pqc:
                raise CPABEError('CoverCrypt authority has no signing key for the requested signed operation.')
            route = CoverCryptVaultRoute(mount, configuration, authority)
            record = self._covercrypt_record(route)
            if any(state.get(key) != value for key, value in record.items()):
                if not vault_service.compare_and_put_secrets({key: state.get(key) for key in record}, record):
                    raise CPABEError('Could not atomically persist CoverCrypt keyset metadata in Vault KV.')
            if return_route:
                return route
            return authority.public_key
        except CPABEError:
            raise
        except (ValueError, TypeError, KeyError, requests.RequestException, VaultABEContractError) as exc:
            logger.error('CoverCrypt authority verification failed (%s).', type(exc).__name__)
            if isinstance(exc, VaultABEContractError):
                raise CPABEError(str(exc)) from exc
            raise CPABEError('CoverCrypt authority could not be verified; setup/recovery was refused.') from exc

    def _ensure_classical_vault_keyset(self, scheme, headers, pqc_enabled):
        """Recover missing AC17/TKN20 public metadata without replacing keys."""
        authority = self._read_vault_authority(scheme, headers, public_key_format='base64')
        if authority is None:
            self._verify_vault_setup_contract(scheme, headers)
            authority = self._create_vault_authority(scheme, headers, pqc_enabled)
        if pqc_enabled and not authority.pqc:
            raise CPABEError('Existing Vault authority has no signing key; refusing replacement setup.')
        if not vault_service.put_secrets({f'CPABE_PK_{scheme.upper()}': authority.public_key,
                                         f'PQC_PK_{scheme.upper()}': authority.verifier}):
            raise CPABEError('Could not atomically persist Vault authority public metadata.')
        return authority.public_key

    def _ensure_covercrypt_native_keyset(self):
        with _COVERCRYPT_ENV_LOCK:
            return self._ensure_covercrypt_native_keyset_locked()

    def _ensure_covercrypt_native_keyset_locked(self):
        """Load or create the native CoverCrypt authority; master secrets stay in Vault."""
        from .covercrypt_config import (
            CoverCryptConfigurationError, build_covercrypt_configuration,
            build_keyset_manifest, verify_keyset_manifest,
        )

        if not self._lib or not self._setup_scheme_func:
            raise CPABEError("The loaded native library does not expose scheme-aware CoverCrypt setup.")
        if not vault_service.is_authenticated():
            raise CPABEError("Vault authentication is required for native CoverCrypt key material.")

        configuration = build_covercrypt_configuration()
        pqc_enabled = bool(getattr(settings, 'ENABLE_PQC_FEATURES', False))
        manifest_key = f"COVERCRYPT_KEYSET_MANIFEST_{COVERCRYPT_NATIVE_KEYSET_ID}"
        init_key = f"COVERCRYPT_KEYSET_INITIALIZING_{COVERCRYPT_NATIVE_KEYSET_ID}"
        state = vault_service.get_secrets([
            COVERCRYPT_NATIVE_PK_KEY, COVERCRYPT_NATIVE_MSK_KEY, COVERCRYPT_NATIVE_PQC_PK_KEY,
            COVERCRYPT_NATIVE_PQC_SK_KEY, manifest_key, init_key,
        ])
        pk_b64 = state.get(COVERCRYPT_NATIVE_PK_KEY)
        msk_b64 = state.get(COVERCRYPT_NATIVE_MSK_KEY)
        pqc_pk_b64 = state.get(COVERCRYPT_NATIVE_PQC_PK_KEY)
        pqc_sk_b64 = state.get(COVERCRYPT_NATIVE_PQC_SK_KEY)
        manifest_raw = state.get(manifest_key)

        if manifest_raw:
            if not pk_b64 or not msk_b64:
                raise CPABEError("Native CoverCrypt manifest exists but its authority keys are incomplete.")
            if pqc_enabled and (not pqc_pk_b64 or not pqc_sk_b64):
                raise CPABEError("CoverCrypt signing is enabled but its native ML-DSA keys are unavailable.")
            try:
                pk = base64.b64decode(pk_b64, validate=True)
                msk = base64.b64decode(msk_b64, validate=True)
                verify_keyset_manifest(
                    manifest_raw, COVERCRYPT_NATIVE_KEYSET_ID, "native", configuration,
                    public_key_fingerprint=hashlib.sha256(pk).hexdigest(),
                )
            except (ValueError, CoverCryptConfigurationError) as exc:
                raise CPABEError(f"Native CoverCrypt keyset is incompatible with current dimensions: {exc}") from exc
            self.covercrypt_pk_data, self.covercrypt_msk_data = pk, msk
            self.covercrypt_pqc_pk_data = base64.b64decode(pqc_pk_b64, validate=True) if pqc_pk_b64 else None
            self.covercrypt_pqc_sk_data = base64.b64decode(pqc_sk_b64, validate=True) if pqc_sk_b64 else None
            self.pk_data = base64.b64encode(pk)
            return
        if any((pk_b64, msk_b64, pqc_pk_b64, pqc_sk_b64)):
            raise CPABEError("Native CoverCrypt Vault state is incomplete; refusing to replace authority keys.")
        if state.get(init_key) is not None:
            raise CPABEError("Native CoverCrypt setup was interrupted or is in progress; operator reconciliation is required.")
        if not vault_service.claim_secret(init_key, json.dumps({"status": "initializing", "config_fingerprint": configuration.fingerprint})):
            raise CPABEError("Could not create the native CoverCrypt initialization guard in Vault KV.")

        scheme = 2  # CPABE_SCHEME_COVERCRYPT in the upstream v6 API.
        previous_config = os.environ.get("HCPABE_COVERCRYPT_CONFIG")
        previous_mode = os.environ.get("HCPABE_COVERCRYPT_MODE")
        _COVERCRYPT_ENV_LOCK.acquire()
        try:
            with tempfile.TemporaryDirectory(prefix="cpqa-covercrypt-") as temp_dir:
                config_path = os.path.join(temp_dir, "covercrypt.json")
                with open(config_path, "w", encoding="utf-8") as stream:
                    stream.write(configuration.config_json)
                os.environ["HCPABE_COVERCRYPT_CONFIG"] = config_path
                os.environ["HCPABE_COVERCRYPT_MODE"] = "hybridized"
                pk_ptr = ctypes.POINTER(ctypes.c_ubyte)()
                msk_ptr = ctypes.POINTER(ctypes.c_ubyte)()
                pk_len, msk_len = ctypes.c_size_t(), ctypes.c_size_t()
                pqc_pk_ptr = ctypes.POINTER(ctypes.c_ubyte)()
                pqc_sk_ptr = ctypes.POINTER(ctypes.c_ubyte)()
                pqc_pk_len, pqc_sk_len = ctypes.c_size_t(), ctypes.c_size_t()
                if pqc_enabled:
                    if not self._setup_scheme_pqc_func:
                        raise CPABEError("Native library lacks scheme-aware CoverCrypt plus PQC setup.")
                    result = self._setup_scheme_pqc_func(
                        ctypes.byref(pk_ptr), ctypes.byref(pk_len), ctypes.byref(msk_ptr), ctypes.byref(msk_len),
                        ctypes.byref(pqc_pk_ptr), ctypes.byref(pqc_pk_len), ctypes.byref(pqc_sk_ptr),
                        ctypes.byref(pqc_sk_len), scheme,
                    )
                else:
                    result = self._setup_scheme_func(
                        ctypes.byref(pk_ptr), ctypes.byref(pk_len), ctypes.byref(msk_ptr), ctypes.byref(msk_len), scheme,
                    )
                if result != 0:
                    detail = self._lib.getErrorMessage(result).decode("utf-8", errors="replace")
                    raise CPABEError(f"Native CoverCrypt setup failed ({result}): {detail}")
                pk, msk = bytes(pk_ptr[:pk_len.value]), bytes(msk_ptr[:msk_len.value])
                pqc_pk = bytes(pqc_pk_ptr[:pqc_pk_len.value]) if pqc_enabled else None
                pqc_sk = bytes(pqc_sk_ptr[:pqc_sk_len.value]) if pqc_enabled else None
                if hasattr(self._lib, "freeBuffer"):
                    for ptr in (pk_ptr, msk_ptr, pqc_pk_ptr, pqc_sk_ptr):
                        if ptr:
                            self._lib.freeBuffer(ptr)
                if not pk or not msk or (pqc_enabled and (not pqc_pk or not pqc_sk)):
                    raise CPABEError("Native CoverCrypt setup returned incomplete key material.")
                manifest = build_keyset_manifest(
                    COVERCRYPT_NATIVE_KEYSET_ID, "native", configuration,
                    public_key_fingerprint=hashlib.sha256(pk).hexdigest(),
                )
                values = [
                    (COVERCRYPT_NATIVE_PK_KEY, pk), (COVERCRYPT_NATIVE_MSK_KEY, msk),
                    (COVERCRYPT_NATIVE_PQC_PK_KEY, pqc_pk), (COVERCRYPT_NATIVE_PQC_SK_KEY, pqc_sk),
                ]
                record = {key: base64.b64encode(value).decode("ascii") if value else None for key, value in values}
                record[manifest_key] = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                record[init_key] = "initialized"
                if not vault_service.put_secrets(record):
                    raise CPABEError("Could not atomically persist native CoverCrypt keyset in Vault.")
                self.covercrypt_pk_data, self.covercrypt_msk_data = pk, msk
                self.covercrypt_pqc_pk_data, self.covercrypt_pqc_sk_data = pqc_pk, pqc_sk
                self.pk_data = base64.b64encode(pk)
                self.pqc_pk_data = pqc_pk
        except CoverCryptConfigurationError as exc:
            raise CPABEError(f"Native CoverCrypt dimensions are invalid: {exc}") from exc
        finally:
            if previous_config is None:
                os.environ.pop("HCPABE_COVERCRYPT_CONFIG", None)
            else:
                os.environ["HCPABE_COVERCRYPT_CONFIG"] = previous_config
            if previous_mode is None:
                os.environ.pop("HCPABE_COVERCRYPT_MODE", None)
            else:
                os.environ["HCPABE_COVERCRYPT_MODE"] = previous_mode
            _COVERCRYPT_ENV_LOCK.release()

    def covercrypt_cache_identity(self, *, route=None):
        """Return the verified CoverCrypt config/key fingerprint for user-key caches."""
        if route is not None:
            return f'{route.mount}:{route.configuration.fingerprint}:{route.authority.fingerprint}:{route.authority.revision}'
        if self.use_vault_plugin:
            route = self._ensure_covercrypt_keyset(
                bool(getattr(settings, 'ENABLE_PQC_FEATURES', False)),
                {"X-Vault-Token": vault_service.get_token, "Content-Type": "application/json"},
                allow_setup=False, return_route=True,
            )
            return self.covercrypt_cache_identity(route=route)
        self._ensure_covercrypt_native_keyset()
        pk_b64 = base64.b64encode(self.covercrypt_pk_data).decode("ascii")
        manifest = vault_service.get_secret(f"COVERCRYPT_KEYSET_MANIFEST_{COVERCRYPT_NATIVE_KEYSET_ID}")
        try:
            from .covercrypt_config import build_covercrypt_configuration, verify_keyset_manifest
            configuration = build_covercrypt_configuration()
            verified = verify_keyset_manifest(
                manifest, COVERCRYPT_NATIVE_KEYSET_ID, "native", configuration,
                public_key_fingerprint=public_key_fingerprint(pk_b64),
            )
            return f"{verified['config_fingerprint']}:{verified['public_key_fingerprint']}"
        except Exception as exc:
            raise CPABEError(f"CoverCrypt cache identity could not be verified: {exc}") from exc

    def _ensure_keys_exist(self):
        """Load CP-ABE keys from Vault (primary) or local backup (fallback), or generate new ones.
        After loading/generating, always saves a local backup for disaster recovery."""
        from django.conf import settings
        
        if self.use_vault_plugin:
            is_pqc_enabled = getattr(settings, 'ENABLE_PQC_FEATURES', False)
            current_scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
            
            headers = {"X-Vault-Token": vault_service.get_token, "Content-Type": "application/json"}
            
            ac17_pk_b64 = vault_service.get_secret('CPABE_PK_AC17')
            if not ac17_pk_b64:
                ac17_pk_b64 = self._ensure_classical_vault_keyset('ac17', headers, is_pqc_enabled)
            tkn20_pk_b64 = vault_service.get_secret('CPABE_PK_TKN20')
            if not tkn20_pk_b64:
                tkn20_pk_b64 = self._ensure_classical_vault_keyset('tkn20', headers, is_pqc_enabled)
            # Set self.pk_data to current scheme's PK just in case it's read by the frontend/API
            if current_scheme == 'tkn20' and tkn20_pk_b64:
                self.pk_data = base64.b64decode(tkn20_pk_b64)
            elif current_scheme == 'covercrypt':
                self.pk_data = b''  # Vault owns the public key; callers use its verified transport.
            elif ac17_pk_b64:
                self.pk_data = base64.b64decode(ac17_pk_b64)

            logger.info("CP-ABE keys (Vault Plugin Mode) verified/initialized for dual-scheme.")
            return
            
        # Legacy ctypes mode below
        is_pqc_enabled = getattr(settings, 'ENABLE_PQC_FEATURES', False) and bool(getattr(self, '_setup_pqc_func', None))
        
        backup_dir = os.environ.get('KEYS_DIR', self.keys_dir)
        backup_msk = os.path.join(backup_dir, 'cpabe_msk.key')
        backup_pk = os.path.join(backup_dir, 'cpabe_pk.key')
        backup_pqc_sk = os.path.join(backup_dir, 'pqc_sk.key')
        backup_pqc_pk = os.path.join(backup_dir, 'pqc_pk.key')
        
        # 1. Fetch from Vault
        cpabe_msk_b64 = vault_service.get_secret('CPABE_MSK')
        cpabe_pk_b64 = vault_service.get_secret('CPABE_PK')
        pqc_sk_b64 = vault_service.get_secret('PQC_SK')
        pqc_pk_b64 = vault_service.get_secret('PQC_PK')
        
        has_vault_keys = cpabe_msk_b64 and cpabe_pk_b64
        has_backup_keys = os.path.exists(backup_msk) and os.path.exists(backup_pk)
        
        # A feature-flag change must never make existing ABE keys look absent.
        # Load existing signing material independently; missing PQC keys are an
        # explicit signing error, not permission to regenerate an ABE master key.
        self.pqc_sk_data = base64.b64decode(pqc_sk_b64) if pqc_sk_b64 else None
        self.pqc_pk_data = base64.b64decode(pqc_pk_b64) if pqc_pk_b64 else None
        for attribute, path in (('pqc_sk_data', backup_pqc_sk), ('pqc_pk_data', backup_pqc_pk)):
            if getattr(self, attribute) is None and os.path.isfile(path):
                with open(path, 'rb') as stream:
                    setattr(self, attribute, stream.read())

        # Split-brain check: Mismatch between Vault and Local Backup
        if has_vault_keys and has_backup_keys:
            vault_msk = base64.b64decode(cpabe_msk_b64)
            with open(backup_msk, 'rb') as f:
                local_msk = f.read()
                
            if vault_msk != local_msk:
                err_msg = "CRITICAL ERROR: CP-ABE Key mismatch between Vault and local backup! System halted to prevent data loss. Please manually resolve this conflict."
                logger.critical(err_msg)
                raise CPABEError(err_msg)
                
            logger.info("CP-ABE keys fetched from Vault (matches local backup).")
            self.msk_data = vault_msk
            self.pk_data = base64.b64decode(cpabe_pk_b64)
            return

        # Vault has keys, but no backup exists
        if has_vault_keys:
            logger.info("CP-ABE keys fetched from Vault. Saving new local backup...")
            self.msk_data = base64.b64decode(cpabe_msk_b64)
            self.pk_data = base64.b64decode(cpabe_pk_b64)
            self._save_backup(backup_dir, backup_msk, backup_pk, backup_pqc_sk, backup_pqc_pk,
                              bool(self.pqc_sk_data and self.pqc_pk_data))
            return

        # Backup has keys, but Vault is empty
        if has_backup_keys:
            logger.warning("Vault has no CP-ABE keys. Restoring from local backup...")
            with open(backup_msk, 'rb') as f:
                self.msk_data = f.read()
            with open(backup_pk, 'rb') as f:
                self.pk_data = f.read()
            vault_service.put_secret('CPABE_MSK', base64.b64encode(self.msk_data).decode('utf-8'))
            vault_service.put_secret('CPABE_PK', base64.b64encode(self.pk_data).decode('utf-8'))
            
            if self.pqc_sk_data and self.pqc_pk_data:
                vault_service.put_secret('PQC_SK', base64.b64encode(self.pqc_sk_data).decode('utf-8'))
                vault_service.put_secret('PQC_PK', base64.b64encode(self.pqc_pk_data).decode('utf-8'))

            logger.info("CP-ABE keys restored to Vault from local backup.")
            return

        # 3. Generate new keys (first-time setup or overwrite requested due to missing keys)
        logger.info("Generating CP-ABE Master and Public keys...")
        
        # We must generate to disk first because C library expects path
        tmp_dir = tempfile.mkdtemp()
        
        if is_pqc_enabled:
            logger.info("PQC features enabled. Generating ML-DSA keys along with CP-ABE keys...")
            res = self._setup_pqc_func(tmp_dir.encode('utf-8'))
        else:
            res = self._lib.setup(tmp_dir.encode('utf-8'))
            
        if res != 0:
            err_msg = self._lib.getErrorMessage(res).decode('utf-8')
            raise CPABEError(f"Setup failed ({res}): {err_msg}")
            
        msk_path = os.path.join(tmp_dir, 'cpabe_msk.key')
        pk_path = os.path.join(tmp_dir, 'cpabe_pk.key')
        
        with open(msk_path, 'rb') as f:
            self.msk_data = f.read()
        with open(pk_path, 'rb') as f:
            self.pk_data = f.read()
            
        logger.info("Pushing CP-ABE keys to Vault...")
        vault_service.put_secret('CPABE_MSK', base64.b64encode(self.msk_data).decode('utf-8'))
        vault_service.put_secret('CPABE_PK', base64.b64encode(self.pk_data).decode('utf-8'))
        os.remove(msk_path)
        os.remove(pk_path)
        
        if is_pqc_enabled:
            pqc_sk_tmp_path = os.path.join(tmp_dir, 'pqc_sk.key')
            pqc_pk_tmp_path = os.path.join(tmp_dir, 'pqc_pk.key')
            with open(pqc_sk_tmp_path, 'rb') as f:
                self.pqc_sk_data = f.read()
            with open(pqc_pk_tmp_path, 'rb') as f:
                self.pqc_pk_data = f.read()
            vault_service.put_secret('PQC_SK', base64.b64encode(self.pqc_sk_data).decode('utf-8'))
            vault_service.put_secret('PQC_PK', base64.b64encode(self.pqc_pk_data).decode('utf-8'))
            os.remove(pqc_sk_tmp_path)
            os.remove(pqc_pk_tmp_path)
        
        # Save local backup
        self._save_backup(backup_dir, backup_msk, backup_pk, backup_pqc_sk, backup_pqc_pk, is_pqc_enabled)
        
        # Clean up temp files
        os.rmdir(tmp_dir)

    def _save_backup(self, backup_dir, backup_msk, backup_pk, backup_pqc_sk, backup_pqc_pk, is_pqc_enabled):
        """Save CP-ABE keys to local backup directory for disaster recovery."""
        try:
            os.makedirs(backup_dir, exist_ok=True)
            with open(backup_msk, 'wb') as f:
                f.write(self.msk_data)
            with open(backup_pk, 'wb') as f:
                f.write(self.pk_data)
                
            if is_pqc_enabled:
                with open(backup_pqc_sk, 'wb') as f:
                    f.write(self.pqc_sk_data)
                with open(backup_pqc_pk, 'wb') as f:
                    f.write(self.pqc_pk_data)
                    
            logger.info(f"CP-ABE keys backed up to {backup_dir}")
        except Exception as e:
            logger.warning(f"Could not save CP-ABE key backup: {e}")
                
    def expand_hierarchical_attributes(self, attrs: dict, scheme: str = 'ac17', *, configuration=None) -> List[str]:
        """
        Convert ABAC attributes to CP-ABE string attributes.
        AC17 expands hierarchies; TKN20 requires one value per normalized label.
        """
        if scheme == 'covercrypt':
            from .covercrypt_config import CoverCryptConfigurationError, build_covercrypt_configuration

            try:
                configuration = configuration or build_covercrypt_configuration()
                dimensions = {item['name']: set(item['attributes']) for item in configuration.dimensions}
                mapped = []
                missing = []
                for name, allowed_values in dimensions.items():
                    value = attrs.get(name)
                    if not isinstance(value, str) or not value:
                        missing.append(name)
                        continue
                    if value not in allowed_values:
                        raise CPABEAccessDenied(f"User attribute '{name}' has a value outside the CoverCrypt dimension.")
                    mapped.append(f"{name}::{value}")
                if missing:
                    raise CPABEAccessDenied("User is missing required CoverCrypt dimensions: " + ", ".join(missing))
                return sorted(mapped)
            except CoverCryptConfigurationError as exc:
                raise CPABEError(f"CoverCrypt dimensions are invalid: {exc}") from exc

        if scheme == 'tkn20':
            normalized = {}
            for key, value in attrs.items():
                values = value if isinstance(value, list) else [value]
                values = {str(v).lower() for v in values if v is not None and str(v)}
                label = key.lower()
                normalized[label] = normalized.get(label, set()) | values
                if len(normalized[label]) > 1:
                    raise CPABEError('TKN20 requires one value per attribute label.')
            # Do not expand role/clearance into duplicate labels in a TKN20 map.
            return sorted(f'{label}:{next(iter(values))}' for label, values in normalized.items() if values)

        result = []
        for key, value in attrs.items():
            if not value:
                continue
                
            if isinstance(value, list):
                for v in value:
                    result.append(f"{key}:{v}")
            else:
                result.append(f"{key}:{value}")
                
            # Hierarchical expansion for clearance_level
            if key == 'clearance_level':
                levels = ['public', 'confidential', 'secret', 'top_secret']
                try:
                    idx = levels.index(value)
                    # Add all levels below the current one
                    for i in range(idx):
                        result.append(f"clearance_level:{levels[i]}")
                except ValueError:
                    pass
                    
            # Hierarchical expansion for role
            if key == 'role':
                levels = ['intern', 'employee', 'manager', 'director']
                try:
                    idx = levels.index(value)
                    for i in range(idx):
                        result.append(f"role:{levels[i]}")
                except ValueError:
                    pass
                    
        return sorted(set(result))
        
    def generate_user_key(self, user_attributes: dict, output_path: str, scheme: str = None, *, route=None):
        """Generate a private key file for a user based on their attributes"""
        if scheme is None:
            scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')
            
        headers = {"X-Vault-Token": vault_service.get_token, "Content-Type": "application/json"} if self.use_vault_plugin else None
        if self.use_vault_plugin and scheme == 'covercrypt' and route is None:
            route = self._ensure_covercrypt_keyset(False, headers, allow_setup=False, return_route=True)
        attr_strings = self.expand_hierarchical_attributes(
            user_attributes, scheme=scheme, configuration=route.configuration if route else None,
        )
        attr_str = " ".join(attr_strings)
        logger.info(f"Generating Private Key (Scheme: {scheme}) with attributes: {attr_str}")
        
        if self.use_vault_plugin:
            payload = {"scheme": scheme, "attributes": attr_str}
            mount = route.mount if route else f'abe_{scheme}'
            endpoint = f"/v1/{mount}/genkey"
            try:
                resp = requests.put(f"{vault_service.get_addr}{endpoint}", headers=headers, json=payload, verify=self._vault_verify)
                resp.raise_for_status()
                sk_b64 = resp.json()["data"]["secret_key"]
                with open(output_path, 'wb') as f:
                    f.write(base64.b64decode(sk_b64))
                return
            except Exception as e:
                raise CPABEError(f"Vault ABE Plugin GenKey ({scheme}) failed: {e}")

        if not self._lib:
            raise CPABEError("Library not loaded")

        if scheme == 'covercrypt':
            self._ensure_covercrypt_native_keyset()
            msk = self.covercrypt_msk_data
            msk_ptr = ctypes.cast(ctypes.create_string_buffer(msk), ctypes.POINTER(ctypes.c_ubyte))
            sk_ptr = ctypes.POINTER(ctypes.c_ubyte)()
            sk_len = ctypes.c_size_t()
            result = self._genkey_scheme_func(
                msk_ptr, len(msk), attr_str.encode('utf-8'), ctypes.byref(sk_ptr), ctypes.byref(sk_len), 2,
            )
            if result != 0:
                detail = self._lib.getErrorMessage(result).decode('utf-8', errors='replace')
                raise CPABEError(f"CoverCrypt key generation failed ({result}): {detail}")
            raw_key = bytes(sk_ptr[:sk_len.value])
            if hasattr(self._lib, 'freeBuffer'):
                self._lib.freeBuffer(sk_ptr)
            with open(output_path, 'wb') as stream:
                stream.write(base64.b64encode(raw_key))
            return
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp_msk:
            tmp_msk.write(self.msk_data)
            tmp_msk_path = tmp_msk.name
            
        try:
            res = self._lib.generateSecretKey(
                tmp_msk_path.encode('utf-8'),
                attr_str.encode('utf-8'),
                output_path.encode('utf-8')
            )
            
            if res != 0:
                err_msg = self._lib.getErrorMessage(res).decode('utf-8')
                raise CPABEError(f"Key generation failed ({res}): {err_msg}")
        finally:
            os.remove(tmp_msk_path)
            
    def encrypt_file(self, input_path: str, output_path: str, policy: str):
        """Encrypt a file using CP-ABE policy"""
        if not self._lib:
            raise CPABEError("Library not loaded")
            
        logger.info(f"Encrypting file with policy: {policy}")
        if not self._encrypt_func:
            raise CPABEError("Encryption function not found in library")
            
        with tempfile.NamedTemporaryFile(delete=False) as tmp_pk:
            tmp_pk.write(self.pk_data)
            tmp_pk_path = tmp_pk.name
            
        try:
            result = self._encrypt_func(
                tmp_pk_path.encode('utf-8'),
                input_path.encode('utf-8'),
                policy.encode('utf-8'),
                output_path.encode('utf-8')
            )
            
            if result != 0:
                err_msg = self._lib.getErrorMessage(result).decode('utf-8')
                raise CPABEError(f"Encryption failed ({result}): {err_msg}")
        finally:
            os.remove(tmp_pk_path)
            
    def decrypt_file(self, private_key_path: str, input_path: str, output_path: str):
        """Decrypt a file using a user's private key"""
        if not self._lib:
            raise CPABEError("Library not loaded")
            
        logger.info(f"Decrypting file with key: {private_key_path}")
        if not self._decrypt_func:
            raise CPABEError("Decryption function not found in library")
            
        result = self._decrypt_func(
            private_key_path.encode('utf-8'),
            input_path.encode('utf-8'),
            output_path.encode('utf-8')
        )
        
        if result != 0:
            err_msg = self._lib.getErrorMessage(result).decode('utf-8')
            raise CPABEError(f"Decryption failed ({result}): {err_msg}")

    def get_version(self) -> str:
        """Get the library version"""
        if hasattr(self._lib, 'getVersion'):
            return self._lib.getVersion().decode('utf-8')
        return "Unknown"

    def _native_covercrypt_encrypt(self, plaintext: bytes, policy: str, signed: bool) -> bytes:
        self._ensure_covercrypt_native_keyset()
        function = self._encrypt_sign_scheme_func if signed else self._encrypt_scheme_func
        if not function:
            raise CPABEError("The native library lacks the requested scheme-aware CoverCrypt encryption API.")
        pk = self.covercrypt_pk_data
        pk_ptr = ctypes.cast(ctypes.create_string_buffer(pk), ctypes.POINTER(ctypes.c_ubyte))
        pt_ptr = ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_ubyte))
        ct_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        ct_len = ctypes.c_size_t()
        from .covercrypt_config import build_covercrypt_configuration
        configuration = build_covercrypt_configuration()
        with _COVERCRYPT_ENV_LOCK, tempfile.TemporaryDirectory(prefix="cpqa-covercrypt-op-") as temp_dir:
            config_path = os.path.join(temp_dir, "covercrypt.json")
            with open(config_path, "w", encoding="utf-8") as stream:
                stream.write(configuration.config_json)
            old_config, old_mode = os.environ.get("HCPABE_COVERCRYPT_CONFIG"), os.environ.get("HCPABE_COVERCRYPT_MODE")
            os.environ["HCPABE_COVERCRYPT_CONFIG"] = config_path
            os.environ["HCPABE_COVERCRYPT_MODE"] = "hybridized"
            try:
                if signed:
                    if not self.covercrypt_pqc_sk_data:
                        raise CPABEError("CoverCrypt ML-DSA signing key is unavailable.")
                    signing_key = base64.b64decode(self.covercrypt_pqc_sk_data)
                    sign_ptr = ctypes.cast(ctypes.create_string_buffer(signing_key), ctypes.POINTER(ctypes.c_ubyte))
                    result = function(pk_ptr, len(pk), sign_ptr, len(signing_key), pt_ptr, len(plaintext),
                                      policy.encode('utf-8'), ctypes.byref(ct_ptr), ctypes.byref(ct_len), 2)
                else:
                    result = function(pk_ptr, len(pk), pt_ptr, len(plaintext), policy.encode('utf-8'),
                                      ctypes.byref(ct_ptr), ctypes.byref(ct_len), 2)
            finally:
                if old_config is None:
                    os.environ.pop("HCPABE_COVERCRYPT_CONFIG", None)
                else:
                    os.environ["HCPABE_COVERCRYPT_CONFIG"] = old_config
                if old_mode is None:
                    os.environ.pop("HCPABE_COVERCRYPT_MODE", None)
                else:
                    os.environ["HCPABE_COVERCRYPT_MODE"] = old_mode
        if result != 0:
            detail = self._lib.getErrorMessage(result).decode('utf-8', errors='replace')
            raise CPABEError(f"Native CoverCrypt encryption failed ({result}): {detail}")
        ciphertext = bytes(ct_ptr[:ct_len.value])
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer(ct_ptr)
        return ciphertext

    def encrypt_version(self, plaintext: bytes, policy: str, scheme: str, pqc_signed: bool):
        """Return ciphertext and actual crypto metadata from the encryption boundary."""
        from .version_crypto import inspect_header, validate_metadata
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')
        if type(pqc_signed) is not bool:
            raise CPABEError('Signature selection must be a boolean.')
        if self.use_vault_plugin:
            from .version_crypto import metadata_from_plugin
            headers = {'X-Vault-Token': vault_service.get_token}
            mount = f'abe_{scheme}'
            if scheme == 'covercrypt':
                route = self._ensure_covercrypt_keyset(pqc_signed, headers, allow_setup=False, return_route=True)
                mount, authority = route.mount, route.authority
                public_key, verifier = authority.public_key, authority.verifier
            else:
                public_key = vault_service.get_secret(f'CPABE_PK_{scheme.upper()}')
                verifier = vault_service.get_secret(f'PQC_PK_{scheme.upper()}')
                authority = self._read_vault_authority(scheme, headers)
            if not public_key or authority is None or public_key_fingerprint(public_key) != authority.fingerprint:
                raise CPABEError('Encryption public key does not match the current Vault authority.')
            if pqc_signed and (not authority.pqc or not verifier or verifier != authority.verifier):
                raise CPABEError('The requested authority signature verification key is unavailable or inconsistent.')
            payload = {'scheme': scheme, 'plaintext': base64.b64encode(plaintext).decode('ascii'),
                       'policy': policy, 'public_key': public_key, 'sign': pqc_signed}
            response = requests.put(
                f'{vault_service.get_addr}/v1/{mount}/encrypt', headers=headers,
                json=payload, verify=self._vault_verify, timeout=120,
            )
            response.raise_for_status()
            result = response.json()['data']
            data = base64.b64decode(result['ciphertext'], validate=True)
            metadata = metadata_from_plugin(result, data, scheme=scheme, signed=pqc_signed,
                                             public_key=public_key, revision=authority.revision)
        else:
            operation = self.encrypt_buffer_and_sign if pqc_signed else self.encrypt_buffer
            data = operation(plaintext, policy, scheme=scheme)
            metadata = {'schema': 1, **inspect_header(data), 'pqc_signed': pqc_signed, 'backend': 'native'}
        header = inspect_header(data)
        if (metadata['scheme'] != scheme or metadata['pqc_signed'] != pqc_signed or
                metadata['backend'] != ('vault' if self.use_vault_plugin else 'native') or
                any(metadata[key] != header[key] for key in ('scheme', 'format'))):
            raise CPABEError('Encryption result does not match the requested crypto mode.')
        return data, metadata

    def verify_version_authority(self, metadata):
        """Bind new Vault version metadata before a cached user key can be used."""
        from .version_crypto import CryptoMetadataError, validate_metadata
        from .covercrypt_config import AUTHORITY_HISTORY_KEY
        metadata = validate_metadata(metadata)
        scheme = metadata['scheme']
        headers = {'X-Vault-Token': vault_service.get_token}
        if self.use_vault_plugin and scheme == 'covercrypt':
            try:
                state = self._covercrypt_authority_state()
                history = state.get(AUTHORITY_HISTORY_KEY, {})
                if not isinstance(history, dict):
                    raise CPABEError('CoverCrypt authority history is malformed.')
                if metadata['schema'] == 1:
                    if history or self._covercrypt_record_mount(state) != COVERCRYPT_VAULT_MOUNT:
                        raise CPABEError('Legacy CoverCrypt metadata has no authority identity.')
                    route = self._verify_covercrypt_record(state, headers)
                else:
                    identity = f"{metadata['keyset_id']}:{metadata['authority_revision']}"
                    route = self._verify_covercrypt_record(history.get(identity, state), headers)
                    if (route.authority.fingerprint != metadata['keyset_id'] or
                            route.authority.revision != metadata['authority_revision']):
                        raise CPABEError('The CoverCrypt authority identity differs.')
                if metadata['pqc_signed'] and not route.authority.verifier:
                    raise CPABEError('The CoverCrypt authority has no verification key.')
                return route
            except (CPABEError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, requests.RequestException) as exc:
                raise CryptoMetadataError('The recorded CoverCrypt authority is unavailable or inconsistent.') from exc
        if metadata['schema'] != 2:
            return
        if not self.use_vault_plugin:
            raise CryptoMetadataError('This version requires its recorded Vault backend.')
        authority = self._read_vault_authority(scheme, headers)
        if (authority is None or authority.fingerprint != metadata['keyset_id'] or
                authority.revision != metadata['authority_revision']):
            raise CryptoMetadataError('The recorded authority/revision is unavailable; historical-key recovery is required.')
        if metadata['pqc_signed']:
            name = f'PQC_PK_{scheme.upper()}'
            if not authority.verifier or vault_service.get_secret(name) != authority.verifier:
                raise CryptoMetadataError('The verification key for this authority is unavailable or inconsistent.')

    def encrypt_buffer(self, plaintext: bytes, policy: str, scheme: str = None) -> bytes:
        """Encrypt data buffer directly in memory"""
        if scheme is None:
            scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')
            
        if self.use_vault_plugin:
            return self.encrypt_version(plaintext, policy, scheme, False)[0]

        if scheme == 'covercrypt':
            return self._native_covercrypt_encrypt(plaintext, policy, signed=False)

        if not self._encrypt_buffer_func:
            raise CPABEError("Buffer encryption function not found in library")

        pk_json = base64.b64decode(self.pk_data)

        pk_ptr = ctypes.cast(ctypes.create_string_buffer(pk_json), ctypes.POINTER(ctypes.c_ubyte))
        pt_ptr = ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_ubyte))
        
        ct_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        ct_len = ctypes.c_size_t(0)

        result = self._encrypt_buffer_func(
            pk_ptr, len(pk_json),
            pt_ptr, len(plaintext),
            policy.encode('utf-8'),
            ctypes.byref(ct_ptr), ctypes.byref(ct_len)
        )

        if result != 0:
            err_msg = self._lib.getErrorMessage(result).decode('utf-8')
            raise CPABEError(f"Buffer encryption failed ({result}): {err_msg}")

        # Copy data out of C memory
        ciphertext = bytes(ct_ptr[:ct_len.value])
        
        # Free C memory
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer(ct_ptr)
            
        return ciphertext

    def decrypt_buffer(self, private_key_data: bytes, ciphertext: bytes, scheme: str = None, *, route=None) -> bytes:
        """Decrypt data buffer directly in memory"""
        if scheme is None:
            scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')
        from .version_crypto import inspect_header
        if inspect_header(ciphertext)['scheme'] != scheme:
            raise CPABEError("Ciphertext header scheme differs from the recorded scheme.")
            
        if self.use_vault_plugin:
            headers = {"X-Vault-Token": vault_service.get_token, "Content-Type": "application/json"}
            payload = {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "secret_key": base64.b64encode(private_key_data).decode('utf-8'),
            }
            if scheme == 'covercrypt' and route is None:
                route = self._ensure_covercrypt_keyset(False, headers, allow_setup=False, return_route=True)
            mount = route.mount if route else f'abe_{scheme}'
            try:
                resp = requests.put(f"{vault_service.get_addr}/v1/{mount}/decrypt", headers=headers, json=payload, verify=self._vault_verify)
                resp.raise_for_status()
                return base64.b64decode(resp.json()["data"]["plaintext"])
            except requests.HTTPError as e:
                if scheme == 'covercrypt' and e.response.status_code in (400, 403):
                    raise CPABEAccessDenied("CoverCrypt decryption was denied.") from e
                raise CPABEError(f"Vault ABE Plugin decrypt ({scheme}) failed: {e}") from e
            except Exception as e:
                raise CPABEError(f"Vault ABE Plugin decrypt ({scheme}) failed: {e}")

        if not self._decrypt_buffer_func:
            raise CPABEError("Buffer decryption function not found in library")

        sk_json = base64.b64decode(private_key_data)

        sk_ptr = ctypes.cast(ctypes.create_string_buffer(sk_json), ctypes.POINTER(ctypes.c_ubyte))
        ct_ptr = ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_ubyte))
        
        pt_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        pt_len = ctypes.c_size_t(0)

        result = self._decrypt_buffer_func(
            sk_ptr, len(sk_json),
            ct_ptr, len(ciphertext),
            ctypes.byref(pt_ptr), ctypes.byref(pt_len)
        )

        if result != 0:
            err_msg = self._lib.getErrorMessage(result).decode('utf-8')
            raise CPABEError(f"Buffer decryption failed ({result}): {err_msg}")

        # Copy data out of C memory
        plaintext = bytes(pt_ptr[:pt_len.value])
        
        # Free C memory
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer(pt_ptr)
            
        return plaintext

    def encrypt_buffer_and_sign(self, plaintext: bytes, policy: str, scheme: str = None) -> bytes:
        self._ensure_keys_exist()
        if scheme is None:
            scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')

        if scheme == 'covercrypt' and not bool(getattr(settings, 'ENABLE_PQC_FEATURES', False)):
            raise CPABEError("CoverCrypt PQC signing is disabled by deployment configuration.")
        
        if self.use_vault_plugin:
            return self.encrypt_version(plaintext, policy, scheme, True)[0]

        if scheme == 'covercrypt':
            return self._native_covercrypt_encrypt(plaintext, policy, signed=True)

        if not getattr(self, '_encrypt_buffer_sign_func', None):
            raise CPABEError("PQC encryptBuffer_and_sign function not found in DLL")

        pk_json = base64.b64decode(self.pk_data)
        if not getattr(self, 'pqc_sk_data', None):
            raise CPABEError('PQC signing keys are unavailable; existing ABE keys were preserved.')
        pqc_sk_json = base64.b64decode(self.pqc_sk_data)
        
        pk_ptr = ctypes.cast(ctypes.create_string_buffer(pk_json), ctypes.POINTER(ctypes.c_ubyte))
        pqc_sk_ptr = ctypes.cast(ctypes.create_string_buffer(pqc_sk_json), ctypes.POINTER(ctypes.c_ubyte))
        pt_ptr = ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_ubyte))
        
        ct_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        ct_len = ctypes.c_size_t(0)
        
        result = self._encrypt_buffer_sign_func(
            pk_ptr, len(pk_json),
            pqc_sk_ptr, len(pqc_sk_json),
            pt_ptr, len(plaintext),
            policy.encode('utf-8'),
            ctypes.byref(ct_ptr), ctypes.byref(ct_len)
        )

        if result != 0:
            err_msg = self._lib.getErrorMessage(result).decode('utf-8')
            raise CPABEError(f"Buffer PQC encryption failed ({result}): {err_msg}")

        ciphertext = bytes(ct_ptr[:ct_len.value])
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer(ct_ptr)
            
        return ciphertext

    def decrypt_buffer_and_verify(self, sk_data: bytes, ciphertext: bytes, scheme: str = None, *, route=None) -> bytes:
        if scheme is None:
            scheme = getattr(settings, 'CPABE_SCHEME', 'ac17')
        from .abe_schemes import validate_scheme
        scheme = validate_scheme(scheme, backend='vault' if self.use_vault_plugin else 'native')
        from .version_crypto import inspect_header
        if inspect_header(ciphertext)['scheme'] != scheme:
            raise CPABEError("Ciphertext header scheme differs from the recorded scheme.")
        
        if self.use_vault_plugin:
            headers = {"X-Vault-Token": vault_service.get_token, "Content-Type": "application/json"}
            if scheme == 'covercrypt' and route is None:
                route = self._ensure_covercrypt_keyset(True, headers, allow_setup=False, return_route=True)
            mount = route.mount if route else f'abe_{scheme}'
            pqc_pk_b64 = route.authority.verifier if route else vault_service.get_secret(f'PQC_PK_{scheme.upper()}')
            if not pqc_pk_b64:
                raise CPABEError('The verification key for this version is unavailable.')
            
            payload = {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "secret_key": base64.b64encode(sk_data).decode('utf-8'),
                "pqc_public_key": pqc_pk_b64,
            }
            try:
                resp = requests.put(f"{vault_service.get_addr}/v1/{mount}/decrypt", headers=headers, json=payload, verify=self._vault_verify)
                resp.raise_for_status()
                return base64.b64decode(resp.json()["data"]["plaintext"])
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 400 or e.response.status_code == 403:
                    if scheme == 'covercrypt':
                        raise CPABEAccessDenied("CoverCrypt decryption or signature verification was denied.") from e
                    raise CPABEError("Decryption failed or signature invalid (unauthorized)")
                raise CPABEError(f"Vault ABE Plugin PQC decrypt ({scheme}) failed: {e}")
            except Exception as e:
                raise CPABEError(f"Vault ABE Plugin PQC decrypt ({scheme}) failed: {e}")

        if not getattr(self, '_decrypt_buffer_verify_func', None):
            raise CPABEError("PQC decryptBuffer_and_verify function not found in DLL")

        sk_json = base64.b64decode(sk_data)
        if scheme == 'covercrypt':
            self._ensure_covercrypt_native_keyset()
            verifier_data = self.covercrypt_pqc_pk_data
        else:
            verifier_data = getattr(self, 'pqc_pk_data', None)
        if not verifier_data:
            raise CPABEError('The verification key for this version is unavailable.')
        pqc_pk_json = base64.b64decode(verifier_data)

        sk_ptr = ctypes.cast(ctypes.create_string_buffer(sk_json), ctypes.POINTER(ctypes.c_ubyte))
        pqc_pk_ptr = ctypes.cast(ctypes.create_string_buffer(pqc_pk_json), ctypes.POINTER(ctypes.c_ubyte))
        ct_ptr = ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_ubyte))
        
        pt_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        pt_len = ctypes.c_size_t(0)
        
        result = self._decrypt_buffer_verify_func(
            sk_ptr, len(sk_json),
            pqc_pk_ptr, len(pqc_pk_json),
            ct_ptr, len(ciphertext),
            ctypes.byref(pt_ptr), ctypes.byref(pt_len)
        )

        if result != 0:
            err_msg = self._lib.getErrorMessage(result).decode('utf-8')
            raise CPABEError(f"Buffer PQC decryption failed ({result}): {err_msg}")

        plaintext = bytes(pt_ptr[:pt_len.value])
        if hasattr(self._lib, 'freeBuffer'):
            self._lib.freeBuffer(pt_ptr)
            
        return plaintext

# Lazy singleton – CPABEService is only created the first time it is accessed,
# giving Vault enough time to start up before any connection is attempted.
class _LazyCPABEService:
    """Proxy that delays CPABEService() creation until first attribute access."""
    def __init__(self):
        self._instance = None

    def _get_instance(self):
        if self._instance is None:
            self._instance = CPABEService()
        return self._instance

    def __getattr__(self, name):
        return getattr(self._get_instance(), name)

cpabe_service = _LazyCPABEService()
