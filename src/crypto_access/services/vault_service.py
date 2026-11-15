import os
import hvac
import logging

logger = logging.getLogger(__name__)

class VaultService:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(VaultService, cls).__new__(cls)
            cls._instance._init()
        return cls._instance
    
    def _init(self):
        self.vault_addr = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
        self.secret_path = os.environ.get('VAULT_SECRET_PATH', 'secret/data/crypto_access')
        
        # Try to read token from file first (written by auto-unseal script)
        keys_dir = os.environ.get('KEYS_DIR', '/app/config/keys')
        token_file = os.path.join(keys_dir, 'vault_token.txt')
        if os.path.exists(token_file):
            with open(token_file, 'r') as f:
                self.vault_token = f.read().strip()
        else:
            self.vault_token = os.environ.get('VAULT_TOKEN', '')
            if not self.vault_token:
                logger.warning("VAULT_TOKEN is not set and no token file found. Vault operations will fail.")

        
        # Only initialize client if addr is provided and not empty
        if self.vault_addr:
            ca_cert_path = os.environ.get('VAULT_CACERT', '/certs/CyberFortress-RootCA.crt')
            if self.vault_addr.startswith('https') and os.path.exists(ca_cert_path):
                self.client = hvac.Client(url=self.vault_addr, token=self.vault_token, verify=ca_cert_path)
            else:
                self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)
        else:
            self.client = None
            
        self._cache = {}

    def is_authenticated(self):
        if not self.client:
            return False
        try:
            return self.client.is_authenticated()
        except Exception as e:
            logger.error(f"Failed to check Vault authentication: {e}")
            return False

    def get_secret(self, key_name, default=None):
        """Retrieve a secret from Vault. Uses simple memory cache."""
        if key_name.startswith(('COVERCRYPT_', 'CPABE_PK_COVERCRYPT', 'CPABE_MSK_COVERCRYPT',
                                'PQC_PK_COVERCRYPT', 'PQC_SK_COVERCRYPT')):
            return self.get_secrets([key_name]).get(key_name, default)
        if key_name in self._cache:
            return self._cache[key_name]
            
        if not self.is_authenticated():
            logger.warning("Vault client is not authenticated or unavailable.")
            return default
            
        try:
            read_response = self.client.secrets.kv.v2.read_secret_version(path=self.secret_path.replace('secret/data/', ''))
            secret_data = read_response['data']['data']
            
            # Cache all fetched secrets from this path
            for k, v in secret_data.items():
                self._cache[k] = v
                
            return self._cache.get(key_name, default)
        except hvac.exceptions.InvalidPath:
            logger.warning(f"Secret path {self.secret_path} not found in Vault.")
            return default
        except Exception as e:
            logger.error(f"Error reading from Vault: {e}")
            return default

    def put_secret(self, key_name, value):
        """Merge one value using bounded KV v2 compare-and-set retries."""
        return self.put_secrets({key_name: value})

    def _read_record(self):
        """Read one consistent revision. Deleted/destroyed records are not empty records."""
        path = self.secret_path.replace('secret/data/', '')
        try:
            record = self.client.secrets.kv.v2.read_secret_version(path=path, raise_on_deleted_version=False)
        except hvac.exceptions.InvalidPath:
            # Distinguish a missing path from an existing record whose latest
            # version cannot be read. Never resurrect deleted key material.
            try:
                self.client.secrets.kv.v2.read_secret_metadata(path=path)
            except hvac.exceptions.InvalidPath:
                return {}, 0
            raise RuntimeError('Vault record exists but its data is unavailable') from None
        data = record['data']['data']
        version = record['data']['metadata']['version']
        if not isinstance(data, dict) or type(version) is not int or version < 1:
            raise RuntimeError('Vault record is deleted, destroyed or malformed')
        return dict(data), version

    def get_secrets(self, key_names):
        """Fresh security-critical snapshot; outages must not look like missing keys."""
        if not self.is_authenticated():
            raise RuntimeError('Vault authentication is required to read keyset state')
        data, _ = self._read_record()
        return {key: data[key] for key in key_names if key in data}

    def claim_secret(self, key_name, value):
        """Acquire a durable one-shot initialization guard; no lease or automatic expiry."""
        return self._merge_secrets({key_name: value}, absent_key=key_name)

    def put_secrets(self, values):
        """Commit related metadata fields together in a single KV revision."""
        return self._merge_secrets(values)

    def compare_and_put_secrets(self, expected, values):
        """Replace related authority metadata only if its source snapshot still matches."""
        return self._merge_secrets(values, expected=expected)

    def _merge_secrets(self, values, *, absent_key=None, expected=None):
        if not self.is_authenticated():
            logger.warning("Vault client is not authenticated. Cannot write secret.")
            return False
        try:
            path = self.secret_path.replace('secret/data/', '')
            for _ in range(8):
                current_data, version = self._read_record()
                if absent_key is not None and current_data.get(absent_key) is not None:
                    return False
                if expected is not None and any(current_data.get(key) != value for key, value in expected.items()):
                    return False
                current_data.update(values)
                try:
                    self.client.secrets.kv.v2.create_or_update_secret(path=path, secret=current_data, cas=version)
                except hvac.exceptions.InvalidRequest as exc:
                    if 'check-and-set parameter did not match' not in str(exc):
                        raise
                    continue
                self._cache.clear()
                return True
            logger.error('Vault KV update exhausted CAS conflict retries')
            return False
        except Exception as e:
            # Never log request values or exception representations containing secrets.
            logger.error("Vault KV update failed (%s)", type(e).__name__)
            return False

    @property
    def get_token(self):
        return self.vault_token

    @property
    def get_addr(self):
        return self.vault_addr

vault_service = VaultService()
