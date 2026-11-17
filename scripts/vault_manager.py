import os
import json
import time
import urllib.request
import urllib.error
import argparse
import ssl
import tempfile

# Install hvac if running outside container but we assume it's running inside `web` container
try:
    import hvac
except ImportError:
    print("hvac not installed. Run 'pip install hvac'")
    exit(1)

# Suppress InsecureRequestWarning for self-signed Vault certs

VAULT_ADDR = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
VAULT_SECRET_PATH = os.environ.get('VAULT_SECRET_PATH', 'secret/data/crypto_access')
KEYS_DIR = os.environ.get('KEYS_DIR', '/app/config/keys')
UNSEAL_KEYS_FILE = os.path.join(KEYS_DIR, 'vault_unseal_keys.json')
TOKEN_FILE = os.path.join(KEYS_DIR, 'vault_token.txt')
VAULT_INIT_TIMEOUT = 180
VAULT_BOOTSTRAP_BLOCKED = 78


class VaultBootstrapBlocked(RuntimeError):
    """The operator must inspect bootstrap state before another attempt."""


def write_bootstrap_file(path, content):
    """Keep a complete credential file and restrict access to the current user."""
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=KEYS_DIR, delete=False) as output:
            temporary_path = output.name
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)


def initialize_new_vault(verify, shares, threshold):
    # Test the destination before requesting credentials that Vault returns only once.
    try:
        os.makedirs(KEYS_DIR, exist_ok=True)
        with tempfile.TemporaryFile(dir=KEYS_DIR):
            pass
    except OSError:
        raise VaultBootstrapBlocked("Vault bootstrap requires a writable keys directory.") from None
    initializer = hvac.Client(url=VAULT_ADDR, verify=verify, timeout=VAULT_INIT_TIMEOUT)
    try:
        result = initializer.sys.initialize(secret_shares=shares, secret_threshold=threshold)
        keys = result['keys']
        root_token = result['root_token']
        if not keys or not root_token:
            raise ValueError()
    except Exception:
        raise VaultBootstrapBlocked(
            "Vault initialization did not return credentials. Check its initialization state and local "
            "credential files before retrying. A committed initialization cannot issue the same shares again."
        ) from None
    try:
        write_bootstrap_file(UNSEAL_KEYS_FILE, json.dumps({'keys': keys}))
        write_bootstrap_file(TOKEN_FILE, root_token)
    except OSError:
        raise VaultBootstrapBlocked(
            "Vault initialized, but one or more local credential files could not be saved. "
            "Check the keys directory and use the operator recovery procedure."
        ) from None
    return keys, root_token


def unseal_with_keys(client, keys):
    """Submit stored shares without mistaking partial progress for an unseal."""
    for key in dict.fromkeys(keys):
        if not client.sys.is_sealed():
            break
        result = client.sys.submit_unseal_key(key)
        if not result.get('sealed', True):
            break

    status = client.sys.read_seal_status()
    if status.get('sealed', True):
        raise RuntimeError(
            f"Vault remains sealed: {status.get('progress', 0)}/{status.get('t', '?')} "
            "unseal shares submitted. Restore the original unseal-key backup or "
            "complete unsealing in the Vault UI. Do not reset Vault storage."
        )


def wait_for_active_vault(client, attempts=30):
    """Wait for authenticated operations after unseal and Raft leader election."""
    for attempt in range(attempts):
        if client.sys.is_sealed():
            raise RuntimeError("Vault is sealed; engine setup cannot continue.")
        try:
            client.sys.list_mounted_secrets_engines()
            return
        except (hvac.exceptions.VaultDown, hvac.exceptions.InternalServerError):
            if attempt + 1 < attempts:
                time.sleep(1)
    raise RuntimeError("Vault is unsealed but its active node did not become ready in time.")

def get_ca_cert_path():
    ca_cert_path = os.environ.get('VAULT_CACERT', '/certs/CyberFortress-RootCA.crt')
    if os.path.exists(ca_cert_path):
        return ca_cert_path
    # Fallback to local path when running outside container (e.g., via start.py on Windows)
    local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'certs', 'CyberFortress-RootCA.crt')
    if os.path.exists(local_path):
        return local_path
    return None

def wait_for_vault():
    print(f"Waiting for Vault at {VAULT_ADDR}...")
    
    ctx = ssl.create_default_context()
    ca_cert_path = get_ca_cert_path()
    if VAULT_ADDR.startswith('https') and ca_cert_path:
        ctx.load_verify_locations(cafile=ca_cert_path)

    for _ in range(30):
        try:
            req = urllib.request.Request(f"{VAULT_ADDR}/v1/sys/health")
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
                    if response.status in [200, 429, 472, 473, 501, 503]:
                        return True
            except urllib.error.HTTPError as e:
                # Vault returns 501/503 when uninitialized/sealed, which is fine!
                return True
        except Exception:
            pass
        time.sleep(1)
    print("Vault did not become reachable in time.")
    return False

def ensure_kv_engine(client):
    """Ensure the KV v2 secrets engine is enabled at 'secret/'."""
    try:
        # Check existing mounts first to prevent Vault from logging 'path already in use' errors
        mounts = client.sys.list_mounted_secrets_engines()
        if 'secret/' in mounts:
            # Optionally check if it's kv v2, but usually it is if it exists
            return
            
        client.sys.enable_secrets_engine(
            backend_type='kv',
            path='secret',
            options={'version': '2'}
        )
        print("KV v2 secrets engine enabled at 'secret/'.")
    except Exception as e:
        if "local node not active" in str(e):
            # Retry for Raft leader election
            for attempt in range(10):
                time.sleep(2)
                try:
                    mounts = client.sys.list_mounted_secrets_engines()
                    if 'secret/' in mounts:
                        return
                    client.sys.enable_secrets_engine(
                        backend_type='kv',
                        path='secret',
                        options={'version': '2'}
                    )
                    print("KV v2 secrets engine enabled at 'secret/'.")
                    return
                except Exception as retry_e:
                    if "local node not active" in str(retry_e):
                        print(f"Raft leader not ready yet (attempt {attempt+1}/10), waiting...")
                    else:
                        raise RuntimeError("Failed to enable KV v2 engine") from retry_e
        else:
            raise RuntimeError("Failed to enable KV v2 engine") from e
        raise RuntimeError("KV v2 engine was not ready after retries") from e


def register_abe_plugin(client):
    use_plugin = os.environ.get('USE_VAULT_ABE_PLUGIN', 'False').lower() in ('true', '1', 't')
    if not use_plugin:
        return
        
    plugin_path = '/vault/plugins/vault-plugin-abe'
    if not os.path.exists(plugin_path):
        raise RuntimeError(f"Plugin binary not found at {plugin_path}. Please build it first.")
        
    import hashlib
    with open(plugin_path, "rb") as f:
        plugin_hash = hashlib.sha256(f.read()).hexdigest()
        
    print(f"Registering vault-plugin-abe (sha256: {plugin_hash})...")
    try:
        import requests
        headers = {"X-Vault-Token": client.token}
        payload = {
            "sha256": plugin_hash,
            "command": "vault-plugin-abe"
        }
        url = f"{client.url}/v1/sys/plugins/catalog/secret/vault-plugin-abe"
        response = requests.put(url, headers=headers, json=payload, verify=get_ca_cert_path() or True, timeout=30)
        response.raise_for_status()
    except Exception as e:
        if "already registered" not in str(e):
            print(f"Failed to register plugin: {repr(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Details: {e.response.text}")
            raise RuntimeError("Failed to register Vault ABE plugin") from e
            
    try:
        mounts = client.sys.list_mounted_secrets_engines()
        
        # Mount AC17
        if 'abe_ac17/' not in mounts:
            client.sys.enable_secrets_engine(
                backend_type='vault-plugin-abe',
                path='abe_ac17',
                description='Hybrid PQC CP-ABE Engine (AC17)'
            )
            print("ABE Secrets engine successfully enabled at 'abe_ac17/'.")
        else:
            print("ABE engine already enabled at 'abe_ac17/'.")
            
        # Mount TKN20
        if 'abe_tkn20/' not in mounts:
            client.sys.enable_secrets_engine(
                backend_type='vault-plugin-abe',
                path='abe_tkn20',
                description='Hybrid PQC CP-ABE Engine (TKN20)'
            )
            print("ABE Secrets engine successfully enabled at 'abe_tkn20/'.")
        else:
            print("ABE engine already enabled at 'abe_tkn20/'.")

        # Keep the existing AC17/TKN20 mounts and their data untouched. The
        # application initializes CoverCrypt only after its database schema is
        # available, using the guarded setup path in CPABEService.
        covercrypt_mount_created = False
        if 'abe_covercrypt/' not in mounts:
            client.sys.enable_secrets_engine(
                backend_type='vault-plugin-abe',
                path='abe_covercrypt',
                description='Hybrid PQC CP-ABE Engine (CoverCrypt)',
            )
            covercrypt_mount_created = True
            print("ABE Secrets engine successfully enabled at 'abe_covercrypt/'.")
        else:
            print("ABE engine already enabled at 'abe_covercrypt/'.")

        # Only a mount created by this provisioning run is eligible for the
        # application's first setup. If an operator pre-created the mount, the
        # app cannot inspect plugin-internal authority state and must not guess.
        if covercrypt_mount_created:
            secret_path = VAULT_SECRET_PATH.replace('secret/data/', '').strip('/')
            try:
                record = client.secrets.kv.v2.read_secret_version(
                    path=secret_path, raise_on_deleted_version=False,
                )['data']
                current, version = record['data'], record['metadata']['version']
            except hvac.exceptions.InvalidPath:
                current, version = {}, 0
            if not isinstance(current, dict):
                raise RuntimeError("CoverCrypt cannot record a first-setup guard over unavailable Vault KV metadata.")
            if any(current.get(key) is not None for key in (
                'COVERCRYPT_KEYSET_MANIFEST_primary', 'COVERCRYPT_AUTHORITY_HISTORY_v1',
                'COVERCRYPT_KEYSET_INITIALIZING_primary',
            )):
                print("CoverCrypt keyset metadata already exists. No new first-setup guard was recorded.")
                return
            current['COVERCRYPT_MOUNT_CREATED'] = 'abe_covercrypt'
            client.secrets.kv.v2.create_or_update_secret(path=secret_path, secret=current, cas=version)
            print("Recorded the new CoverCrypt mount for guarded first-time setup.")
            
    except Exception as e:
        raise RuntimeError("Failed to enable ABE secrets engines") from e

def init_and_unseal():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prod', action='store_true', help='Enable production mode (no auto-unseal)')
    args = parser.parse_args()
    is_prod = args.prod

    if not wait_for_vault():
        raise RuntimeError("Vault did not become reachable in time.")

    verify = (get_ca_cert_path() or True) if VAULT_ADDR.startswith('https') else True
    client = hvac.Client(url=VAULT_ADDR, verify=verify)
    
    try:
        is_initialized = client.sys.is_initialized()
    except Exception as e:
        raise RuntimeError("Failed to check Vault initialization status") from e

    if not is_initialized:
        shares = 5 if is_prod else 1
        threshold = 3 if is_prod else 1

        print("Vault is not initialized. Initializing...")
        keys, root_token = initialize_new_vault(verify, shares, threshold)
            
        print(f"Vault initialized. Unseal keys saved to {UNSEAL_KEYS_FILE}")
        
        # Re-authenticate with root token
        client.token = root_token
        
        # Unseal for initial setup
        print("Unsealing Vault for initial setup...")
        unseal_with_keys(client, keys)
        
        # Wait for Raft leader election
        print("Waiting for Raft leader election...")
        time.sleep(2)
        
        print("Vault setup complete.")

        if is_prod:
            print("\n\033[1;93m=======================================================")
            print("🚨 [WARNING] PRODUCTION ENVIRONMENT DETECTED 🚨")
            print(f"Vault initialized with {shares} keys, {threshold} required to unseal.")
            print(f"Keys are saved in {UNSEAL_KEYS_FILE}.")
            print("Please backup these keys securely and DELETE THE FILE!")
            print("Auto-unseal will be DISABLED for all subsequent restarts.")
            print("=======================================================\033[0m\n")

    else:
        print("Vault is already initialized.")
        is_sealed = client.sys.is_sealed()
        if is_sealed:
            if is_prod:
                print("\n\033[1;93m=======================================================")
                print("🚨 [WARNING] PRODUCTION ENVIRONMENT DETECTED 🚨")
                print("Vault is SEALED. Auto-unseal is DISABLED for security.")
                print(f"Please log in to Vault UI at {VAULT_ADDR} and unseal manually.")
                print("=======================================================\033[0m\n")
                raise RuntimeError("Production Vault requires manual unsealing.")

            if not os.path.exists(UNSEAL_KEYS_FILE):
                raise VaultBootstrapBlocked(
                    f"Vault is initialized and sealed, but {UNSEAL_KEYS_FILE} is missing. "
                    "Restore the original shares for this Vault. For a disposable local Vault with no shares, "
                    "recreate its Vault data volume after checking that no data needs to be retained."
                )
            
            try:
                with open(UNSEAL_KEYS_FILE, 'r', encoding='utf-8') as f:
                    keys = json.load(f)['keys']
                if not isinstance(keys, list) or not keys or not all(isinstance(key, str) and key for key in keys):
                    raise ValueError()
            except (OSError, ValueError, KeyError, TypeError):
                raise VaultBootstrapBlocked("The saved Vault unseal file is unreadable or contains no valid shares.") from None
            print("Vault is sealed. Attempting auto-unseal...")
            unseal_with_keys(client, keys)
            print("Vault unsealed successfully.")
        else:
            print("Vault is already unsealed.")
            
    # Try to authenticate with root token if available
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            client.token = f.read().strip()

        wait_for_active_vault(client)
        
        # Always ensure KV v2 engine is enabled (idempotent)
        ensure_kv_engine(client)
        
        # Register ABE plugin if configured
        register_abe_plugin(client)
    else:
        raise VaultBootstrapBlocked("No saved Vault token found; engine setup cannot continue.")

if __name__ == '__main__':
    try:
        init_and_unseal()
    except VaultBootstrapBlocked as exc:
        print(f"Vault bootstrap blocked: {exc}")
        raise SystemExit(VAULT_BOOTSTRAP_BLOCKED)
    except Exception as exc:
        print(f"Vault setup failed: {exc}")
        raise SystemExit(1)
