# Vault runtime identity for CPQA production

Production Django reads its token from `/run/cpqa-vault/token`. Compose mounts this directory read-only from `VAULT_RUNTIME_TOKEN_DIR`. The token requires the sole policy `cpqa-runtime` and a remaining TTL. Use HTTPS with a valid CA. Keep operator tokens and unseal shares outside Django's reach.

## Prepare and cut over

1. Rehearse on staging. Back up Raft, the database and object storage at a coordinated recovery point. Retain the plugin build and manifests required for historical reads. Restore on an isolated network, verify a signed historical read and a denied request, and record recovery time.
2. Initialize or unseal Vault and register the plugin with an operator identity. For an upgrade, retain authorities, public metadata and the field master key. Inventory versions with `backend=native` before retiring that read path. For a fresh deployment, provision the authorities and operator record using the CoverCrypt guide before starting Django. Prepare the organization's attribute catalog, run migrations and provision administrators using the organization's account process.
3. Run `scripts/provision_vault_runtime.py --source-path crypto_access --token-out <runtime-dir>/token` in an operator environment with `hvac`, `VAULT_ADDR`, `VAULT_CACERT` and an operator `VAULT_TOKEN`. Create the directory first and protect its filesystem permissions. Provisioning copies the field master key and approved public records to `secret/data/cpqa-runtime`. It grants access to active and historical mounts from the manifests. Use `--mount` to include additional approved mounts.
4. After verifying an upstream image with `decrypt_with_attributes`, set `VAULT_ABE_INTERNAL_DECRYPT=True`. A deliberate transition with the older plugin requires this setting to stay `False` and requires `--allow-exported-user-keys` during provisioning. After rollout, provision again with the default policy to remove the old `genkey` and `decrypt` grants. Policy changes affect tokens that share the policy. Coordinate the cutover accordingly.
5. Configure `REDIS_PASSWORD` and the service CA. Run `python start.py --prod up`. The command checks the runtime identity and metadata. Run init, unseal and other operator operations through the administrative channel. Verify signed download/preview, historical reads after rotation and ACL denials for setup, dimension updates, operator KV reads and user-key export.
6. Verify service with the new identity before retiring bootstrap material. Runtime tokens are orphan tokens with an initial TTL of eight hours and an explicit maximum TTL of 24 hours. Renew the token where appropriate or provision a replacement and reload Django before expiry. Revoke the former token after verifying workers use the replacement.

## Audit and recovery

Access Vault administration through loopback or a restricted management network. An operator can enable file audit on the `/vault/audit` volume with `vault audit enable file file_path=/vault/audit/audit.json`. Check permissions, capacity, retention and read access first. Confirm audit and application logs omit raw keys, plaintext and tokens. Store snapshots, tokens and unseal shares separately.

Refresh the runtime record from its verified operator source when the active manifest or history changes. Retain access to historical mounts while versions reference them. Roll back with a validated compatible image and metadata. Any regrant of user-key export is an explicit operational decision.
