# CoverCrypt Configuration Lifecycle

[Tiếng Việt](../vi/covercrypt-configuration-lifecycle.md) · [Integration plan](covercrypt-integration-plan.md) · [Vault contract](covercrypt-vault-contract.md)

CoverCrypt setup receives one `config_json` object shaped as `{"dimensions":[...]}`. CPQA derives this JSON from active enum `AttributeDefinition` rows seeded during `start.py initdata`. No CoverCrypt dimensions, values, mode, keyset ID, or Vault mount are duplicated in `.env`, `settings/base.py`, or System Settings.

The upstream Vault CLI form `config_json=@path/to/file.json` reads the file on the CLI client, then sends the JSON text in the request. The Vault server does not read the file or a mounted configuration. CPQA setup must send the canonical JSON generated from its schema service.

Active enum `AttributeDefinition` rows form dimensions; free-form definitions such as `location` are excluded. CPQA also derives a bounded `user_type` dimension from active `UserType` codes plus the legacy `UserProfile.USER_TYPE_CHOICES`, because seeded ABAC policies refer to profile-derived `user_type`. Every dimension uses `hierarchical: false`; the current schema has no hierarchy field. `UserAttribute` is unique per `(user, attribute)`, so the mapper requires exactly one valid value for every configured dimension before a CoverCrypt user key can be requested. Invalid or missing values fail closed.

Seeded `AccessPolicy` records remain CPQA authorization and policy inputs. They are not part of authority setup JSON: setup config describes the attribute universe, while the policy compiler translates policy expressions to CoverCrypt grammar. Policy CRUD still validates through the existing serializer; AI output is only a suggestion and uses the same compiler for validation.

The compiler supports string equality, membership in a non-empty literal list/tuple/set, `and`, `or`, and parentheses. It checks every dimension and value against the same validated setup configuration. It rejects `!=` and `not in`: CPQA's evaluator can treat a missing attribute as unequal, while CoverCrypt keys require a positive attribute to satisfy the complemented policy. It also rejects ordering comparisons, chained comparisons, unary negation, non-string literals, and unconfigured attributes.

## Document bypass and strict mode

For a permitted non-strict administrator/owner document bypass,
`services/covercrypt_policy.py` parses the version's policy as a bounded positive
Boolean expression and chooses a consistent allowed value per dimension
satisfying the complete expression. Unconstrained dimensions use valid current
values or deterministic configured values. This ephemeral key assignment does
not modify stored attributes or policies. Contradictory, unconfigured, malformed
and excessive expressions fail closed. The helper grants no application rights.

Bypass keys use the separate `covercrypt_bypass_v1` namespace with user,
assignment, authority fingerprint and backend. With `SUPER_ADMIN_REQUIRE_POLICY`
enabled, privileged administrators pass document authorization and use real
attributes in the strict namespace, including when they own the file. Ordinary
users do not receive a satisfying assignment unless an existing owner bypass
explicitly applies.

## Privileged discovery

After `start.py initdata`, a super administrator can inspect the generated setup document through `GET /api/admin/covercrypt/configuration/`. The endpoint requires authentication and `IsSuperAdmin`; it is the supported API to review the generated JSON. Clients do not query the database directly.

The same validated service is available to an operator through:

```text
python manage.py covercrypt_config
```

It prints canonical setup JSON and its fingerprint. It performs no plugin setup and no Vault write.

## Fingerprint and keyset manifest

CPQA fingerprints canonical setup JSON together with the source `AttributeDefinition` versions. The fingerprint changes when the generated dimensions or source versions change.

The operator checks the recorded keyset or reconciles matching public metadata:

```text
python manage.py covercrypt_config --check-vault --keyset-id primary --vault-mount abe_covercrypt
python manage.py covercrypt_config --reconcile-vault --keyset-id primary --vault-mount abe_covercrypt
```

On a fresh CoverCrypt deployment, `start.py initdata` initializes the authority
after seeding the dimensions. To initialize an already seeded environment, run
`python manage.py covercrypt_config --initialize-vault --keyset-id primary --vault-mount abe_covercrypt`
from the web container. This can take several minutes on Raft. Upload requires a
ready authority. For an interrupted setup, reconcile the existing authority
first. If it is unavailable, the initialization guard remains in place.

The non-secret manifest is stored under `COVERCRYPT_KEYSET_MANIFEST_<keyset-id>` in the configured Vault KV path. It binds one authority to its fingerprint, source definition versions, and mount. A mismatch fails closed; it never calls `setup` or overwrites the authority.

Backups retain the Vault data path, mount, keyset ID, manifest, and source schema. Recovery restores the matching authority and manifest, then runs `--check-vault`. MSKs are never exported to Django or backup metadata.

## Rotate while retaining historical reads

The initial mount is `abe_covercrypt/` and `VAULT_SECRET_PATH` defaults to
`secret/data/crypto_access`. The active mount comes from the primary manifest.
Before changing the attribute catalog, run `--check-vault --keyset-id primary`
and record the active public-key fingerprint. Back up Vault Raft data, the KV
registry and the corresponding unseal material. Plan a write maintenance window
if you are changing the catalog. A schema mismatch blocks new encryption until
promotion.

1. Choose an unused mount such as `abe_covercrypt_20261115`. Generate the
   prospective configuration with `python manage.py covercrypt_config` and save
   only its `configuration.config` object to `covercrypt.json`.
2. With the operator Vault identity and contract-v1 plugin, provision the new
   mount separately. Use the signing state required for new files.

   ```sh
   vault secrets enable -path=abe_covercrypt_20261115 vault-plugin-abe
   vault write abe_covercrypt_20261115/setup scheme=covercrypt mode=hybridized \
     config_json=@covercrypt.json pqc=true create_only=true public_key_format=reference
   ```

3. Give the application identity access to `authority`, `encrypt`, `genkey`
   and `decrypt` on the candidate. Retain `authority`, `genkey` and `decrypt`
   on each historical mount. Run the following with an identity authorized to
   write the configured KV record.

   ```sh
   python manage.py covercrypt_config --rotate-vault --keyset-id primary \
     --vault-mount abe_covercrypt_20261115 --expected-fingerprint OLD_FINGERPRINT
   python manage.py covercrypt_config --check-vault --keyset-id primary
   ```

4. Verify a new upload and download, a historical download, and a denied read
   with a user lacking the required attributes. Retain access to the exact
   authority and its verifier for each referenced version.

Promotion atomically updates the primary record and archives its public metadata
under `COVERCRYPT_AUTHORITY_HISTORY_v1`, indexed by fingerprint and revision.
CPQA binds ciphertext to its retained mount for key generation and decryption.
Use separate mounts for rotation. In-place `setup` or `add_dimension` changes
the recorded identity. Recover a missing mount from a matching Vault backup.
After rotation, CoverCrypt versions without an authority identity require
operator recovery. Users still need effective attributes accepted by the
historical dimensions. See [the Vault contract guide](covercrypt-vault-contract.md).

## Restore a file version

Choose **Restore** in file version history, or send
`POST /api/storage/files/<id>/restore_version/` with `{"version_number": 1}`.
An owner or administrator with document update permission must also pass the
applicable read and decryption checks. Restore requires an older version with the
same policy, scheme and backend as the current version. If the current version
is signed, the source must be signed. Across CoverCrypt authorities, dimension
names must match and historical value sets must be subsets of the current
sets. After decryption and malware scanning, CPQA writes the verified original
bytes as a new version with the source crypto metadata and signatures.
