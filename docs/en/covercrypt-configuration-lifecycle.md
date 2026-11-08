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

When provisioning is implemented, the operator supplies the approved keyset ID and mount explicitly:

```text
python manage.py covercrypt_config --write-manifest --keyset-id <keyset-id> --vault-mount <mount>
python manage.py covercrypt_config --check-vault --keyset-id <keyset-id> --vault-mount <mount>
```

The non-secret manifest is stored under `COVERCRYPT_KEYSET_MANIFEST_<keyset-id>` in the configured Vault KV path. It binds one authority to its fingerprint, source definition versions, and mount. A mismatch fails closed; it never calls `setup` or overwrites the authority.

Backups retain the Vault data path, mount, keyset ID, manifest, and source schema. Recovery restores the matching authority and manifest, then runs `--check-vault`. MSKs are never exported to Django or backup metadata.

Treat every fingerprint change as incompatible until reviewed. For supported dimension growth, use upstream `add_dimension` and then update the manifest. For incompatible changes, provision a new mount/keyset and retain the old one for historical ciphertext. Never call setup against an existing authority because upstream setup replaces it.
