# CoverCrypt Integration Plan

[Tiếng Việt](../vi/covercrypt-integration-plan.md) · [Crypto source build](crypto-source-build.md)

## Goal and scope

Integrate the upstream CoverCrypt scheme into CPQA's file upload, policy, key-generation, and download flows while preserving existing AC17/TKN20 ciphertexts and Vault mounts.

Upstream v6.0.0 exposes CoverCrypt through both its native C ABI and the Vault plugin. CPQA's current `ctypes` adapter still binds the existing AC17/TKN20 entry points, so native support requires adapter work and tests; do not infer app support from the upstream enum alone. The native DLL's generic `*_with_scheme` exports select CoverCrypt, while setup configuration is supplied through the documented `HCPABE_COVERCRYPT_CONFIG` file and mode environment variables. The Vault API instead accepts `config_json` and `mode` on setup. CoverCrypt KEM mode and the library's optional ML-DSA signing mode are separate capabilities and must be represented separately in configuration and metadata.

The Vault `setup` operation replaces the authority stored at that mount. It is not an idempotent key-presence check. CPQA initialization must avoid calling setup on an existing mount; CoverCrypt dimension growth should use the plugin's `add_dimension` operation where appropriate, and authority/key rotation needs a deliberate procedure.

The library is built from the moving upstream branch by the current Docker build. Keep that update behavior, and use the build-generated source manifest to identify the exact upstream commit and version used by each image. Do not pin a commit in this integration plan.

## Current integration points

- `src/crypto_access/services/cpabe_service.py` initializes AC17/TKN20, calls scheme-specific Vault endpoints, generates user keys, and encrypts/decrypts file buffers.
- `scripts/vault_manager.py` provisions `abe_ac17/` and `abe_tkn20/` mounts. Keep both mounts and their existing KV keys.
- `src/crypto_access/models/policy.py` translates ABAC conditions to AC17/TKN20 policy strings.
- `src/crypto_access/services/version_crypto.py` validates per-version crypto metadata and parses the current AC17/TKN20 ciphertext header.
- `src/crypto_access/views/storage.py` selects the scheme for new ciphertexts and the recorded scheme for reads; it also implements key caching and privileged bypass behavior.
- `UploadedFile.abe_scheme` is currently a 10-character field. `FileVersion.crypto_metadata` is JSON. Confirm these can represent the final CoverCrypt metadata before deciding whether a migration is needed.
- `tests/smoke_crypto_image.py` already exercises CoverCrypt through a temporary Vault mount. It supplies `config_json` with dimensions and checks signed/unsigned allow/deny behavior. This proves the plugin path, not app integration.
- The inspected upstream checkout is `VERSION` 6.0.0. Its Windows DLL reports `getVersion() == 6.0.0` and exports the generic native scheme-selecting functions. Its explicit `hybrid_cpabe_covercrypt_setupBuffer_from_json` helper is not exported by that DLL; native setup uses the documented config file/environment path.
- Contract details and secret-free templates: [CoverCrypt upstream contract](covercrypt-vault-contract.md) and [`tests/fixtures/covercrypt-vault-contract/`](../../tests/fixtures/covercrypt-vault-contract/README.md).

## Implementation checklist

### 0. Confirm and document the upstream contract

- [x] Inspect the current upstream source and build outputs for the exact CoverCrypt entry points; distinguish the native shared-library API from the Go/Vault plugin API.
- [x] Record the Vault request/response contract for `setup`, `genkey`, `encrypt`, and `decrypt`, including field names, encodings, error behavior, and whether `pqc` enables signing for CoverCrypt.
- [x] Confirm the supported `config_json` schema, dimension and attribute syntax, encryption-policy grammar, user-key attribute grammar, and limits on dimensions/attributes. No explicit dimension/attribute-count cap was found in the inspected bridge; native parser/resource limits still apply.
- [x] Confirm setup is not idempotent, does not compare against the existing config, and replaces the mount authority; document existing `add_dimension` behavior and the need for an explicit rotation procedure.
- [x] Confirm the CoverCrypt ciphertext envelope/header and distinguish scheme/format detection from per-version signature metadata.
- [x] Check the upstream README, Vault README, binding README, and v6.0.0 release notes. They already describe native and Vault CoverCrypt APIs, config/modes, and policy syntax; no upstream documentation patch is needed.
- [x] Save representative valid and invalid requests/responses as secret-free fixtures for contract tests.

**Exit criteria:** app integration can rely on the written upstream contract and existing native/Vault contract tests; new app-side behavior still needs its own regression coverage. No serialization or policy behavior is inferred from a scheme name alone.

### 1. Design CoverCrypt dimensions and configuration lifecycle

- [x] Define the initial source and mapping: active enum `AttributeDefinition` rows plus bounded profile-derived `user_type` become non-hierarchical dimensions in deterministic name order; free-form `location` is excluded. See [configuration lifecycle](covercrypt-configuration-lifecycle.md).
- [x] Decide whether an attribute dimension can have one value or multiple values per user and specify behavior for missing, unknown, duplicate, or conflicting values. The current unique `(user, attribute)` model supports one value; missing values grant no corresponding CoverCrypt attribute and invalid data fails closed.
- [x] Add a validated, non-secret CoverCrypt configuration source. CPQA generates the single setup JSON from active enum definitions; dimensions are not duplicated in deployment settings and arbitrary runtime JSON is not accepted.
- [x] Compute and record a stable configuration fingerprint/version alongside the corresponding Vault keyset so a restart cannot silently pair old keys with new dimensions. The explicit non-secret Vault manifest is validated before use and cannot be overwritten when incompatible.
- [x] Define an explicit admin/operator procedure for dimension changes and key rotation. Configuration changes fail closed; setup is never called implicitly.
- [x] Decide how backup/recovery identifies the configuration required by each CoverCrypt keyset without exporting Vault MSKs. The Vault keyset manifest binds the non-secret config, mode, mount, and keyset identifier.

**Exit criteria:** met for configuration lifecycle preparation. The deployment can validate the authority repeatedly, detect an incompatible manifest, and follow a documented rotation path. Provisioning the plugin authority itself remains phase 3 work.

### 2. Add scheme selection without changing legacy defaults

- [x] Add `covercrypt` to the central scheme registry and validate it at CP-ABE service dispatch and before upload. No scheme-selection UI exists; runtime settings do not expose `CPABE_SCHEME`.
- [x] Fail closed for `CPABE_SCHEME=covercrypt` until a CPQA backend has implemented and validated its setup/config contract. Upstream support alone does not enable app dispatch.
- [x] Keep the existing default `ac17` and AC17/TKN20 behavior unchanged.
- [x] Review `UploadedFile.abe_scheme` and consumers: its `max_length=10` fits `covercrypt`; serializers do not accept or expose it as a write field, while crypto metadata currently explicitly accepts only AC17/TKN20. No migration is needed for field length, but CoverCrypt metadata remains phase 6 work.
- [x] Confirm runtime-setting allowlists do not expose `CPABE_SCHEME`; `.env.example` retains the existing deployment default `ac17` and Vault/native toggle.

**Exit criteria:** met for pre-dispatch selection. Unsupported scheme/backend combinations fail before upload, and current deployments continue selecting the same scheme as before. CoverCrypt remains unavailable until phase 3/5 implements a CPQA backend.

### 3. Provision the CoverCrypt Vault engine and key material

- [x] Extend Vault provisioning to add `abe_covercrypt/` while retaining `abe_ac17/` and `abe_tkn20/` and their existing data.
- [x] Initialize CoverCrypt with validated dimensions/configuration only for a mount recorded as newly created and with no existing KV keyset state; interrupted setup is guarded against automatic retries.
- [x] Store/read the CoverCrypt public key and PQC verification key under distinct Vault KV keys. The MSK remains inside the plugin's seal-wrapped storage.
- [x] Update `_ensure_keys_exist` to initialize/verify the CoverCrypt authority during Vault-plugin startup.
- [x] Verify public-key/configuration fingerprints at every encryption and key-generation dispatch through the app's CoverCrypt service boundary.
- [x] Make CoverCrypt setup failures visible and fail closed; startup raises instead of claiming readiness if setup or state validation fails.

**Exit criteria:** mount provisioning, guarded authority setup, and per-operation key/configuration checks are implemented; existing AC17/TKN20 mounts are retained.

### 4. Map CPQA attributes and compile policies

- [x] Implement a CoverCrypt attribute mapper from actual user attributes to the configured `dimension::value` syntax. It requires one valid value for every configured dimension, including profile-derived `user_type`.
- [x] Implement a CoverCrypt policy compiler from the supported ABAC AST subset to the upstream dimension-qualified grammar.
- [x] Define operator semantics: `==`, `in`, `and`, `or`, and parentheses are supported; `!=` and `not in` are rejected because missing-attribute behavior differs; ordering, chained comparisons, unary negation, and non-string literals are rejected.
- [x] Ensure compilation uses the same validated configuration service as authority setup and does not read `os.environ` independently.
- [x] Validate generated policies through AccessPolicy serializer/model paths; AI assistant output remains advisory and goes through the same compiler.
- [x] Add focused tests for mapper behavior, supported expressions, and fail-closed rejection cases.

**Exit criteria:** mapping and compiler are implemented against the same config, with unsupported semantics rejected. End-to-end key generation/encryption semantics still require phase 5/8 integration tests.

### 5. Integrate CoverCrypt with upload, key generation, and decryption

- [x] Route setup/keygen/encrypt/decrypt requests to the CoverCrypt mount and send the validated configuration only where the upstream contract requires it.
- [x] Use the confirmed public-key and user-key encodings; preserve existing temporary-file handling and encrypted cache behavior.
- [x] Use the exact CoverCrypt policy and attribute syntax. Do not fall back to AC17/TKN20 formatting on a CoverCrypt error.
- [x] Keep PQC signature enablement independent from ABE scheme selection. Verify signed ciphertexts against the correct CoverCrypt key and reject missing/mismatched verification keys.
- [x] Extend the native `ctypes` adapter to call the generic `*_with_scheme` functions with `CPABE_SCHEME_COVERCRYPT`, and provision the validated CoverCrypt config file/mode through deployment configuration. Keep Vault setup's inline `config_json` flow separate.
- [x] Check every caller of `encrypt_version`, `generate_user_key`, `encrypt_buffer`, and decrypt functions so upload, preview, download, policy assignment/re-encryption, and file-version reads use the same scheme-aware contract.

**Exit criteria:** a new CoverCrypt upload can be decrypted only via its recorded scheme and matching user key; AC17/TKN20 API behavior remains unchanged.

### 6. Extend version metadata and preserve historical ciphertexts

- [ ] Define the CoverCrypt metadata format, including scheme, backend, ciphertext format/version, signature mode, and the non-secret configuration/keyset identifier required for correct reads.
- [ ] Extend `validate_metadata` and metadata persistence without interpreting a CoverCrypt envelope as the existing AC17/TKN20 `hybrid-v1`/`hybrid-v2` format.
- [ ] Add a parser or trusted plugin-returned metadata contract that validates actual ciphertext scheme/format. Reject metadata/ciphertext mismatches and unknown formats; never guess from current `CPABE_SCHEME`.
- [ ] Keep reads for existing AC17/TKN20 versions working when the deployment's current scheme is CoverCrypt, and vice versa.
- [ ] Review copy, rename, version restore, policy assignment, and re-encryption paths to preserve metadata for copied ciphertexts and write new metadata only for newly encrypted versions.
- [ ] Add a migration only if a concrete relational schema change requires one. JSON metadata changes alone should be handled by explicit versioned validation, not by rewriting ciphertext or backfilling unknown history.

**Exit criteria:** historical versions always use their own recorded scheme/backend/format and unknown legacy ciphertexts remain rejected rather than misclassified.

### 7. Review authorization, bypass, cache, and key lifecycle behavior

- [ ] Define CoverCrypt behavior for file owners and privileged users under both normal mode and `SUPER_ADMIN_REQUIRE_POLICY` strict mode.
- [ ] Do not forge CoverCrypt attributes by extracting tokens from a policy string. If an existing non-strict bypass is retained, implement and test a bounded, semantics-preserving satisfaction path; otherwise reject bypass for CoverCrypt until that path exists.
- [ ] Include scheme, user identity, normalized attributes, backend, and key/configuration version in user-key cache identity as appropriate.
- [ ] Invalidate affected cached keys on attribute changes, key revocation, CoverCrypt configuration/key rotation, or backend changes.
- [ ] Verify denied users cannot decrypt even when a cached key exists and that strict policy mode cannot be bypassed through owner/grant/cache paths.
- [ ] Keep secret keys and plaintext out of logs, error responses, telemetry, and persistent Django settings.

**Exit criteria:** CoverCrypt does not weaken the application's authentication, ABAC, file-policy, or cryptographic enforcement layers.

### 8. Add regression and end-to-end coverage

- [ ] Unit-test dimension parsing, attribute normalization, policy compilation, metadata validation, and unsupported native mode.
- [ ] Extend plugin smoke coverage for configured dimensions, correct/wrong user keys, malformed requests, configuration mismatch, signed/unsigned operations, and error responses.
- [ ] Add isolated CPQA upload/download tests for allowed and denied users, AC17/TKN20/CoverCrypt version interleaving, and old-version reads after changing the current scheme.
- [ ] Cover policy assignment/re-encryption, copy/restore, signature verification, cache invalidation, key revocation, and strict/non-strict privileged access.
- [ ] Confirm a bad CoverCrypt setup or Vault outage fails closed and does not save plaintext as if encryption succeeded.
- [ ] Run the relevant security tests and Docker crypto/plugin smoke tests in an isolated environment; record which checks ran and which external services were unavailable.

**Exit criteria:** tests demonstrate correct allow and deny cases and protect existing schemes and historical ciphertexts.

### 9. Document deployment and release behavior

- [ ] Document the CoverCrypt dimensions, policy syntax, deployment configuration, Vault mount/KV paths, initialization, backup/recovery, and rotation procedure in paired `docs/en/` and `docs/vi/` guides.
- [ ] Update `.env.example`, operator help, and API/UI scheme choices only after configuration behavior is finalized; include no secrets or private key material.
- [ ] Document that initial support is Vault-plugin-only unless native ABI support is separately implemented and verified.
- [ ] Update the project facts and release notes with implementation sources and verified limits after code lands.
- [ ] Verify Docker/CI builds record the resolved upstream commit/version in the generated manifest and exercise the plugin contract without hardcoding a commit.

**Exit criteria:** operators can deploy and rotate CoverCrypt without confusing it with AC17/TKN20 or ML-DSA signatures, and the release claims match tested behavior.

## Completion definition

- [ ] New CoverCrypt files upload and download successfully through Vault using validated dimensions and policy translation.
- [ ] Users with matching rights decrypt; users without matching rights are denied.
- [ ] Per-version metadata selects the correct backend/scheme/format across scheme changes, copies, and historical reads.
- [ ] Existing AC17/TKN20 mounts, keys, and ciphertexts remain readable.
- [ ] Strict authorization, cache invalidation, signature verification, and failure handling have regression coverage.
- [ ] Documentation, operator configuration, source manifest, and release notes match the implemented and tested scope.
