# CoverCrypt Upstream Contract (v6.0.0)

[Tiếng Việt](../vi/covercrypt-vault-contract.md) · [Integration plan](covercrypt-integration-plan.md)

This note records the contract observed in the local upstream source checkout at `D:\Documents\ABE\Hybrid-CP-ABE-Library`, whose `VERSION` file is `6.0.0`. The prebuilt Windows library at `lib/libhybrid-pq-cp-abe.dll` returned `6.0.0` from `getVersion()` and exported the generic scheme-selecting C functions listed below. This is an inspection of that checkout/build, not a claim that an arbitrary future moving-HEAD build has the same ABI. Docker records the resolved source revision in its generated manifest.

## Native C ABI and Vault plugin are separate callers

Upstream defines `CPABE_SCHEME_AC17 = 0`, `CPABE_SCHEME_TKN20 = 1`, and `CPABE_SCHEME_COVERCRYPT = 2`. The public generic ABI includes scheme-selecting setup, key-generation, and encryption functions; decryption reads the scheme from the ciphertext header. The inspected Windows DLL exports `hybrid_cpabe_setupBuffer_with_scheme`, `hybrid_cpabe_setupBuffer_with_pqc_scheme`, `hybrid_cpabe_genkeyBuffer_with_scheme`, `hybrid_cpabe_encryptBuffer_with_scheme`, `hybrid_cpabe_decryptBuffer`, and `hybrid_cpabe_decryptBuffer_and_verify`.

Native CoverCrypt setup needs a JSON config file at `HCPABE_COVERCRYPT_CONFIG`; `HCPABE_COVERCRYPT_MODE` accepts `classic`, `post_quantum`, or `hybridized` and defaults to `hybridized`. The inspected Windows DLL does **not** export the lower-level `hybrid_cpabe_covercrypt_setupBuffer_from_json` helper. The public native path is the generic scheme-selecting API plus the documented process environment/config file. Do not silently assume the inline JSON helper is available through `ctypes` on every platform.

The Vault plugin is a Go/CGO caller of the native library. It accepts inline `config_json` on setup, stores authority state inside Vault, and exposes paths relative to a mount such as `abe_covercrypt/`. Its endpoint contract is:

| Operation | Request fields | Successful `data` fields | Notes |
| --- | --- | --- | --- |
| `PUT /v1/abe_covercrypt/setup` | `scheme: "covercrypt"`; `config_json`: **string containing JSON**; optional `mode` (`classic`, `post_quantum`, `hybridized`, default `hybridized`); optional `pqc` boolean (ML-DSA signing keys, default `false`) | `public_key` (base64); `scheme`; `pqc`; `native_version`; `revision`; optional `pqc_public_key` (base64); CoverCrypt also returns `config_json` (JSON text) and `mode` | The response never returns the MSK. `pqc` controls optional ML-DSA signing, separately from the CoverCrypt KEM mode. |
| `PUT /v1/abe_covercrypt/genkey` | `scheme: "covercrypt"`; `attributes`: string expression | `secret_key` (base64); `attributes`; `scheme` | Requires an existing authority with the same scheme. CoverCrypt example: `Department::IT Level::ADMIN`. |
| `PUT /v1/abe_covercrypt/encrypt` | `scheme: "covercrypt"`; `plaintext` (base64); `policy`; `public_key` (base64); optional `pqc_private_key` (base64) | `ciphertext` (base64) | If the optional signing key is omitted, the plugin uses the signing secret in that mount's stored authority when one exists. CPQA should not send private signing keys. |
| `PUT /v1/abe_covercrypt/decrypt` | `ciphertext` (base64); `secret_key` (base64); optional `pqc_public_key` (base64) | `plaintext` (base64) | Decrypt has no `scheme` request field; native decryption dispatches using the ciphertext's scheme indicator. Supply the verification key for signed files. |

The `data` above is the Vault HTTP response's `data` object. JSON strings such as `config_json` must remain strings in the request body. Public/secret/ciphertext binary values cross the HTTP API as standard Base64. The checked-in fixture values are only schema sentinels; they are not cryptographic keys or a usable ciphertext.

## Setup, persistence, and rotation semantics

- `setup` is **not idempotent** and does not compare the request config with the stored config. The upstream handler describes it as replacing the mount authority, generates new keys, and unconditionally saves the new authority. A repeated setup can make ciphertext encrypted under the old public key undecryptable with newly issued keys. CPQA must perform a guarded first-time initialization, never call `setup` as a routine “ensure keys” operation, and surface an operator-controlled rotation path.
- The upstream authority stores MSK, public key, optional signing keys, config, scheme and revision in its existing single JSON record under the seal-wrapped `msk/` prefix. CPQA does not change this storage format. Large configurations can exceed Vault storage limits.
- A failed first setup leaves an application guard. Do not clear it based on missing KV metadata alone; the upstream project must provide safe recovery/inspection when authority persistence is uncertain.
- `add_dimension` is an existing authority-growth operation. It updates the same authority/MSK and public key, preserves signing keys, increments revision, and returns updated config/mode. It is not equivalent to a full secret rotation and does not revoke already issued rights.
- The Vault plugin accepts only JSON text that parses and has a usable dimensions array. Its Rust bridge denies unknown JSON fields. `dimensions` must be nonempty; each dimension requires a nonempty ASCII `name` and nonempty `attributes`; every attribute must be nonempty ASCII. `hierarchical` defaults to `false`; when true, attributes are ordered from lowest to highest. No explicit maximum dimension/attribute count or string length was found in the inspected bridge. The app should apply a bounded config size and rely on native validation for cryptographic validity.
- A dimension's JSON object is `{ "name": "Department", "attributes": ["IT", "HR"], "hierarchical": false }`. At the root, the only recognized field is `dimensions`.

## Policy and attribute grammar

The native adapter accepts CoverCrypt policies built from dimension-qualified attributes such as `Department::IT` and operators `AND`/`and`/`&&`, `OR`/`or`/`||`, and parentheses. The adapter normalizes `AND` to `&&` and `OR` to `||`. Bare positive names are normalized to lower-case `<name>::present`; this is useful for boolean dimensions, not a substitute for CPQA's dimension mapping. Unquoted `NOT` is explicitly rejected by the adapter. Do not translate TKN20's negation form to CoverCrypt.

Genkey takes a string of attributes. Whitespace-separated attributes become a conjunction; qualified values such as `Department::IT Level::ADMIN` are preserved. Bare values become `<name>::present`. Qualified names and values must use the exact configured dimension/attribute names (the bridge requires ASCII). Upstream documents hierarchical attributes in lowest-to-highest order and supports `hierarchical: true` in the config.

The native CoverCrypt KEM mode is `classic`, `post_quantum`, or `hybridized`. In this upstream implementation, hybridized combines Curve25519 with ML-KEM-768; post-quantum mode uses the post-quantum CoverCrypt path. The separate Vault setup field `pqc=true` generates ML-DSA keys used by optional Sign-then-Encrypt signing. A file's signature mode is therefore not the same thing as its CoverCrypt KEM mode.

## Ciphertext identification and signature metadata

The library's v2 envelope has a scheme indicator byte: `0` AC17, `1` TKN20, and `2` CoverCrypt. CoverCrypt uses the normal v2 scheme-tagged hybrid envelope, so the CPQA header parser should accept `scheme=covercrypt` for v2 and continue to reject unknown values. Legacy v1 has no scheme byte and remains AC17.

The header identifies ciphertext format and ABE scheme; it does **not** record whether ML-DSA signing was enabled. The Vault `encrypt` response only returns `ciphertext`, so the caller must record signature mode from the exact key/configuration used for that encryption in the per-version metadata. For a version recorded as signed, decryption must provide the matching verification public key and require verification success. Never infer the signature mode from `CPABE_SCHEME`, the current `pqc` setting, or the ABE header.

## Upstream-only integration

CPQA builds the original upstream source without local patches, source rewrites,
custom endpoints or serialization extensions. Public keys use the Base64 contract
above. Encrypt has no per-request `sign` field and returns ciphertext only;
CPQA records application metadata from the requested scheme, validated envelope
and known authority signing state. A signing-state mismatch is rejected before
encryption instead of pretending a client flag changes library behavior.

The upstream plugin has no read-only public authority recovery endpoint. An
interrupted setup is blocked; missing KV metadata does not establish that the
mount is empty. Do not repeat setup or clear guards without independent operator
verification. Large authority/public-key support and safe recovery require work
in the library project: [upstream requirements](covercrypt-upstream-requirements.md).

CPQA rejects public-key payloads above a conservative 512-KiB application KV
budget before attempting to persist them. This is not a new library encoding or
a claim that all smaller authority configurations fit Vault's storage limits.

## Error behavior

Plugin validation and native failures are returned as Vault logical error responses (the Vault HTTP API normally represents these as an error response, commonly HTTP 400 with an `errors` array). Stable error categories observed in source include:

- Missing or malformed CoverCrypt `config_json`: requires valid JSON text with a dimensions array.
- `config_json` supplied for AC17/TKN20: supported only for CoverCrypt.
- Unsupported `mode`: use `classic`, `post_quantum`, or `hybridized`.
- Empty/invalid dimensions and attributes: rejected by the native CoverCrypt bridge, which maps structural validation failures to the generic `Invalid parameter` error code.
- Empty attributes or missing authority at key generation; authority scheme mismatch.
- Non-Base64 plaintext/public key/ciphertext/secret key/signing key: rejected before native crypto.
- Unsatisfied access policy: native `Policy mismatch - attributes do not satisfy policy` error.
- Invalid/missing signature verifier for a signed ciphertext: native verification failure; app must fail closed.

Tests should assert status/category and safe error shape rather than pinning every full native error string. Some detailed Rust parser errors are collapsed by the C++ adapter to a generic error code. Never include real keys or plaintext in an error fixture.

## Existing upstream evidence and documentation

The inspected upstream root README, Vault README, CoverCrypt binding README, v6.0.0 release notes, and Go backend tests already describe native CoverCrypt, the Vault endpoints, dimensions/configuration, modes, policies, and signed/unsigned allow/deny cases. No upstream documentation edit was needed for this phase. The upstream backend tests include valid signed and unsigned workflows, invalid CoverCrypt setup inputs, scheme isolation, and dimension growth. This note does not claim those tests were rerun in this task.

See [`tests/fixtures/covercrypt-vault-contract/README.md`](../../tests/fixtures/covercrypt-vault-contract/README.md) for sanitized JSON templates and the rules for turning them into live contract tests.

## Upstream source references

- [Public C API header](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h) and [scheme enum](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/cpabe-scheme.h)
- [CoverCrypt native adapter](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/schemes/covercrypt.cpp) and [native setup dispatch](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/core/abe-setup.cpp)
- Vault [setup](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_setup.go), [key generation](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_genkey.go), [encryption/decryption](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_crypto.go), and [authority storage](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/authority.go)
- Upstream [Vault API guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/README.md), [CoverCrypt binding guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/bindings/covercrypt/README.md), and [release notes v6.0.0](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/release_notes/v6.0.0.md)
