# CoverCrypt upstream integration requirements

[Tiếng Việt](../vi/covercrypt-upstream-requirements.md)

CPQA consumes the upstream `Hybrid-PQ-CP-ABE-Library` contract. It must not patch
that source in Docker, add private plugin routes, reinterpret key serialization,
or require fields the library does not return. Required library changes belong
in the library project with its own review, tests and release/build provenance.

## Observed integration blockers

1. **Large authority persistence.** The application's six dimensions, with
   cardinalities 4/3/6/4/5/6, produced a serialized authority around 143 MB. The
   inspected upstream `plugin/authority.go` writes one JSON storage record; the
   tested Vault/Raft deployment rejected that record at its per-entry limit.
   The library needs a supported storage strategy and compatibility tests.
2. **Large public-key transport.** A native probe measured a 35,952,472-byte
   public key (47,936,632 bytes in Base64). The upstream API returns that Base64
   key and requires it on encrypt. This exceeds the deployment's 32-MiB HTTP
   request limit and is unsuitable for its shared KV record. The library must
   define a supported solution; CPQA will follow that published contract.
3. **Interrupted setup.** The inspected plugin provides setup, add_dimension,
   genkey, encrypt and decrypt. It has no read-only public-authority recovery
   route. Setup replaces keys. Recovery must preserve the existing authority,
   expose no MSK/signing secret and never rely on calling setup a second time.
4. **Signature selection.** Encrypt auto-signs when its stored authority has a
   signing key. There is no `sign` request field or `crypto_metadata` response.
   CPQA checks known signing state, records its own version metadata and rejects
   conflicting signature requests. Independent per-request selection or an
   authoritative signature-mode response requires an upstream contract change.

## Previously patched local test state

Earlier CPQA builds used application-owned authority-chunk and public-reference
patches. Those patches have now been removed from source/build. Their prior
test results do not establish compatibility with the unmodified plugin.

Do not replace a running patched plugin over its existing data volume with the
original plugin and assume it can read the custom authority format. Retain the
existing data/keys/images until the library project supplies and verifies a
compatible reader/migration. CPQA rejects the old private key-reference encoding
instead of silently guessing a key or rerunning setup. No data reset or secret
export is part of this correction.

Stages 6–9 of the integration plan remain incomplete. Large-schema deployment
and historical-data migration must be resolved in the library project first.
Build verification uses a separate disposable image/container; it must not
replace or initialize deployment authorities as a side effect of testing.
