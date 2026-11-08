# Building the native library and Vault plugin from upstream source

[Tiếng Việt](../vi/crypto-source-build.md)

CPQA configures only the upstream GitHub URL through `CRYPTO_REPOSITORY` in
`docker/Dockerfile`. It does not pin a tag, commit, or library version. Each build
resolves the **latest HEAD of the upstream default branch**, then builds the
native library and Vault plugin from that checkout using the upstream Makefile
(`make vault`, which depends on `make shared`). No binaries, headers, or plugin
source are vendored under `src/`.

## Clone, build, and update

```bash
git clone https://github.com/WanThinnn/Cloud-Policy-Quantum-Access.git
cd Cloud-Policy-Quantum-Access
# Prepare .env and certificates using the existing deployment instructions.
python start.py build
python start.py up
# Update CPQA, fetch the latest crypto source, build, and recreate services:
python start.py update
```

Place `--prod` before the command to use production Compose. Both development
and production build web/Vault from source. Production uses the local image tags
`cpqa-web:local` and `cpqa-vault:local`; its pull step skips services that have a
build definition. Always run build before up after cloning.

Cloning CPQA downloads only CPQA. Docker fetches the library source during the
build, so no adjacent library checkout or host C++/Rust/Go toolchain is required.
The first build needs network access, disk space for the toolchains, and more
time than cached builds. Linux AMD64 is the currently supported Docker platform.

## Cache and artifact synchronization

BuildKit fetches the Git source through `ADD --keep-git-dir=true`, resolves HEAD
on each build, and uses the resolved commit as its cache identity. A new upstream
commit therefore rebuilds crypto even if CPQA has not changed; `--no-cache` is not
needed to refresh source. An unchanged HEAD reuses the crypto stage. Cargo/Go
caches reduce subsequent build time. `CRYPTO_BUILD_JOBS` in the Compose
environment controls parallelism (default 4; use 2 on machines with limited RAM).
Resolving the latest upstream HEAD requires network access even for cached builds.

The common `crypto-builder` stage supplies the `web`, `vault`, and
`crypto-artifacts` targets. Its native `.so` and plugin come from the same source
checkout. The actual commit and version are recorded **after building** in
`/opt/cpqa/crypto/source.env` for inspection; this is output metadata, not a source
pin. Override the upstream URL with the Docker build argument `CRYPTO_REPOSITORY`
when needed.

The web library lives in `/opt/cpqa/crypto/lib`, outside the development `/app`
bind mount. `CPABE_LIBRARY_DIR` points the ctypes consumer there. The old anonymous
`/app/lib` volume is no longer used. On each start, the Vault entrypoint refreshes
the executable and matching `.so` in the plugin volume so existing volumes cannot
hide artifacts from the new image. Web reads that executable to register its
SHA256 with Vault.

Update runs git pull --ff-only and builds before recreating services. Build
failures stop before up. It no longer downloads release ZIPs, patches CGO paths,
or overwrites local plugin source. Vault data, credentials, trust roots, master
keys, AC17/TKN20 mounts, and KV public keys are preserved. Upstream 6.0.0 includes
legacy plugin storage reads in `plugin/authority.go`; following HEAD does not
establish compatibility of every future revision with deployment data. Do not
call setup to test an upgrade against existing authorities.

The build applies `docker/patches/vault-authority-chunks.patch` to the upstream
Vault plugin before `make vault`. This keeps the CPQA build compatible with the
upstream Git HEAD while storing large CoverCrypt authorities as sub-1-MiB
seal-wrapped values. The patch is checked before application; if upstream changes
the authority storage implementation incompatibly, the crypto image build fails
instead of silently shipping an unpatched plugin. Existing single-record
authorities remain readable. See the [Vault contract](covercrypt-vault-contract.md)
for the chunk manifest and commit behavior.

The following `vault-covercrypt-public-reference.patch` adds a read-only public
authority endpoint and fingerprint-bound CoverCrypt public-key references. Both
web and Vault must use this contract; its checksum is recorded separately in
`source.env`. See the [Vault contract](covercrypt-vault-contract.md) for safe
recovery after authority creation succeeds but public metadata persistence fails.

## Verification and export

```bash
docker build --platform linux/amd64 --target crypto-test -f docker/Dockerfile -t cpqa-crypto-test:latest .
docker build --platform linux/amd64 --target vault -f docker/Dockerfile -t cpqa-vault-test:latest .
python tests/smoke_crypto_image.py --image cpqa-vault-test:latest
python -m unittest discover -s tests -p test_crypto_build.py -v
```

`crypto-test` runs upstream native and Go backend tests with real cryptography
and disposable data in the build container. The smoke test creates and removes
a separate Vault container, checks AC17/TKN20/CoverCrypt HTTP encryption/decryption with and
without signatures, verifies allow/deny behavior, and checks stale artifact
replacement. Neither test uses deployment databases, Vault services, storage, or
volumes. These checks do not establish compatibility with every existing
ciphertext in a deployment.

Upstream v6.0.0 includes native CoverCrypt and the Vault plugin adapter. Vault
setup requires `config_json` describing authority dimensions; native setup reads
the configured JSON file through `HCPABE_COVERCRYPT_CONFIG`. Both expose
`classic`, `post_quantum`, and `hybridized` CoverCrypt modes. The optional Vault
`pqc` flag controls ML-DSA signing separately from the CoverCrypt KEM mode.

CPQA integrates CoverCrypt using validated dimensions derived from active database
attributes, a bounded policy compiler, per-file scheme metadata, and the Vault or
native backend selected by deployment configuration. Building the upstream
artifacts alone does not initialize the application authority or configure the
database-derived dimensions. See the [CoverCrypt lifecycle guide](covercrypt-configuration-lifecycle.md),
[integration plan](covercrypt-integration-plan.md), and [upstream contract](covercrypt-vault-contract.md).

The `scripts/build_plugin_for_docker.sh` and `.ps1` helpers export the
`crypto-artifacts` target to `build/crypto/`, including `lib/`, `plugin/`, and
`source.env`. Host Python on Windows still needs an upstream Windows Makefile
build; set `CPABE_LIBRARY_DIR` to its `lib/` directory containing both the main
DLL and `libcpabe_tkn20.dll`. Linux Docker artifacts cannot replace Windows DLLs.
