# Native runtime

CPQA builds the native library and Vault plugin together from the latest upstream
Git HEAD. The repository URL is configured in `docker/Dockerfile`.
No binaries or third-party headers are vendored here.
Docker installs the library in `/opt/cpqa/crypto/lib`, outside the development bind mount.

See [source build instructions](../../docs/en/crypto-source-build.md).
