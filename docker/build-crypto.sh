#!/bin/bash
set -euo pipefail
cd /build/crypto
git submodule update --init --recursive
git apply --check /build/vault-authority-chunks.patch
git apply /build/vault-authority-chunks.patch
make -j"${CRYPTO_BUILD_JOBS:-4}" vault
mkdir -p /opt/cpqa/crypto/lib /opt/cpqa/crypto/plugin
cp build/artifacts/linux/vault/libhybrid-pq-cp-abe.so /opt/cpqa/crypto/lib/
cp build/artifacts/linux/vault/vault-plugin-abe /opt/cpqa/crypto/plugin/
{
    printf 'CRYPTO_REPOSITORY=%s\n' "$CRYPTO_REPOSITORY"
    printf 'CRYPTO_COMMIT=%s\n' "$(git rev-parse HEAD)"
    printf 'CRYPTO_VERSION=%s\n' "$(tr -d '[:space:]' < VERSION)"
    printf 'CRYPTO_PATCH_SHA256=%s\n' "$(sha256sum /build/vault-authority-chunks.patch | cut -d' ' -f1)"
} > /opt/cpqa/crypto/source.env
ldd /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so
ldd /opt/cpqa/crypto/plugin/vault-plugin-abe
! ldd /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so | grep 'not found'
! ldd /opt/cpqa/crypto/plugin/vault-plugin-abe | grep 'not found'
