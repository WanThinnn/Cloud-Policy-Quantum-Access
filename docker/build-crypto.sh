#!/bin/bash
set -euo pipefail
cd /build/crypto
git submodule update --init --recursive
# Application builds must consume upstream source without modifying its contract.
git diff --quiet HEAD --
make -j"${CRYPTO_BUILD_JOBS:-4}" vault
mkdir -p /opt/cpqa/crypto/lib /opt/cpqa/crypto/plugin
cp build/artifacts/linux/vault/libhybrid-pq-cp-abe.so /opt/cpqa/crypto/lib/
cp build/artifacts/linux/vault/vault-plugin-abe /opt/cpqa/crypto/plugin/
{
    printf 'CRYPTO_REPOSITORY=%s\n' "$CRYPTO_REPOSITORY"
    printf 'CRYPTO_COMMIT=%s\n' "$(git rev-parse HEAD)"
    printf 'CRYPTO_VERSION=%s\n' "$(tr -d '[:space:]' < VERSION)"
    printf 'CRYPTO_CPQA_PATCHES=none\n'
} > /opt/cpqa/crypto/source.env
ldd /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so
ldd /opt/cpqa/crypto/plugin/vault-plugin-abe
! ldd /opt/cpqa/crypto/lib/libhybrid-pq-cp-abe.so | grep 'not found'
! ldd /opt/cpqa/crypto/plugin/vault-plugin-abe | grep 'not found'
