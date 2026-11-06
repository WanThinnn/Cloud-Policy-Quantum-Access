# syntax=docker/dockerfile:1
# One source checkout for both Django's native ABI and the Vault plugin.
FROM golang:1.25.7-bookworm AS go-toolchain
FROM rust:1.89.0-bookworm AS rust-toolchain
FROM ubuntu:24.04 AS crypto-builder
ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/usr/local/go/bin:/usr/local/cargo/bin:$PATH \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo
COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates pkg-config clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ARG CRYPTO_REPOSITORY=https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library.git
# BuildKit resolves remote Git HEAD on each build and keys its cache by commit.
# Unlike RUN git clone, this also sees upstream updates when CPQA is unchanged.
ADD --keep-git-dir=true ${CRYPTO_REPOSITORY} /build/crypto
COPY docker/build-crypto.sh ./
COPY docker/patches/vault-authority-chunks.patch ./
ARG CRYPTO_BUILD_JOBS=4
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    bash /build/build-crypto.sh

# Optional isolated checks with real native crypto, including allow/deny cases.
FROM crypto-builder AS crypto-checks
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd /build/crypto && make -j4 test && \
    LD_LIBRARY_PATH=/opt/cpqa/crypto/lib go run scripts/build-vault.go -test && \
    touch /crypto-tests-passed

FROM scratch AS crypto-test
COPY --from=crypto-checks /crypto-tests-passed /crypto-tests-passed

# Export artifacts without requiring a container or a host compiler.
FROM scratch AS crypto-artifacts
COPY --from=crypto-builder /opt/cpqa/crypto/ /

FROM ubuntu:24.04 AS vault
ARG TARGETARCH
ARG VAULT_VERSION=1.15.6
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget unzip libcap2-bin ca-certificates libstdc++6 \
    && cd /tmp \
    && wget -q "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" \
    && wget -q "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" \
    && grep " vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip$" "vault_${VAULT_VERSION}_SHA256SUMS" | sha256sum -c - \
    && unzip "vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" vault -d /usr/bin \
    && rm -f /tmp/vault_* && rm -rf /var/lib/apt/lists/*
COPY --from=crypto-builder /opt/cpqa/crypto /opt/cpqa/crypto
COPY docker/vault/entrypoint.sh /usr/local/bin/cpqa-vault-entrypoint
RUN mkdir -p /vault/plugins /vault/config /vault/file \
    && chmod 755 /usr/local/bin/cpqa-vault-entrypoint \
    && setcap cap_ipc_lock=+ep /usr/bin/vault
ENV LD_LIBRARY_PATH=/opt/cpqa/crypto/lib
EXPOSE 8200
ENTRYPOINT ["/usr/local/bin/cpqa-vault-entrypoint"]
CMD ["server", "-config=/vault/config/config.hcl"]

# Build Tailwind assets separately to keep runtime image slim
FROM node:20-slim AS tailwind-builder
WORKDIR /app/src/theme/static_src

# Copy only package files first to cache npm ci
COPY src/theme/static_src/package*.json ./
RUN npm ci

# Copy the rest of the source code so Tailwind can scan templates
WORKDIR /app
COPY src/ ./src/

WORKDIR /app/src/theme/static_src
RUN npm run build

# Final runtime image
FROM ubuntu:24.04 AS web

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    DJANGO_SETTINGS_MODULE=config.settings.production \
    CPABE_LIBRARY_DIR=/opt/cpqa/crypto/lib \
    LD_LIBRARY_PATH=/opt/cpqa/crypto/lib

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 \
    python3-pip \
    python3-venv \
    gcc \
    sqlite3 \
    libglib2.0-0 \
    libgmp10 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Create and activate a virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY src/requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install gunicorn

COPY src/ /app/
COPY --from=crypto-builder /opt/cpqa/crypto/lib /opt/cpqa/crypto/lib
COPY --from=crypto-builder /opt/cpqa/crypto/source.env /opt/cpqa/crypto/source.env
COPY --from=tailwind-builder /app/src/theme/static/css/dist /app/theme/static/css/dist

RUN mkdir -p /app/data /app/staticfiles /app/logs

RUN DJANGO_SECRET_KEY=dummy DJANGO_ALLOWED_HOSTS=* DATABASE_URL=postgres://dummy:dummy@localhost:5432/dummy python manage.py collectstatic --noinput || true

RUN chmod -R 755 /app && \
    chmod -R 777 /app/data /app/logs

EXPOSE 8000

CMD python manage.py migrate --noinput && \
    python manage.py init_settings && \
    python manage.py collectstatic --noinput && \
    gunicorn config.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
