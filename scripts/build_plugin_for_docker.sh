#!/bin/bash
set -euo pipefail
PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Export the matching .so AND plugin; a standalone plugin is not sufficient.
docker build --platform linux/amd64 --target crypto-artifacts \
    -f "$PROJECT_ROOT/docker/Dockerfile" \
    --output "type=local,dest=$PROJECT_ROOT/build/crypto" "$PROJECT_ROOT"
echo "Crypto artifacts: $PROJECT_ROOT/build/crypto (lib/, plugin/, source.env)"
