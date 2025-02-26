#!/usr/bin/env bash

set -Euo pipefail

# This script runs before the container is composed.

# if there isn't already a value, store the value in tmp/vault/approle-token
mkdir -p tmp/vault
if [[ ! -f "tmp/vault/approle-token" ]]; then
    mv tmp/secrets/vault-approle-token tmp/vault/approle-token
fi

# if we didn't need this temp secret, delete it
if [[ -f "tmp/secrets/vault-approle-token" ]]; then
    rm tmp/secrets/vault-approle-token
fi
