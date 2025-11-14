#!/usr/bin/env bash

export VAULT_APPROLE_TOKEN=$(cat /vault/config/approle-token)

echo "renewing approle token"
curl --request POST \
    --header "X-Vault-Token: ${VAULT_APPROLE_TOKEN}" \
    --header "X-Vault-Namespace: ${VAULT_NAMESPACE}" \
    $VAULT_URL/v1/auth/token/renew-self > finish.json

grep "error" finish.json
if [[ $? -eq 0 ]]; then
    echo "Approle token renewal error:"
    cat finish.json | jq
fi
rm finish.json
