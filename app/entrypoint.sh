#!/usr/bin/env bash

set -Euo pipefail


if [[ -f "/app/initial_setup" ]]; then

    cp -r /app/permissions_engine/* /permissions-engine/
    chmod 777 /permissions-engine

    mkdir /app/data
    chmod 777 /app/data

    # set up our default values
    sed -i s@PCGL_ADMIN_GROUP@$PCGL_ADMIN_GROUP@ /permissions-engine/calculate.rego

    token=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | base64 | tr -d '\n\r+' | sed s/[^A-Za-z0-9]//g)
    echo { \"opa_secret\": \"$token\" } > /permissions-engine/opa_secret.json
    # set up vault URL and namespace
    sed -i s@VAULT_URL@$VAULT_URL@ /permissions-engine/vault.rego
    sed -i s@VAULT_NAMESPACE@$VAULT_NAMESPACE@ /permissions-engine/vault.rego

    echo "initializing stores"
    python3 /app/initialize_vault_store.py
    if [[ $? -eq 0 ]]; then
        rm /app/initial_setup
        echo "setup complete"
    else
        echo "!!!!!! INITIALIZATION FAILED, TRY AGAIN !!!!!!"
    fi
# TODO: add this to a new "dev-entrypoint.sh" file for local dev
# else
#     sleep 10
#     # unseal vault
#     KEY=$(head -n 2 /app/config/keys.txt | tail -n 1)
#     echo '{ "key": "'$KEY'" }' > payload.json
#     curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
#     KEY=$(head -n 3 /app/config/keys.txt | tail -n 1)
#     echo '{ "key": "'$KEY'" }' > payload.json
#     curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
#     KEY=$(head -n 4 /app/config/keys.txt | tail -n 1)
#     echo '{ "key": "'$KEY'" }' > payload.json
#     curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
fi

# make sure that our vault stores have the latest values
python3 /app/refresh_stores.py


# start server
cd /app/src
gunicorn -k uvicorn.workers.UvicornWorker server:app &


while [ 0 -eq 0 ]
do
  echo "storing vault token"
  date
  bash /app/renew_token.sh
  python3 /app/refresh_stores.py
  if [[ $? -eq 0 ]]; then
      echo "vault token stored"
      sleep 300
  else
      echo "vault token not stored"
      sleep 30
  fi
done
