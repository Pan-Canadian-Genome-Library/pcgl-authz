#!/usr/bin/env bash

# Container entrypoint for local development with root access to a local Vault server.

set -Euo pipefail


if [[ -f "/app/initial_setup" ]]; then
    mkdir /app/data
    chmod 777 /app/data

    echo "initializing stores"
    python3 /app/initialize_vault_store.py
    if [[ $? -eq 0 ]]; then
        rm /app/initial_setup
        echo "setup complete"
    else
        echo "!!!!!! INITIALIZATION FAILED, TRY AGAIN !!!!!!"
    fi

else
    sleep 10
    # unseal vault
    KEY=$(head -n 2 /app/config/keys.txt | tail -n 1)
    echo '{ "key": "'$KEY'" }' > payload.json
    curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
    KEY=$(head -n 3 /app/config/keys.txt | tail -n 1)
    echo '{ "key": "'$KEY'" }' > payload.json
    curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
    KEY=$(head -n 4 /app/config/keys.txt | tail -n 1)
    echo '{ "key": "'$KEY'" }' > payload.json
    curl --request POST --data @payload.json http://vault:8200/v1/sys/unseal
fi

# make sure that our vault stores have the latest values
python3 /app/refresh_stores.py

# spin up daemon process
bash /app/daemon.sh &

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
