#!/usr/bin/env bash

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
