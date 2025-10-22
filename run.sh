#!/usr/bin/env bash


source secrets.sh
bash vault_preflight.sh
docker compose build $@
docker compose --compatibility up --detach
mv tmp/vault/backup.tar.gz tmp/vault/restore.tar.gz
bash vault_setup.sh
bash opa_setup.sh
echo ">> waiting for flask to start"
curl "http://localhost:1235/service-info"
while [ $? -ne 0 ]
do
  echo "..."
  sleep 1
  curl "http://localhost:1235/service-info"
done
echo "setup complete"
