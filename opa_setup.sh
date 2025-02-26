#!/usr/bin/env bash

set -Euo pipefail

# This script runs after the container is composed.
# make sure we have all the env vars:
source secrets.sh

echo ">> waiting for flask to start"
docker ps --format "{{.Names}}" | grep flask
while [ $? -ne 0 ]
do
  echo "..."
  sleep 1
  docker ps --format "{{.Names}}" | grep flask
done
sleep 5

flask=$(docker ps -a --format "{{.Names}}" | grep "flask" | awk '{print $1}')
opa_container=$(docker ps -a --format "{{.Names}}" | grep "opa" | awk '{print $1}')

bash $PWD/create_service_store.sh "opa"

docker exec $flask touch /app/initial_setup

docker restart $flask
docker restart $opa_container

