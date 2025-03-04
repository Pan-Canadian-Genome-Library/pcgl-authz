#!/usr/bin/env bash


source secrets.sh
bash vault_preflight.sh
docker compose build $@
docker compose --compatibility up --detach
bash vault_setup.sh
bash opa_setup.sh