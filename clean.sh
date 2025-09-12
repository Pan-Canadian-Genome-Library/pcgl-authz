#!/usr/bin/env bash

source secrets.sh
bash make_backup.sh
docker compose down
docker container prune -f --filter "label=pcgl"
docker image prune -a -f
docker volume rm `docker volume ls -q --filter dangling=true`