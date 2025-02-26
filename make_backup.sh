#!/usr/bin/env bash

vault=$(docker ps -a --format "{{.Names}}" | grep vault_1 | awk '{print $1}')
flask=$(docker ps -a --format "{{.Names}}" | grep flask_1 | awk '{print $1}')

mkdir -p $(pwd)/tmp/vault/backup
docker exec $vault vault auth disable approle/
stop=$(docker stop $vault)
zip=$(docker exec $flask bash -c "cd /vault; tar -cz data/ > backup.tar.gz")
copy=$(docker cp $flask:/vault/backup.tar.gz $(pwd)/tmp/vault/backup/)

cp $(pwd)/tmp/vault/keys.txt $(pwd)/tmp/vault/backup
cp $(pwd)/tmp/vault/service_stores.txt $(pwd)/tmp/vault/backup
pwd=$(pwd)
cd $(pwd)/tmp/vault
tar -cz backup > backup.tar.gz
rm -R backup
cd $pwd

start=$(docker start $vault)
