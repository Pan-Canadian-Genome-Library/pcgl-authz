#!/usr/bin/env bash

set -Euo pipefail

VAULT_SERVICE_PUBLIC_URL=http://127.0.0.1:8200
PCGL_DEBUG_MODE=1

# make sure we have all the env vars:
source secrets.sh

vault=$(docker ps -a --format "{{.Names}}" | grep pcgl-authz_vault_1 | awk '{print $1}')
flask=$(docker ps -a --format "{{.Names}}" | grep pcgl-authz_flask_1 | awk '{print $1}')
docker cp app/vault-config.json $vault:/vault/config/

# check to see if we need to restore a backup before initializing a fresh Vault:
if [[ -f "tmp/vault/restore.tar.gz" ]]; then
  echo ">> restoring vault from backup"
  docker stop $vault
  pwd=$(pwd)
  cd tmp/vault
  tar -xzf $pwd/tmp/vault/restore.tar.gz
  cd $pwd
  cp tmp/vault/backup/keys.txt tmp/vault/
  docker cp tmp/vault/backup/keys.txt $flask:/vault/config/
  docker cp tmp/vault/backup/backup.tar.gz $flask:/vault/
  docker exec -u root $flask bash -c "cd /vault; tar -xzf backup.tar.gz"
  rm -R tmp/vault/backup
  mv tmp/vault/restore.tar.gz tmp/vault/restored.tar.gz
fi

# if vault isn't started, start it:
docker restart $vault

echo ">> waiting for vault to start"
docker ps --format "{{.Names}}" | grep vault_1
while [ $? -ne 0 ]
do
  echo "..."
  sleep 1
  docker ps --format "{{.Names}}" | grep vault_1
done
sleep 5

mkdir -p tmp/vault

# gather keys and login token
stuff=$(docker exec $vault vault operator init) # | head -7 | rev | cut -d " " -f1 | rev)
if [[ $? -eq 0 ]]; then
  echo ">> initialized vault, saving keys"

  key_1=$(echo -n "${stuff}" | grep 'Unseal Key 1: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')
  key_2=$(echo -n "${stuff}" | grep 'Unseal Key 2: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')
  key_3=$(echo -n "${stuff}" | grep 'Unseal Key 3: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')
  key_4=$(echo -n "${stuff}" | grep 'Unseal Key 4: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')
  key_5=$(echo -n "${stuff}" | grep 'Unseal Key 5: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')
  key_root=$(echo -n "${stuff}" | grep 'Initial Root Token: ' | awk '{print $4}' | sed 's/[^a-zA-Z0-9\.\/\+]//g' | sed -e 's/\(0m\)*$//g' | tr -d '[:space:]')

  echo "found key1: ${key_1}"
  echo "found key2: ${key_2}"
  echo "found key3: ${key_3}"
  echo "found key4: ${key_4}"
  echo "found key5: ${key_5}"
  echo "found root: ${key_root}"

  # save keys
  touch tmp/vault/keys.txt
  echo -e "keys: \n${key_1}" > tmp/vault/keys.txt
  echo -e "${key_2}" >> tmp/vault/keys.txt
  echo -e "${key_3}" >> tmp/vault/keys.txt
  echo -e "${key_4}" >> tmp/vault/keys.txt
  echo -e "${key_5}" >> tmp/vault/keys.txt
  echo -e "root: \n${key_root}" >> tmp/vault/keys.txt

  docker cp tmp/vault/keys.txt $vault:/vault/config/

else
  echo ">> retrieving keys"
  key_1=$(head -n 2 tmp/vault/keys.txt | tail -n 1)
  key_2=$(head -n 3 tmp/vault/keys.txt | tail -n 1)
  key_3=$(head -n 4 tmp/vault/keys.txt | tail -n 1)

  key_root=$(tail -n 1 tmp/vault/keys.txt)
fi
echo $key_root
echo ">> attempting to automatically unseal vault:"
docker exec $vault sh -c "vault operator unseal ${key_1}"
docker exec $vault sh -c "vault operator unseal ${key_2}"
docker exec $vault sh -c "vault operator unseal ${key_3}"

# login
echo
echo ">> logging in automatically -- " #copy and paste this: ${key_root}"
docker exec $vault sh -c "vault login ${key_root}"

# configuration
# audit file
# echo
# echo ">> enabling audit file"
# docker exec $vault sh -c "vault audit enable file file_path=/vault/vault-audit.log"

# enable approle
echo
echo ">> enabling approle"
docker exec $vault sh -c "vault auth enable approle"

echo ">> setting up approle policy"
docker exec $vault sh -c "echo 'path \"auth/approle/role/*\" {capabilities = [\"read\", \"update\"]}' > approle-policy.hcl; vault policy write approle approle-policy.hcl"

echo
echo ">> setting up approle role"
cidr_block=$(docker network inspect --format "{{json .IPAM.Config}}" pcgl-authz_default | jq '.[0].Gateway')
cidr_block=$(echo ${cidr_block} | tr -d '"')
cidr_block="${cidr_block}/27"
if [ $PCGL_DEBUG_MODE -eq 1 ]; then
  echo "{\"token_period\": \"768h\"}" > tmp/temp.json
else
  echo "{\"bound_cidrs\": [\"${cidr_block}\"], \"token_period\": \"768h\"}" > tmp/temp.json
fi
curl --request POST --header "X-Vault-Token: ${key_root}" --data @tmp/temp.json $VAULT_SERVICE_PUBLIC_URL/v1/auth/token/roles/approle
rm tmp/temp.json

echo
echo ">> setting up approle token"
echo "{\"policies\": [\"approle\"]}" > tmp/temp.json
curl --request POST --header "X-Vault-Token: ${key_root}" --data @tmp/temp.json $VAULT_SERVICE_PUBLIC_URL/v1/auth/token/create/approle | jq '.auth.client_token' -r > tmp/vault/approle-token
docker cp tmp/vault/approle-token $vault:/vault/config/approle-token
rm tmp/temp.json
