#!/usr/bin/env bash

### Creates a key-value secret store for the service in Vault. This should be invoked at the end of the <service>_setup.sh script (see opa_setup.sh for an example).

# uncomment the next line for debugging
#set -x

source secrets.sh

vault=$(docker ps --format "{{.Names}}" | grep vault_1 | awk '{print $1}')

create_service_store() {
   echo ">> create a policy for opa's access to the approle role and secret"
   docker exec $vault sh -c "echo 'path \"auth/approle/role/opa/role-id\" {capabilities = [\"read\"]}' >> opa-policy.hcl; echo 'path \"auth/approle/role/opa/secret-id\" {capabilities = [\"update\"]}' >> opa-policy.hcl; vault policy write opa opa-policy.hcl"

   echo ">> create an approle for opa"
   cmd="vault write auth/approle/role/opa secret_id_ttl=10m token_ttl=20m token_max_ttl=30m token_policies=opa"
   if [ $PCGL_DEBUG_MODE -eq 0 ]; then
      # get service's container IPs:
      local ips=$(collect_ips)

      cmd+=" secret_id_bound_cidrs=${ips} token_bound_cidrs=${ips}"
   fi
   docker exec $vault sh -c "${cmd}"

   echo ">> setting up opa store policy"
   docker exec $vault sh -c "echo 'path \"opa/*\" {capabilities = [\"create\", \"update\", \"read\", \"delete\"]}' >> opa-policy.hcl; vault policy write opa opa-policy.hcl"

   echo ">> save the role id to secrets"
   docker exec $vault sh -c "vault read -field=role_id auth/approle/role/opa/role-id" > tmp/vault/opa-roleid
   docker cp $PWD/tmp/vault/opa-roleid pcgl-authz_flask_1:/home/pcgl/roleid
   rm $PWD/tmp/vault/opa-roleid

   echo ">> create a kv store for opa"
   docker exec $vault vault secrets enable -path=opa -description="opa kv store" kv

   docker cp $PWD/tmp/vault/approle-token pcgl-authz_flask_1:/home/pcgl/approle-token
}

collect_ips() {
   local containers="opa flask"

   # get service's container IPs:
   local network_containers=$(docker network inspect pcgl-authz_default | jq '.[0].Containers' | jq '[map(.Name), map(.IPv4Address)] | transpose | map( {(.[0]): .[1]}) | add')
   local ips=()
   if [ -n "$network_containers" ]; then
      for container in $containers
      do
         local ip=$(echo $network_containers | jq --arg x "pcgl-authz_${container}_1" -r '.[$x]')
         ip="${ip%/*}/32"
         ips+="\"$ip\","
      done
   fi
   echo $ips
}

if [[ $vault != "" ]]; then
    create_service_store $@
fi
