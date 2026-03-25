#!/usr/bin/env bash

### Creates a key-value secret store for the service in Vault. This should be invoked at the end of the <service>_setup.sh script (see opa_setup.sh for an example).

# uncomment the next line for debugging
#set -x

source secrets.sh

bao=$(docker ps --format "{{.Names}}" | grep vault_1 | awk '{print $1}')

create_service_store() {
   local service=$@

   echo ">> create a policy for ${service}'s access to the approle role and secret"
   docker exec $bao sh -c "echo 'path \"auth/approle/role/${service}/role-id\" {capabilities = [\"read\"]}' >> ${service}-policy.hcl; echo 'path \"auth/approle/role/${service}/secret-id\" {capabilities = [\"update\"]}' >> ${service}-policy.hcl; bao policy write ${service} ${service}-policy.hcl"

   echo ">> create an approle for ${service}"
   cmd="bao write auth/approle/role/${service} secret_id_ttl=10m token_ttl=20m token_max_ttl=30m token_policies=${service}"
   docker exec $bao sh -c "${cmd}"

   echo ">> setting up ${service} store policy"
   docker exec $bao sh -c "echo 'path \"${service}/*\" {capabilities = [\"create\", \"update\", \"read\", \"delete\"]}' >> ${service}-policy.hcl; bao policy write ${service} ${service}-policy.hcl"

   echo ">> save the role id to secrets"

   docker exec $bao sh -c "bao read -field=role_id auth/approle/role/${service}/role-id" > tmp/vault/${service}-roleid
   docker cp $PWD/tmp/vault/${service}-roleid pcgl-authz_flask_1:/home/pcgl/${service}-roleid
   rm $PWD/tmp/vault/${service}-roleid

   echo ">> create a kv store for ${service}"
   docker exec $bao bao secrets enable -path=${service} -description="${service} kv store" kv

   echo ">> create a policy for service-verification"
   docker exec $bao sh -c "echo 'path \"auth/approle/role/verify/role-id\" {capabilities = [\"read\"]}' >> verify-policy.hcl; echo 'path \"auth/approle/role/verify/secret-id\" {capabilities = [\"update\"]}' >> verify-policy.hcl; bao policy write verify verify-policy.hcl"

   echo ">> create an approle for verify"
   cmd="bao write auth/approle/role/verify secret_id_ttl=10m token_ttl=20m token_max_ttl=30m token_policies=verify"
   docker exec $bao sh -c "${cmd}"

   echo ">> save the role id to secrets"
   docker exec $bao sh -c "bao read -field=role_id auth/approle/role/verify/role-id" > tmp/vault/verify-roleid
   docker cp $PWD/tmp/vault/verify-roleid pcgl-authz_flask_1:/home/pcgl/verify-roleid
   rm $PWD/tmp/vault/verify-roleid

   docker cp $PWD/tmp/vault/approle-token pcgl-authz_flask_1:/home/pcgl/approle-token
}

if [[ $bao != "" ]]; then
    create_service_store $@
fi
