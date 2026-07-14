mkdir -p /permissions_engine
cp -r /app/permissions_engine/* /permissions_engine/
chmod 777 /permissions_engine

# set up our default values
sed -i s@PCGL_ADMIN_GROUP@$PCGL_ADMIN_GROUP@ /permissions_engine/calculate.rego
sed -i s@PCGL_DATA_ADMIN_GROUP@$PCGL_DATA_ADMIN_GROUP@ /permissions_engine/calculate.rego

token=$(dd if=/dev/urandom bs=1 count=16 2>/dev/null | base64 | tr -d '\n\r+' | sed s/[^A-Za-z0-9]//g)
echo { \"opa_secret\": \"$token\" } > /permissions_engine/opa_secret.json
# set up vault URL and namespace
sed -i s@VAULT_URL@$VAULT_URL@ /permissions_engine/vault.rego
sed -i s@VAULT_NAMESPACE@$VAULT_NAMESPACE@ /permissions_engine/vault.rego
