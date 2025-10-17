package vault

#
# Obtain secrets from Opa's service secret store in Vault
#
import rego.v1

vault_token := data.test_token.token if {
	input.body.test
}

else := data.opa_token.token

test := "test" if {
	input.body.test
}

else := "opa"

# TODO: need to pass the 'X-Vault-Namespace' header to the vault requests

# paths are the paths authorized for methods, used by permissions.rego
paths := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "paths"]), "headers": {"X-Vault-Token": vault_token}}).body.data.paths

# groups are site-wide authorizations, used by permissions.rego and authz.rego
groups := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "groups"]), "headers": {"X-Vault-Token": vault_token}}).body.data

all_studies := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "studies"]), "headers": {"X-Vault-Token": vault_token}}).body.data.studies

study_auths[p] := study if {
	some p in all_studies
	study := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "studies", p]), "headers": {"X-Vault-Token": vault_token}}).body.data[p]
}

user_index := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "users/index"]), "headers": {"X-Vault-Token": vault_token}, "raise_error": false}).body.data

user_id := user_index[data.idp.user_sub] if {
	not input.body.user_pcglid
}

else := user_index[input.body.user_pcglid]

# check to see if the user is authorized for any other studies via DACs
user_auth := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "users", user_id]), "headers": {"X-Vault-Token": vault_token}, "raise_error": false})

user_pcglid := user_auth.body.data.pcglid

default user_studies := {}

user_studies := user_auth.body.data.study_authorizations if {
	user_auth.status_code = 200
}

default service := ""
# if there is a service associated with this token:
service := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/cubbyhole", input.token]), "headers": {"X-Vault-Token": input.token}}).body.data.service
