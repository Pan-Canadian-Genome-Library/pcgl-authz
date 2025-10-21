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

ns := "VAULT_NAMESPACE"

vault_headers := {"X-Vault-Token": vault_token} if {
    ns == ""
}

vault_headers := {"X-Vault-Token": vault_token, "X-Vault-Namespace": ns} if {
    ns != ""
}

vault_service_headers := {"X-Vault-Token": input.token} if {
    ns == ""
}

vault_service_headers := {"X-Vault-Token": input.token, "X-Vault-Namespace": ns} if {
    ns != ""
}


# paths are the paths authorized for methods, used by permissions.rego
paths := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "paths"]), "headers": vault_headers}).body.data.paths

# groups are site-wide authorizations, used by permissions.rego and authz.rego
groups := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "groups"]), "headers": vault_headers}).body.data

all_studies := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "studies"]), "headers": vault_headers}).body.data.studies

study_auths[p] := study if {
	some p in all_studies
	study := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "studies", p]), "headers": vault_headers}).body.data[p]
}

user_index := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "users/index"]), "headers": vault_headers, "raise_error": false}).body.data

user_id := user_index[data.idp.user_sub] if {
	not input.body.user_pcglid
}

else := user_index[input.body.user_pcglid]

# check to see if the user is authorized for any other studies via DACs
user_auth := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1", test, "users", user_id]), "headers": vault_headers, "raise_error": false})

user_pcglid := user_auth.body.data.pcglid

default user_studies := {}

user_studies := user_auth.body.data.study_authorizations if {
	user_auth.status_code = 200
}

default service := ""
# if there is a service associated with this token:
service := http.send({"method": "get", "url": concat("/", ["VAULT_URL/v1/cubbyhole", input.token]), "headers": vault_service_headers}).body.data.service
