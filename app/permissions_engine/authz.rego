package system.authz

import rego.v1

# this defines authentication to have access to opa at all
# from: https://www.openpolicyagent.org/docs/v0.22.0/security/#token-based-authentication-example

# Reject requests by default
default allow := false

# Site admin should be able to see anything
allow if {
	data.permissions.site_admin == true
}

# Opa should be able to store its vault token
allow if {
	input.path == ["v1", "data", "opa_token"]
	input.method == "PUT"
	input.headers["X-Opa"][_] == data.opa_secret
}

# Opa should be able to store its vault token
allow if {
	input.path == ["v1", "data", "test_token"]
	input.method == "PUT"
	input.headers["X-Opa"][_] == data.opa_secret
}

# An authorized user has a valid token (and passes in that same token for both bearer and body)
# Authz users can access the authx paths
allow if {
	input.path == ["v1", "data", "permissions"]
	input.method == "POST"
	input.body.input.token == input.identity
}

# Any service should be able to verify that a service is who it says it is:
allow if {
	input.path == ["v1", "data", "service", "verified"]
	input.method == "POST"
}
