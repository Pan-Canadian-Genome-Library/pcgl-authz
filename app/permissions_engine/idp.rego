package idp

# for interacting with the IdP

import rego.v1

user_info := output if {
	possible_tokens := ["identity", "token"]
	output := http.send({"method": "get", "url": concat("", ["https://cilogon.org/oauth2/userinfo?access_token=", input[possible_tokens[_]]])}).body
}

user_key := user_info.sub

default valid_token := false
valid_token if user_key