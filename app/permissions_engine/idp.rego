package idp

# for interacting with the IdP

import rego.v1

user_info := output if {
	output := input.body.token_info
}

else := output if {
	possible_tokens := ["identity", "token"]
	output := http.send({"method": "get", "url": concat("", ["https://cilogon.org/oauth2/userinfo?access_token=", input[possible_tokens[_]]])}).body
}

user_sub := user_info.sub
user_aud := user_info.aud

default valid_token := false
valid_token if user_sub