package permissions

import rego.v1

#
# Values that are used by authx
#
valid_token if {
	data.idp.valid_token
}

else := false

#
# Authorization for Studies
#

study_dac := data.vault.study_auths[input.body.study].dac_id

studies := data.calculate.studies if {
	valid_token
}

else := []


#
# Roles
#

site_admin := data.calculate.site_admin if {
	valid_token
}

else := false

data_admin := data.calculate.data_admin if {
	valid_token
}

else := false

dac_chair := true if {
	some p in data.idp.user_info.groups
	p = concat("", ["PCGL:DACO:CHAIR:", study_dac])
}
else := false

dac_member := true if {
	some p in data.idp.user_info.groups
	p = concat("", ["PCGL:DACO:MEMBER:", study_dac])
}
else := false


#
# Check to see if the path is readable or editable:
#

# true if the path and method in the input match a readable combo in paths.json
readable_method_path if {
	input.body.method = "GET"
	data.calculate.readable_get[_]
}

else if {
	input.body.method = "POST"
	data.calculate.readable_post[_]
}

else := false

# true if the path and method in the input match a editable combo in paths.json
editable_method_path if {
	input.body.method = "GET"
	data.calculate.editable_get[_]
}

else if {
	input.body.method = "POST"
	data.calculate.editable_post[_]
}

else if {
	input.body.method = "UPDATE"
	data.calculate.editable_update[_]
}

else if {
	input.body.method = "DELETE"
	data.calculate.editable_delete[_]
}

else := false

####
# ALLOWED: this is the main calculation
####

# if a specific study is in the body, allowed = true if that study is in studies
allowed if {
	studies[input.body.study] == true
}

else if {
	input.body.study in studies
}

# or if someone is querying themselves
else if {
	regex.match("/me$", input.body.path)
	input.body.method == "GET"
}

# or if the user is a site admin
else if {
	site_admin
}

# or if the user is a data admin and wants to edit something
else if {
	data_admin
	editable_method_path
}

else if {
	data_admin
	readable_method_path
}

# or if the path contains dac_authorizations
else if {
	dac_chair
	regex.match(`.*/dac_authorizations$`, input.body.path)
	input.body.method in ["GET", "POST", "DELETE"]
}

else if {
	dac_member
	regex.match(`.*/dac_authorizations$`, input.body.path)
	input.body.method in ["GET"]
}

else := false

#
# User information, for decision log
#

user_id := data.vault.user_id
user_pcglid := data.vault.user_pcglid
user_aud := data.idp.user_aud
user_sub := data.idp.user_sub

#
# Debugging information for decision log
#

user_is_authorized if {
	data.vault.user_auth.status_code == 200
}

else := false

# studies the user can read
readable_studies := data.calculate.readable_studies

# studies the user can edit
editable_studies := data.calculate.editable_studies

# daco memberships
daco_memberships contains p if {
	some p in data.idp.user_info.groups
	regex.match(`PCGL:DACO:.*`, p)
}
