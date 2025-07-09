package permissions

import rego.v1

#
# Values that are used by authx
#
valid_token if {
	data.idp.valid_token
}

else := false

site_admin := data.calculate.site_admin if {
	valid_token
}

site_curator := data.calculate.site_curator if {
	valid_token
}

studies := data.calculate.studies if {
	valid_token
}

else := []

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

# if a specific study is in the body, allowed = true if that study is in studies
# or if the user is a site admin
# or if the user is a site curator and wants to edit something
allowed if {
	studies[input.body.study] == true
}

else if {
	input.body.study in studies
}

else if {
	regex.match("/me$", input.body.path)
	input.body.method == "GET"
}

else if {
	site_admin
}

else if {
	site_curator
	editable_method_path
}

else if {
	site_curator
	readable_method_path
}

else := false

#
# User information, for decision log
#

user_id := data.vault.user_id
user_pcglid := data.vault.user_pcglid

#
# Debugging information for decision log
#

user_is_site_admin if {
	user_id in data.vault.groups.admin
}

else := false

user_is_site_curator if {
	user_id in data.vault.groups.curator
}

else := false

user_is_authorized if {
	data.vault.user_auth.status_code == 200
}

else := false

# studies the user can read
readable_studies := data.calculate.readable_studies

# studies the user can edit
editable_studies := data.calculate.editable_studies
