package calculate

#
# This is the set of policy definitions for the permissions engine.
#

#
# Provided:
# input = {
#     'token': user token
#     'method': method requested at data service
#     'path': path to request at data service
#     'study': name of study (optional)
# }
#
import data.idp.user_key as user_key
import data.vault.user_id as user_id

user_pcglid := data.vault.user_pcglid
import rego.v1

#
# This user is a site admin if they have the site_admin role
#
import data.vault.groups as groups

site_admin if {
	user_id in groups.admin
}

site_curator if {
	user_id in groups.curator
}

#
# what studies are available to this user?
#

import data.vault.all_studies as all_studies
import data.vault.study_auths as study_auths
import data.vault.user_studies as user_studies

# compile list of studies specifically authorized for the user by DACs and within the authorized time period
user_readable_studies[p.study_id] := output if {
	some p in user_studies
	time.parse_ns("2006-01-02", p.start_date) <= time.now_ns()
	time.parse_ns("2006-01-02", p.end_date) >= time.now_ns()
	output := p
}

# compile list of studies that list the user as a team member
team_readable_studies[p] := output if {
	some p in all_studies
	user_pcglid in study_auths[p].team_members
	output := study_auths[p].team_members
}

# user can read studies that are either team-readable or user-readable
readable_studies := object.keys(object.union(team_readable_studies, user_readable_studies))

# user can edit studies that list the user as a study curator
editable_studies[p] if {
	some p in all_studies
	user_pcglid in study_auths[p].study_curators
}

import data.vault.paths as paths

# debugging
readable_get[p] := output if {
	some p in paths.read.get
	output := regex.match(p, input.body.path)
}

readable_post[p] := output if {
	some p in paths.read.post
	output := regex.match(p, input.body.path)
}

editable_get[p] := output if {
	some p in paths.edit.get
	output := regex.match(p, input.body.path)
}

editable_post[p] := output if {
	some p in paths.edit.post
	output := regex.match(p, input.body.path)
}

editable_update[p] := output if {
	some p in paths.edit.update
	output := regex.match(p, input.body.path)
}

editable_delete[p] := output if {
	some p in paths.edit.delete
	output := regex.match(p, input.body.path)
}

# which studies can this user see for this method, path
default studies := []

# site admins can see all studies
studies := all_studies if {
	site_admin
}

# if user is a team_member, they can access studies that allow read access for this method, path
else := readable_studies if {
	input.body.method = "GET"
	regex.match(paths.read.get[_], input.body.path) == true
}

else := readable_studies if {
	input.body.method = "POST"
	regex.match(paths.read.post[_], input.body.path) == true
}

# if user is a site curator, they can access all studies that allow edit access for this method, path
else := all_studies if {
	user_key in groups.curator
	input.body.method = "GET"
	regex.match(paths.edit.get[_], input.body.path) == true
}

else := all_studies if {
	user_key in groups.curator
	input.body.method = "POST"
	regex.match(paths.edit.post[_], input.body.path) == true
}

else := all_studies if {
	user_key in groups.curator
	input.body.method = "DELETE"
	regex.match(paths.edit.delete[_], input.body.path) == true
}

# if user is a study_curator, they can access studies that allow edit access for them for this method, path
else := editable_studies if {
	input.body.method = "GET"
	regex.match(paths.edit.get[_], input.body.path) == true
}

else := editable_studies if {
	input.body.method = "POST"
	regex.match(paths.edit.post[_], input.body.path) == true
}

else := editable_studies if {
	input.body.method = "DELETE"
	regex.match(paths.edit.delete[_], input.body.path) == true
}
