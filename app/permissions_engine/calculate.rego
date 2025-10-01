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
import data.vault.user_id as user_id

user_pcglid := data.vault.user_pcglid
import rego.v1

#
# This user is a site admin if they have the site_admin role
#
import data.vault.groups as groups

site_admin := true if {
	"PCGL_ADMIN_GROUP" in data.idp.user_info.groups
}

else if {
	user_id in groups.admin
}

site_curator if {
	user_id in groups.curator
}

#
# what studies are available to this user?
#

import data.vault.study_auths as study_auths
import data.vault.user_studies as user_studies

# convert this to be a set, not an array
all_studies := {x | x := data.vault.all_studies[_]}

# compile list of studies specifically authorized for the user by DACs and within the authorized time period
user_readable_studies contains p.study_id if {
	some p in user_studies
	time.parse_ns("2006-01-02", p.start_date) <= time.now_ns()
	time.parse_ns("2006-01-02", p.end_date) >= time.now_ns()
}

# compile list of studies that list the user as a team member
team_readable_studies contains p if {
	some p in all_studies
	user_pcglid in study_auths[p].team_members
}

# user can read studies that are either team-readable or user-readable
readable_studies := all_studies if {
	site_curator
}

else := team_readable_studies | user_readable_studies

# user can edit studies that list the user as a study curator
study_editable_studies contains p if {
	some p in all_studies
	user_pcglid in study_auths[p].study_curators
}

# if the user is a site curator, they can curate any study
editable_studies := all_studies if {
	site_curator
}

# otherwise, the user can curate studies where they're listed as a study curator
else := study_editable_studies

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

accessible_studies := editable_studies | readable_studies

# which datasets can this user see for this method, path
default studies := []

# site admins can see all studies
studies := all_studies if {
	site_admin
}

# if user is a curator, they can access studies that allow edit access for them for this method, path
else := accessible_studies if {
	site_curator
}

else := accessible_studies if {
	input.body.method = "GET"
	regex.match(paths.edit.get[_], input.body.path) == true
}

else := accessible_studies if {
	input.body.method = "POST"
	regex.match(paths.edit.post[_], input.body.path) == true
}

else := accessible_studies if {
	input.body.method = "DELETE"
	regex.match(paths.edit.delete[_], input.body.path) == true
}
