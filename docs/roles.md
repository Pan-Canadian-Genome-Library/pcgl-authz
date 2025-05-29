# User roles

The definition of specific roles in PCGL is still a work in progress. This documentation describes the high-level overview, as well as the current roles that are implemented (which are almost certainly subject to change).

There are two different levels of roles in PCGL - site level roles and study level roles. 

## Site roles

Site roles are those that apply across all service. Current examples include PCGL Site Admins and DACO Reviewers. These roles are defined by group membership in COManage. We can eiter manually add users to groups, or have the group member attribute be part of the enrollment flow (see [enrollment](/docs/enrollment.md)).

PCGL services can programmatically:

* find the users in a group with the `/group/{group_id}` endpoint 
* find the groups for user with the `/user/{pcgl_id}` endpoint

The names of the site-level roles in COManage are hard-coded into pcgl-authz at the moment, but we want to make this configurable in case we want to re-name the roles in COManage: https://github.com/Pan-Canadian-Genome-Library/pcgl-authz/issues/10 

## Study roles 

We currently have the following roles either implemented or planned:

* `data submitter` (implemented) - a user that can add data (clinical data or genomic data) to a study via the Data Submission services
* `study admin` (planned) - all of the permissions of a `data submitter`, plus the authorization to manage  users for a study; https://github.com/Pan-Canadian-Genome-Library/pcgl-authz/issues/11 
* `team member` (implemented, planned for removal) - this is a hold-over from the MOHCCN implementation in CanDIG and has no meaning in PCGL https://github.com/Pan-Canadian-Genome-Library/pcgl-authz/issues/12 
