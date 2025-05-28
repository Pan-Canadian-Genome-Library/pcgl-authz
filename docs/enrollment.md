# User enrollment in CILogon

CILogon provides federated identify management, supporting any institution in the [InCommon](https://incommon.org/federation/) federation - in Canada, this is any institution that is a member of [CAF](https://www.canarie.ca/identity/caf/). It also supports login using GitHub, Google, Microsoft, and ORCID. 

During enrollment, users authenticate using a preferred identity. Users should be advised to choose their institutional identity if available (true for any Canadian academic institution that is a member of CAF, which is nearly all universities). It is possible to merge identities later, if a user registers more than once with different IDPs. 

At the moment, all enrollment is either through invitation or by self-registration with approval. We will eventually want to allow self-enrollment without approval, but that's further down the line when we have a prod instance. 

## PCGL user identifiers

We are current creating both a `PCGL Number` (int) and a `PCGL ID` for each user (string, format `PCGL######` where ##### = PCGL Number) through `Configuration -> Identifier Assignments`. In the absence of the ID registry service, we will use this the PCGL ID to uniquely identify users (for example, in calls to the authorization API). This ensures that we always use the same ID, no matter what OIDC attributes are released by the IDP used to authenticate. 

## Configuring enrollment flows 

The default enrollment flows are `Invite a collaborator` and `Self Signup With Approval` - please don't delete these! https://registry-test.alliancecan.ca/registry/co_enrollment_flows/index/co:4

We can create multiple enrollment flows in CILogon for different types of users under `Configuration -> Enrollment Flows`. Flows can be initiated by the user or by invitation. For each flow, we can configure the email text, text displayed in CILogon, approvals, information captured during enrollment, and automatically other attributes. 

For example, we anticipate having different enrollment flows for data curators and DAC reviewers that will automatically place them into COManage groups for curators and reviewers. There is a sample invite-based flow for DACO members `DACO member invitation` that automatically adds an `Enrollment Attribute` of `Group Membership` with a default value of `PCGL:daco-reviewer`. 