# User enrollment in CILogon

CILogon provides federated identify management, supporting any institution in the [InCommon](https://incommon.org/federation/) federation - in Canada, this is any institution that is a member of [CAF](https://www.canarie.ca/identity/caf/). It also supports login using GitHub, Google, Microsoft, and ORCID. 

During enrollment, users will need to authenticate using a preferred identity. Users should be advised to choose their institutional identity if available (true for any Canadian academic institution that is a member of CAF, which is nearly all universities). 

At the moment, all enrollment is either through invitation or by self-registration with approval. We will eventually want to allow self-enrollment without approval, but that's further down the line when we have a prod instance. 

## Configuring enrollment flows 

We can create multiple enrollment flows in CILogon for different types of users. Flows can be initiated by the user or by invitation. For each flow, we can configure the email text, text displayed in CILogon, approvals, information captured during enrollment, and automatically assign Groups and other attributes. 

