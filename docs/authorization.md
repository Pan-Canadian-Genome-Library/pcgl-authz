# Authorization in PCGL 

The authz API allows for the following types of actions and queries related to data authorization:

* registering new studies (and adding users authorized to edit data for studies)
* asking about authorization for a user-requested actions
* viewing user information
* adding authorization information based on a DACO approval

All authorization in the PCGL is at the level of whole studies. We do not currently implement authorization to only a subset of cases or to a subset of data types in a study. 

Authorization stored as study attributes (via the `/study` endpoints) is meant for users who are submitting data for those studies. Specific approvals for data use that stem from a DACO request process are stored as user attributes (via the `/user` endpoints).

## API spec

OpenAPI spec in [authz_openapi.yaml](https://github.com/CanDIG/pcgl-authz/blob/main/app/src/authz_openapi.yaml)

View spec in swagger: https://editor.swagger.io/?url=https://raw.githubusercontent.com/CanDIG/pcgl-authz/refs/heads/main/app/src/authz_openapi.yaml

## Registering a study

Before any data can be uploaded for a study, a PCGL admin must register the study in the system via the `/study` endpoint. Only the study id is required - this should be provided by the study and must be unique within the PCGL. For CPHI projects, we have agreed on the format of the study id in advance. 

The endpoint also takes an optional list of data submitters (users who can add / edit data for this study). 

The `/study` endpoint does not have an update option, so to modify the list of data submitters, an admin has to GET the study and then re-POST it with the existing + new information. 

CAUTION: A POST request to the ingest/program replaces any existing program registration data for that program. 

Once the PCGL internal identifer service is deployed, the study creation step will also call the identifier service to generate the internal identifier. This ensures that both IDs are recorded at the point of study creation. The quirk with allowing updates to study registrations will need to be fixed before then to avoid re-generating the internal ID. 

## Authorization queries

It is the responsibility of PCGL services to ensure that data is not released unless the user is authorized. The authz `/allowed` endpoint is the primary interface for asking if a user can perform a specified action on a study. When calling `allowed` a service provides the following information, along with user information in the Bearer token:

```
{
  "action": {
    "endpoint": "string",
    "method": "GET"
  },
  "studies": [
    "string"
  ]
}
```


The action must match one of the endpoint / method combinations provided during [service registraion](/docs/service-registration.md).

The authx service returns `True` or `False` for each study in the list of studies, depending on whether the given user can perform the action on the study. It also logs a decision log as an audit trail that details the logic of the decision. 

PCGL services should prioritize this endpoint for authorization decisions vs writing their own logic about data authorization given user and / or study information returned by the study and user endpoints. Why?

* consistent authorization decision-making across the platform
* allows for changes to only happen in one place (e.g. creating a new user role), rather than changing logic in multiple services


## Adding study authorization for a user following a DACO approval 

When a user has been approved by the DACO for access to a study, a PCGL Admin (and eventually a DACO approver once that role is defined) can add authorization for that user by providing the following info via POST to the `/user/{pcgl_id}` endpoint. 

```
{
  "study_id": "string",
  "start_date": "string",
  "end_date": "string"
}
```

You can look up the pcgl_id in CILogon, or search for the user by email with the `/user/lookup` endpoint. 


## Viewing authorization information

The `/user/{pcgl_id}` and `/study/{study_id}` endpoints provide authorization information for users and studies, respectively. 

A user can always view their own authorization information. Viewing information about another user requires a PCGL admin role, as does viewing information about study authorization. Note that there is an open request for a study admin role that can view / edit authorization information for a specific study. 


