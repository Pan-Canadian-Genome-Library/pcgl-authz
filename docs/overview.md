# Overview of authentication and authorization in PCGL

Auth in PCGL uses CILogon for authentication, COManage for group management, and the pcgl-authz API for authorization (this API calls the COManage API for group information). In this documentation, we use CILogon and COManage interchangeably - they are separately software products on the back end, but from our perspective, it is all one UI. 

PCGL services need to register as OIDC clients with CILogon and register with the authorization service. 

## Authentication

All authentication of users in PCGL (except for participants in the participant portal) is via CILogon. 

Each PCGL service should register as an OIDC client in CILogon ([CILogon docs for OIDC](https://www.cilogon.org/oidc)). In the CILogon interface, this is under `Configuration -> OIDC Clients`. 

All user enrollment is currently either via self-registration (requires approval) or by invitation. We can create multiple enrollment flows under `Configuration -> Enrollment Flows` for managing different kinds of users. See [enrollment](\docs\enrollment.md) for details. 

We are using a CILogon deployment that is part of The Alliance subscription - we do not maintain this instance. We are currently only using the test instance - prod is available but not yet configured. Note that PCGL is only one of the Collaborative Organizations in this CILogon deployment. You may see `co:4` at the end of various URLs - we are org #4. 

Links
* CILogon https://www.cilogon.org/ 
* PCGL CILogon test instance https://registry-test.alliancecan.ca

## Authorization

