# Overview of authentication and authorization in PCGL

Auth in PCGL uses CILogon for authentication, COManage for group management, and the pcgl-authz API for authorization (this API uses Open Policy Agent as the permissions engine and calls the COManage API for group information). In this documentation, we use CILogon and COManage interchangeably - they are separately software products on the back end, but from our perspective, it is all one UI. 

PCGL services need to register as OIDC clients with CILogon and register with the authorization service. 

## Authentication

All authentication of users in PCGL (except for participants in the participant portal) is via CILogon. 

Each PCGL service should register as an OIDC client in CILogon. In the CILogon interface, this is under `Configuration -> OIDC Clients`. 

All user enrollment is currently either via self-registration (requires approval) or by invitation. We can create multiple enrollment flows under `Configuration -> Enrollment Flows` for managing different kinds of users. See [enrollment](\docs\enrollment.md) for details. 

We are using a CILogon deployment that is part of The Alliance subscription - we do not maintain this instance. We are currently only using the test instance - prod is available but not yet configured. Note that PCGL is only one of the Collaborative Organizations in this CILogon deployment. You may see `co:4` at the end of various URLs - we are org #4. 

External links
* CILogon https://www.cilogon.org/ 
* CILogon docs on registering an OIDC client https://www.cilogon.org/oidc 
* COManage https://spaces.at.internet2.edu/display/COmanage/Home 
* PCGL CILogon test instance https://registry-test.alliancecan.ca

## Authorization

The general philosophy for PCGL authentication is that all logic for what users can access what data / services is centrally stored and managed through the pcgl-authz API. This ensures that authorization information is consistent throughout the platform and avoid scenarios where a authorization information has been updated in one service but not another. 

Services are expected to call the authz API to determine whether a user has the appropriate authorization before releasing / editing data. This is in contract to passing all user authorization in the JWT - we may include more in then token when we implement GA4GH Passports and Visas, but that is a future initiative. 

For specific tasks:

* [service-registration](\docs\service-registration.md) for information on registering a PCGL service with the authorization service 
* [authorization](\docs\authorization.md) for using the authorization API to register studies and verify authorization
* [service-verification][\docs\service-verification.md] for implementing service-to-service authorization
