# Service to service authorization 

The authz service supports service-to-service communication when a request exceeds the authorization of the authenticated user. This authorization flow should only be implemented for specific requests. 

## Calling service

The calling service requests a service token with a POST to `/service/{service_id}/verify` where service_id is it's own service_id and the POST body includes the service UUID obtained during service registration. This returns a service token specific for this service, and also stores this token in the auth service's secret store (Vault).  

When making the request, the calling service includes this token as an `X-Service-Token` in the header. 

## Receiving service:

When receiving a request where service-to-service flow has been implemented, the receiving service verifies the token using GET `/service/{service_id}/verify` where the service_id is that of the calling service and including the token as an `X-Service-Token` in the header. The auth service returns `true` or `false` depending if the token matches the stored token for that service_id. 