# Service registration 

In order to call the authorization API, PCGL services need to be registered with the authorization service. The authz service maintains a secret store in Vault with tokens for each service. When processing an API call, the authz service verifies the identity of the calling service by matching a provided X-Service-Token with the Vault secret store.  

## API spec

OpenAPI spec in [authz_openapi.yaml](https://github.com/CanDIG/pcgl-authz/blob/main/app/src/authz_openapi.yaml)

View spec in swagger: https://editor.swagger.io/?url=https://raw.githubusercontent.com/CanDIG/pcgl-authz/refs/heads/main/app/src/authz_openapi.yaml

## Registering a PCGL service with the authorization service

Information required for registering a service via a POST to the `/service` endpoint:

* a unique service id (string)
* a description of the operations considered "read" and "write" for the service, provided as a list of endpoint + http method for each 

```
{
  "service_id": "string",
  "readable": [
    {
      "endpoint": "string",
      "method": "GET"
    }
  ],
  "editable": [
    {
      "endpoint": "string",
      "method": "GET"
    }
  ]
}
```

In return, the service receives a UUID to use for [service-to-service verification](/docs/service-verification.md). The service is responsible for saving this UUID securely. This token is not needed to simple call the authz API. 

Only a user that is part of the PCGL Admin group in COManage can register a PCGL service. 

