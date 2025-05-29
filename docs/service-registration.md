# Service registration 

In order to enable authorization decisions, PCGL services need to be registered with the authorization service. This registration defines the actions implemented by the service, and generates a UUID for enabling service-to-service authorization.   

The `/service` endpoints can also be used to list all services and get a specific service. See the API spec for details. These endpoints are only available to users that is part of the PCGL Admin group in COManage. 

See [service-verification](\docs\service-verification.md) for documentation on making and verifying service-to-service API calls. 

## API spec

OpenAPI spec in [authz_openapi.yaml](https://github.com/CanDIG/pcgl-authz/blob/main/app/src/authz_openapi.yaml)

View spec in swagger: https://editor.swagger.io/?url=https://raw.githubusercontent.com/CanDIG/pcgl-authz/refs/heads/main/app/src/authz_openapi.yaml

## Registering a PCGL service with the authorization service

Information required for registering a service via a POST to the `/service` endpoint:

* a unique service id (string) - provided by the service
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
      "method": "DELETE"
    }
  ]
}
```

In return, the service receives a UUID to use for [service-to-service verification](/docs/service-verification.md). The service is responsible for saving this UUID securely. This token is not needed to simple call the authz API. 


