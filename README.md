An initial specification and implementation of an authorization service for the Pan-Canadian Genome Library. This readme describes installation, see [docs](/docs/overview.md) for documentation on usage.

OpenAPI spec in [authz_openapi.yaml](https://github.com/CanDIG/pcgl-authz/blob/main/app/src/authz_openapi.yaml)

View spec in swagger: https://editor.swagger.io/?url=https://raw.githubusercontent.com/CanDIG/pcgl-authz/refs/heads/main/app/src/authz_openapi.yaml

## Running the test implementation
You can run the test implementation of the service via Docker.

Before running the `run.sh` script, open the file `secrets.sh.example` and rename it to `secrets.sh`. Fill in the values for the secrets, based on the PCGL CILogon test configuration. Ask Daisie on Slack if you need directions on obtaining the secrets.

The `run.sh` script will use the environment variables listed in `secrets.sh` and launch three docker containers. The API server will be available at http://localhost:1235.

## Calling the REST API

The authz API is primarily meant to be called by registered services. While all calls require a bearer token that is associated with a user in CILogon, service calls additionally require `X-Service-Id` and `X-Service-Token` headers to determine which service's OIDC client is being used for the user token.

To obtain user tokens, you will need to get an access code from CILogon and exchange it for an access token:

1. In a browser, go to the authorization endpoint: https://cilogon.org/authorize?response_type=code&client_id=cilogon%3A%2Fclient_id%2F234088ba9c4226f6883f38d7f6af69d6&redirect_uri=http%3A%2F%2Flocalhost%3A1235&scope=openid%2Bprofile%2Bemail%2Borg.cilogon.userinfo. You will probably get an error message, but the URL in the browser bar will look something like `https://localhost/?code=NB2HI4D...`. Save that as an environment variable, `export code=NB2HI4D...`

2. Exchange that value for an access token:
```
curl -X "POST" "https://cilogon.org/oauth2/token" \
     -H 'Content-Type: application/x-www-form-urlencoded; charset=utf-8' \
     --data-urlencode "client_id=$PCGL_CLIENT_ID" \
     --data-urlencode "client_secret=$PCGL_CLIENT_SECRET" \
     --data-urlencode "grant_type=authorization_code" \
     --data-urlencode "redirect_uri=http://localhost" \
     --data-urlencode "code=$code"
```

3. Use the access token in an Authorization header for any of the API calls:
```
curl "http://localhost:1235/authz/group/admin" \
 -H 'Authorization: Bearer <token>'
```

## Pytest
There is a basic pytest suite that is primarily designed to test the Opa functionality. Tests to exercise the API calls are still being developed.

## Cleanup
Running the `clean.sh` script will tear down all of the Docker containers.

## Running behind Caddy for HTTPS

TODO: details

```bash
# Set the domain name variable,
export PCGL_AUTHZ_DOMAIN=auth.dev.pcgl.sd4h.ca

docker compose -f docker-compose.proxy.yml up -d
```
