import json
import os
from src.auth import set_service_store_secret, reload_comanage, add_service
import sys
import requests

## Initializes Vault's opa service store for PCGL openid

results = []

try:
    # initialize idp
    issuer = os.getenv("PCGL_ISSUER")
    aud = os.getenv("PCGL_CLIENT_ID")
    jwks_response = requests.get(f"{issuer}/.well-known/openid-configuration")
    if jwks_response.status_code == 200:
        jwks_response = requests.get(jwks_response.json()["jwks_uri"])
        if jwks_response.status_code == 200:
            new_provider = { "keys": [{"cert": jwks_response.text, "iss": issuer, "aud": aud}]}
            response, status_code = set_service_store_secret("opa", key="data", value=json.dumps(new_provider))
    else:
        raise Exception("couldn't get openid configuration")

    # initialize authz as service, with the default client ID and secret
    with open("config.json") as f:
        authz_service = json.load(f)["service"]
        authz_service["authorization"]["client_id"] = os.getenv("PCGL_CLIENT_ID")
        authz_service["authorization"]["client_secret"] = os.getenv("PCGL_CLIENT_SECRET")
        add_service(authz_service)

except Exception as e:
    print(f"{type(e)}{str(e)}")
    sys.exit(4)

sys.exit(0)
