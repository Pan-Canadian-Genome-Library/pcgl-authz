import json
import os
from src.auth import set_service_store_secret, reload_comanage
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

except Exception as e:
    print(f"{type(e)}{str(e)}")
    sys.exit(4)

sys.exit(0)
