import json
import os
from src.auth import get_service_store_secret, set_service_store_secret, get_comanage_groups, get_user_record, list_studies, add_study
import sys
import requests

## Initializes Vault's opa service store with the data in site_roles.json, paths.json, studies.json

results = []

try:
    response, status_code = get_service_store_secret("opa", key="paths")
    if status_code != 200:
        with open('/app/defaults/paths.json') as f:
            data = f.read()
            response, status_code = set_service_store_secret("opa", key="paths", value=data)
            if status_code != 200:
                raise Exception(f"failed to save paths: {response} {status_code}")
            results.append(response)

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

    # initialize groups from comanage
    members_to_initialize = []
    response, status_code = get_comanage_groups()

    if status_code == 200:
        group_ids = response["ids"]
        for group_id in group_ids:
            for i in response[group_id]:
                if i not in members_to_initialize:
                    members_to_initialize.append(i)
        response, status_code = set_service_store_secret("opa", key="groups", value=json.dumps(response))
    else:
        raise Exception(f"failed to save groups: {response} {status_code}")

    # initialize users:
    for member in members_to_initialize:
        print(get_user_record(member))

    # initialize studies
    current_studies, status_code = list_studies()
    if status_code != 200:
        current_studies = []
    with open('/app/defaults/studies.json') as f:
        studies = json.load(f)
        for study in studies:
            if studies[study] not in current_studies:
                response, status_code = add_study(studies[study])
                if status_code != 200:
                    raise Exception(f"failed to save study authz: {response} {status_code}")
                results.append(response)


except Exception as e:
    print(str(e))
    sys.exit(4)

sys.exit(0)
