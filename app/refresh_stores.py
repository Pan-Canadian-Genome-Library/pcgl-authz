import json
import os
from src.auth import get_secret_file_value_or_env, get_vault_token_for_service, reload_comanage
import sys
import requests

# get the token for the opa store
try:
    with open("/app/permissions_engine/opa_secret.json") as f:
        opa_json = json.load(f)
        headers = {
            "X-Opa": opa_json["opa_secret"],
            "Content-Type": "application/json; charset=utf-8"
        }

        # OPA Role-ID
        opa_role_id = get_secret_file_value_or_env("/home/pcgl/opa-roleid", "OPA_ROLEID")
        payload = f"{{\"token\": \"{get_vault_token_for_service("opa", role_id=opa_role_id)}\"}}"
        response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/opa_token", headers=headers, data=payload)
        print(response.text)

        # Test Role-ID
        test_role_id = get_vault_token_for_service("/home/pcgl/test-roleid", "TEST_ROLEID")
        payload = f"{{\"token\": \"{get_vault_token_for_service("test", role_id=test_role_id)}\"}}"
        response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/test_token", headers=headers, data=payload)
        print(response.text)

    print(reload_comanage())
except Exception as e:
    print(str(e))
    sys.exit(1)
