import json
import os
from src.auth import get_vault_token_for_service, reload_comanage
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
        with open("/home/pcgl/opa-roleid") as f:
            role_id = f.read().strip()
            payload = f"{{\"token\": \"{get_vault_token_for_service("opa", role_id=role_id)}\"}}"
            response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/opa_token", headers=headers, data=payload)
            print(response.text)
        with open("/home/pcgl/test-roleid") as f:
            role_id = f.read().strip()
            payload = f"{{\"token\": \"{get_vault_token_for_service("test", role_id=role_id)}\"}}"
            response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/test_token", headers=headers, data=payload)
            print(response.text)

    print(reload_comanage())
except Exception as e:
    print(str(e))
    sys.exit(1)
