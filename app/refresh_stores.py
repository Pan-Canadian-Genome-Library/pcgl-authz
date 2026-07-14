import json
import os
from src.auth import get_secret_file_value_or_env, get_vault_token_for_service, reload_comanage
import sys
import requests
import logging
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(filename)s: %(funcName)s:%(lineno)d: %(message)s', stream=sys.stdout)
logger = logging.getLogger(__file__)

# get the token for the opa store
try:
    headers = {
        "X-Opa": os.getenv('OPA_SECRET'),
        "Content-Type": "application/json; charset=utf-8"
    }

    # OPA Role-ID
    opa_role_id = get_secret_file_value_or_env("/home/pcgl/opa-roleid", "OPA_ROLEID")
    payload = f"{{\"token\": \"{get_vault_token_for_service("opa", role_id=opa_role_id)}\"}}"
    response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/opa_token", headers=headers, data=payload)
    logger.info(f"Updated opa_token: {response.status_code} {response.text}")

    # TODO: can we remove this? Feel that this should be in tests rather than baked in
    # Test Role-ID
    test_role_id = get_secret_file_value_or_env("/home/pcgl/test-roleid", "TEST_ROLEID")
    if test_role_id:
        payload = f"{{\"token\": \"{get_vault_token_for_service("test", role_id=test_role_id)}\"}}"
        response = requests.put(url=f"{os.getenv('OPA_URL')}/v1/data/test_token", headers=headers, data=payload)
        logger.info(f"Updated opa_token: {response.status_code} {response.text}")
    logger.info(reload_comanage())
except Exception as e:
    logger.error(str(e))
    sys.exit(1)
