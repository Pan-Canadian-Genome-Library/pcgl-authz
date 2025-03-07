import os
import re
import requests
import base64
import json
import uuid
import getpass
import urllib


## Env vars for most auth methods:
OPA_URL = os.getenv('OPA_URL', "http://localhost:8181")
VAULT_URL = os.getenv('VAULT_URL', "http://localhost:8200")
SERVICE_NAME = os.getenv("SERVICE_NAME")
APPROLE_TOKEN_FILE = os.getenv("APPROLE_TOKEN_FILE", "/home/pcgl/approle-token")
ROLE_ID_FILE = os.getenv("ROLE_ID_FILE", "/home/pcgl/roleid")
PCGL_COID = os.getenv("PCGL_COID", "")
PCGL_CORE_API_USER = os.getenv("PCGL_CORE_API_USER", "")
PCGL_CORE_API_KEY = os.getenv("PCGL_CORE_API_KEY", "")
PCGL_API_URL = os.getenv("PCGL_API_URL", "")


class AuthzError(Exception):
    pass


def get_auth_token(request, token=None):
    """
    Extracts token from request's Authorization header
    """
    if request is not None:
        if "Authorization" not in request.headers:
            raise AuthzError("No Authorization header present")
        token = request.headers['Authorization']
        token = token.split(",")[0].strip()
        token = token.split()[1]
    if token is None:
        return None

    return token


######
# General authorization methods
######

def get_opa_permissions(bearer_token=None, user_token=None, method=None, path=None, study=None):
    token = get_auth_token(None, token=bearer_token)
    if user_token is None:
        user_token = token
    headers = {
        "Authorization": f"Bearer {token}"
    }
    input = {
        "token": user_token,
        "body": {
            "method": method,
            "path": path
        }
    }
    if study is not None:
        input["body"]["study"] = study
    response = requests.post(
        OPA_URL + "/v1/data/permissions",
        headers=headers,
        json={"input": input}
        )
    if response.status_code == 200:
        return response.json()["result"], 200
    return response.text, response.status_code


def get_authorized_studies(request, token=None):
    """
    Get studies authorized for the user.
    Returns array of strings
    """

    token = get_auth_token(request, token=token)

    if hasattr(request, 'path'):
        path = request.path
    elif hasattr(request, 'url'):
        path = request.url

    response, status_code = get_opa_permissions(bearer_token=token, method=request.method, path=path)
    if status_code == 200:
        if "studies" in response:
            return response["studies"], 200

    return [], status_code


def is_site_admin(request, token=None):
    """
    Is the user associated with the token a site admin?
    Returns boolean.
    """
    token = get_auth_token(request, token=token)

    response, status_code = get_opa_permissions(bearer_token=token)

    if status_code == 200:
        if 'site_admin' in response:
            return response["site_admin"]
    return False


def is_action_allowed_for_study(request, token=None, method=None, path=None, study=None):
    """
    Is the user allowed to perform this action on this study?
    """
    token = get_auth_token(request, token=token)

    response, status_code = get_opa_permissions(bearer_token=token, method=method, path=path, study=study)
    if status_code == 200:
        if 'allowed' in response:
            return response["allowed"]
    return False


def get_oidcsub(request, token=None):
    """
    Returns the OIDC sub (as defined in the sub claim of userinfo).
    """
    token = get_auth_token(request, token=token)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        OPA_URL + f"/v1/data/idp/user_key",
        headers=headers,
        json={
            "input": {
                    "token": token
                }
            }
        )
    if response.status_code == 200:
        if 'result' in response.json():
            return response.json()['result']
    return None


#####
# Users
#####

def write_user(user_dict):
    if "id" in user_dict:
        comanage_id = user_dict.pop("id")
        response, status_code = set_service_store_secret("opa", key=f"users/{comanage_id}", value=json.dumps(user_dict))
        if status_code != 200:
            response = {"error": f"User {comanage_id} was not found"}
    return response, status_code


def get_user_by_pcglid(pcglid):
    user_index, status_code = get_service_store_secret("opa", key=f"users/index")
    if status_code == 200:
        if pcglid in user_index:
            user, status_code = get_service_store_secret("opa", key=f"users/{user_index[pcglid]}")
            user["id"] = user_index[pcglid]
            return user, status_code
    return {"error": f"no user found for pcglid {pcglid}"}, 404


def get_user_by_comanage_id(comanage_id):
    return get_service_store_secret("opa", key=f"users/{comanage_id}")


def get_self(request, token=None):
    oidcsub = get_oidcsub(request, token=token)
    user_index, status_code = get_service_store_secret("opa", key=f"users/index")
    if status_code == 200:
        if oidcsub in user_index:
            return get_service_store_secret("opa", key=f"users/{user_index[oidcsub]}")
    return {"error": f"could not find user {oidcsub}"}, 404


def lookup_user_by_email(email):
    user_index, status_code = get_service_store_secret("opa", key=f"users/index")
    if status_code == 200:
        if email in user_index:
            result = []
            for comanage_id in user_index[email]:
                user, status_code = get_service_store_secret("opa", key=f"users/{comanage_id}")
                if status_code == 200:
                    user["id"] = comanage_id
                    result.append(user)
            return result, 200
    return {"error": f"no user found for email {email}"}, 404


######
# Studies
######

def get_study(study_id):
    """
    Returns a StudyAuthorization for the study_id
    Authorized only if the service requesting it is allowed to see Opa's vault secrets.
    """
    response, status_code = get_service_store_secret("opa", key=f"studies/{study_id}")
    if status_code < 300:
        return response[study_id], status_code
    return {"message": f"{study_id} not found"}, status_code


def list_studies():
    response, status_code = get_service_store_secret("opa", key="studies")
    if status_code == 200:
        return response['studies'], status_code
    return response, status_code


def add_study(study_auth):
    """
    Creates or updates a StudyAuthorization in Opa's vault service store for the study_id.
    Authorized only if the requesting service is allowed to write Opa's vault secrets.
    """
    study_id = study_auth["study_id"]
    response, status_code = get_study(study_id)
    if status_code < 300 or status_code == 404:
        # create or update the study itself
        if "date_created" not in study_auth:
            from datetime import datetime
            study_auth["date_created"] = datetime.today().strftime('%Y-%m-%d')
        response, status_code = set_service_store_secret("opa", key=f"studies/{study_id}", value=json.dumps({study_id: study_auth}))
        if status_code < 300:
            # update the values for the study list
            response2, status_code = get_service_store_secret("opa", key="studies")

            if status_code == 200:
                # check to see if it's already here:
                if study_id not in response2['studies']:
                    response2['studies'].append(study_id)
            else:
                response2 = {'studies': [study_id]}
            response2, status_code = set_service_store_secret("opa", key="studies", value=json.dumps(response2))
            return response, status_code

    return {"message": f"{study_id} not added"}, status_code


def remove_study(study_id):
    """
    Removes the StudyAuthorization in Opa's vault service store for the study_id.
    Authorized only if the requesting service is allowed to write Opa's vault service store.
    """
    response, status_code = get_study(study_id)
    if status_code == 404:
        return response, status_code
    if status_code < 300:
        # create or update the study itself
        response, status_code = delete_service_store_secret("opa", key=f"studies/{study_id}")

        # update the values for the study list
        response, status_code = get_service_store_secret("opa", key="studies")

        if status_code == 200:
            # check to see if it's here:
            if study_id in response['studies']:
                response['studies'].remove(study_id)
                response, status_code = set_service_store_secret("opa", key="studies", value=json.dumps(response))

        return {"success": f"{study_id} removed"}, status_code
    return {"message": f"{study_id} not removed"}, status_code


######
# Services
######

def get_service(service_id):
    """
    Returns a Service for the service_id
    """
    response, status_code = get_service_store_secret("opa", key=f"services/{service_id}")
    if status_code < 300:
        return response, status_code
    return {"message": f"{service_id} not found"}, status_code


def list_services():
    result = []
    response, status_code = get_service_store_secret("opa", key="services")
    if status_code == 200:
        services = response["services"]
        for service_id in services:
            response, status_code = get_service_store_secret("opa", key=f"services/{service_id}")
            if status_code == 200:
                result.append(response)
    return result, 200


def add_service(service_dict):
    service_id = service_dict["service_id"]

    # list the service in the services index:
    services, status_code = get_service_store_secret("opa", key="services")
    if status_code == 404:
        services = []
    services.append(service_id)
    set_service_store_secret("opa", key="services", value=json.dumps({"services": services}))

    # add the actions to the paths
    paths_response, status_code = get_service_store_secret("opa", key="paths")
    if status_code == 200:
        paths = paths_response["paths"]
        # add the actions:
        for action in service_dict["readable"]:
            if action["endpoint"] in paths["read"][action["method"].lower()]:
                return {"error": f"endpoint {action["endpoint"]} is already registered"}, 500
            paths["read"][action["method"].lower()].append(action["endpoint"])
        for action in service_dict["editable"]:
            if action["endpoint"] in paths["edit"][action["method"].lower()]:
                return {"error": f"endpoint {action["endpoint"]} is already registered"}, 500
            paths["edit"][action["method"].lower()].append(action["endpoint"])
        response, status_code = set_service_store_secret("opa", key="paths", value=json.dumps(paths_response))

    # write the service into its own store:
    response, status_code = set_service_store_secret("opa", key=f"services/{service_id}", value=json.dumps(service_dict))
    return response, status_code


def remove_service(service_id):
    # remove the service from the services index:
    response, status_code = get_service_store_secret("opa", key="services")
    if status_code == 200:
        services = response["services"]
        if service_id in services:
            services.remove(service_id)
        set_service_store_secret("opa", key="services", value=json.dumps(response))

    # remove the actions from the paths
    service_dict, status_code = get_service_store_secret("opa", key=f"services/{service_id}")
    paths_response, status_code = get_service_store_secret("opa", key="paths")
    if status_code == 200:
        paths = paths_response["paths"]
        # remove the actions:
        for action in service_dict["readable"]:
            if action["endpoint"] in paths["read"][action["method"].lower()]:
                paths["read"][action["method"].lower()].remove(action["endpoint"])
        for action in service_dict["editable"]:
            if action["endpoint"] in paths["edit"][action["method"].lower()]:
                paths["edit"][action["method"].lower()].remove(action["endpoint"])
        response, status_code = set_service_store_secret("opa", key="paths", value=json.dumps(paths_response))

    # remove the service's own store:
    response, status_code = delete_service_store_secret("opa", key=f"services/{service_id}")
    return response, status_code


######
# Vault service stores. Call these from within containers.
######

def get_vault_token_for_service(service=SERVICE_NAME, approle_token=None, role_id=None, secret_id=None):
    """
    Get this service's vault token. Should only be called from inside a container.
    """
    # if there is no SERVICE_NAME env var, something is wrong
    if service is None:
        raise AuthzError("no SERVICE_NAME specified")
    # in CanDIGv2 docker stack, approle token should have been passed in
    if approle_token is None:
        with open(APPROLE_TOKEN_FILE) as f:
            approle_token = f.read().strip()
    if approle_token is None:
        raise AuthzError("no approle token found")

    # in CanDIGv2 docker stack, roleid should have been passed in
    if role_id is None:
        try:
            with open(ROLE_ID_FILE) as f:
                role_id = f.read().strip()
        except Exception as e:
            raise AuthzError(str(e))
    if role_id is None:
        raise AuthzError("no role_id found")

    # get the secret_id
    if secret_id is None:
        url = f"{VAULT_URL}/v1/auth/approle/role/{service}/secret-id"
        headers = { "X-Vault-Token": approle_token }
        response = requests.post(url=url, headers=headers)
        if response.status_code == 200:
            secret_id = response.json()["data"]["secret_id"]
        else:
            raise AuthzError(f"secret_id: {response.text}")

        # swap the role_id and service_id for a token
        data = {
            "role_id": role_id,
            "secret_id": secret_id
        }
        url = f"{VAULT_URL}/v1/auth/approle/login"
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return response.json()["auth"]["client_token"]
        else:
            raise AuthzError(f"login: {response.text}")
    return None


def set_service_store_secret(service, key=None, value=None, role_id=None, secret_id=None, token=None):
    """
    Set a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = {
        "X-Vault-Token": token
    }
    url = f"{VAULT_URL}/v1/{service}/{key}"
    if "dict" in str(type(value)):
        value = json.dumps(value)
    response = requests.post(url, headers=headers, data=value)
    if response.status_code >= 200 and response.status_code < 300:
        return get_service_store_secret(service, key, token=token)
    return response.json(), response.status_code


def get_service_store_secret(service, key=None, role_id=None, secret_id=None, token=None):
    """
    Get a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = {
        "X-Vault-Token": token
    }
    url = f"{VAULT_URL}/v1/{service}/{key}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()["data"]
        return result, 200
    return {"error": response.text}, response.status_code


def delete_service_store_secret(service, key=None, role_id=None, secret_id=None, token=None):
    """
    Delete a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = {
        "X-Vault-Token": token
    }
    url = f"{VAULT_URL}/v1/{service}/{key}"
    response = requests.delete(url, headers=headers)
    return response.text, response.status_code


def get_user_record(comanage_id=None, oidcsub=None, force=False):
    if comanage_id is None and oidcsub is None:
        return {"error": "no user specified"}, 500

    user_index, status_code = get_service_store_secret("opa", key=f"users/index")
    # initialize the user index if it doesn't exist
    if status_code != 200:
        user_index = {}

    if comanage_id is None:
        if oidcsub in user_index:
            comanage_id = user_index[oidcsub]
        else:
            lookup_user, status_code = get_comanage_user(None, oidcsub=oidcsub)
            if status_code == 200:
                comanage_id = lookup_user["CoPerson"]["meta"]["id"]
            else:
                return lookup_user, status_code

    response, status_code = get_service_store_secret("opa", key=f"users/{comanage_id}")
    if status_code == 200 and not force:
        return response, status_code

    # either force re-create user or
    # this is a new user: set up the user and the index entry
    user = {"study_authorizations": {}}

    # set up identifiers
    response = requests.get(f"{PCGL_API_URL}/registry/identifiers.json", params={"copersonid": comanage_id}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
    if response.status_code == 200:
        for ident in response.json()["Identifiers"]:
            user[ident["Type"]] = ident["Identifier"]

    # set up email addresses
    emails = []
    response = requests.get(f"{PCGL_API_URL}/registry/email_addresses.json", params={"copersonid": comanage_id}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
    if response.status_code == 200:
        for email in response.json()["EmailAddresses"]:
            if email not in emails:
                emails.append(email["Mail"])
    user["emails"] = emails

    set_service_store_secret("opa", key=f"users/{comanage_id}", value=json.dumps(user))
    status_code = 201 # Created
    response = user

    # set entries in user index
    if "oidcsub" not in response:
        response = {"error": f"user {comanage_id} does not have an oidcsub"}
        status_code = 500
    else:
        oidcsub = response["oidcsub"]
        user_index[oidcsub] = str(comanage_id)
    if "pcglid" not in response:
        response = {"error": f"user {comanage_id} does not have an PCGL ID"}
        status_code = 500
    else:
        pcglid = response["pcglid"]
        user_index[pcglid] = str(comanage_id)

    for email in user["emails"]:
        if email not in user_index:
            user_index[email] = []
        if str(comanage_id) not in user_index[email]:
            user_index[email].append(str(comanage_id))

    set_service_store_secret("opa", key=f"users/index", value=json.dumps(user_index))

    return response, status_code


def get_comanage_user(request, token=None, oidcsub=None):
    if oidcsub is None:
        oidcsub = get_oidcsub(request, token=token)
    if oidcsub is not None:
        response = requests.get(f"{PCGL_API_URL}/api/co/{PCGL_COID}/core/v1/people", params={"identifier": oidcsub}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
        if response.status_code == 200:
            return response.json()[0], 200
        return response.text, response.status_code
    return {"error": "could not find oidcsub"}, 500


def get_comanage_groups():
    result = []
    response = requests.get(f"{PCGL_API_URL}/registry/co_groups.json", params={"coid": PCGL_COID}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
    if response.status_code == 200:
        for group in response.json()["CoGroups"]:
            new_group = {
                "id": group["Id"],
                "description": group["Description"],
                "members": []
            }
            response = requests.get(f"{PCGL_API_URL}/registry/co_group_members.json", params={"coid": PCGL_COID, "cogroupid": group["Id"]}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
            if response.status_code == 200:
                for member in response.json()["CoGroupMembers"]:
                    new_group["members"].append(str(member["Person"]["Id"]))
            result.append(new_group)
        data = {"ids": {}}
        for group in result:
            if group["description"] == "PCGL Administrators":
                data["ids"]["admin"] = str(group["id"])
                data["admin"] = group["members"]
            elif group["description"] == "PCGL Approvers":
                data["ids"]["curator"] = str(group["id"])
                data["curator"] = group["members"]
            elif group["description"] == "PCGL Members":
                data["ids"]["members"] = str(group["id"])
                data["members"] = group["members"]
        return data, 200
        set_service_store_secret("opa", key="groups", value=json.dumps(data))

    return response.text, response.status_code
