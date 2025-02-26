import os
import re
import requests
import jwt
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
        token = request.headers['Authorization']
        token = token.split(",")[0].strip()
        token = token.split()[1]
    if token is None:
        return None

    return token


######
# General authorization methods
######

def get_authorized_studies(request):
    """
    Get allowed study result from OPA
    Returns array of strings
    """

    token = get_auth_token(request)

    body = {
        "input": {
            "token": token,
            "body": {
                "method": request.method
            }
        }
    }
    if hasattr(request, 'path'):
        body["input"]["body"]["path"] = request.path
    elif hasattr(request, 'url'):
        body["input"]["body"]["path"] = request.url

    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        OPA_URL + "/v1/data/permissions",
        headers=headers,
        json=body
    )
    if response.status_code == 200:
        if "studies" in response.json()["result"]:
            return response.json()["result"]["studies"]

    return []


def is_site_admin(request, token=None):
    """
    Is the user associated with the token a site admin?
    Returns boolean.
    """
    if request is not None and "Authorization" in request.headers:
        token = get_auth_token(request)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        OPA_URL + "/v1/data/permissions",
        headers=headers,
        json={
            "input": {
                    "token": token
                }
            }
        )
    if response.status_code == 200:
        if 'site_admin' in response.json()["result"]:
            return response.json()["result"]["site_admin"]
    return False


def get_opa_permissions(bearer_token=None, user_token=None, method=None, path=None, study=None):
    token = get_auth_token(None, token=bearer_token)
    if user_token is None:
        user_token = token
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(
        OPA_URL + "/v1/data/permissions",
        headers=headers,
        json={
            "input": {
                    "token": user_token,
                    "body": {
                        "method": method,
                        "path": path,
                        "study": study
                    }
                }
            }
        )
    if response.status_code == 200:
        return response.json()["result"], 200
    return response.text, response.status_code

def is_action_allowed_for_study(token, method=None, path=None, study=None):
    """
    Is the user allowed to perform this action on this study?
    """

    response, status_code = get_opa_permissions(bearer_token=token, method=method, path=path, study=study)
    if status_code == 200:
        if 'allowed' in response:
            return response["allowed"]
    return False


def get_oidcsub(request, token=None):
    """
    Returns the OIDC sub (as defined in the sub claim of userinfo).
    """
    if token is None:
        if "Authorization" in request.headers:
            token = get_auth_token(request)
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

    # add the users to the preapproved user list
    for user_id in study_auth["team_members"]:
        # if the user isn't already approved, make sure they will be:
        response, status_code = add_preapproved_user(user_id)
    for user_id in study_auth["study_curators"]:
        # if the user isn't already approved, make sure they will be:
        response, status_code = add_preapproved_user(user_id)

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

    return response.text, response.status_code
