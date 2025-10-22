import os
import requests
import json
import uuid
from connexion.context import context
import connexion


## Env vars for most auth methods:
OPA_URL = os.getenv('OPA_URL', "http://localhost:8181")
VAULT_URL = os.getenv('VAULT_URL', "http://localhost:8200")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", "")
SERVICE_NAME = os.getenv("SERVICE_NAME")
APPROLE_TOKEN_FILE = os.getenv("APPROLE_TOKEN_FILE", "/home/pcgl/approle-token")
VERIFY_ROLE_ID_FILE = "/home/pcgl/verify-roleid"
PCGL_COID = os.getenv("PCGL_COID", "")
PCGL_CORE_API_USER = os.getenv("PCGL_CORE_API_USER", "")
PCGL_CORE_API_KEY = os.getenv("PCGL_CORE_API_KEY", "")
PCGL_API_URL = os.getenv("PCGL_API_URL", "")
PCGL_ISSUER = os.getenv("PCGL_ISSUER", None)
PCGL_CLIENT_ID = os.getenv("PCGL_CLIENT_ID", None)
PCGL_CLIENT_SECRET = os.getenv("PCGL_CLIENT_SECRET", None)
PCGL_ADMIN_GROUP = os.getenv("PCGL_ADMIN_GROUP", "CO:admins")
PCGL_MEMBER_GROUP = os.getenv("PCGL_MEMBER_GROUP", "CO:members:active")
PCGL_CURATOR_GROUP = os.getenv("PCGL_CURATOR_GROUP", "PCGL:site_curators")

class AuthzError(Exception):
    pass

class ServiceHeadersError(AuthzError):
    pass

class NoServiceFoundError(AuthzError):
    pass

class ServiceTokenError(AuthzError):
    pass

class UserTokenError(AuthzError):
    pass

class UserServiceMismatchError(AuthzError):
    pass


def handle_token(token, request=None):
    try:
        access_token = token
        # set up testing: the token is the "name" and also the type of user we're testing
        service = SERVICE_NAME
        if "X-Test-Mode" in request.headers and request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
            service = "test"
            token_info = {
              "iss": "http://test.iss.com",
              "aud": "test",
              "groups": [
                PCGL_MEMBER_GROUP
              ]
            }
            token_info["sub"] = token
            if "admin" in token:
                token_info["groups"].append(PCGL_ADMIN_GROUP)
            return token_info
        if "X-Service-Id" in request.headers:
            service_dict, status_code = get_service(request.headers["X-Service-Id"], service=service)
            if "token_type" in service_dict["authorization"] and service_dict["authorization"]["token_type"] == "refresh":
                client_id = service_dict["authorization"]["client_id"]
                client_secret = service_dict["authorization"]["client_secret"]
                response = exchange_refresh_token(token, client_id=client_id, client_secret=client_secret)
                access_token = response["access_token"]

        response = requests.get(url="https://cilogon.org/oauth2/userinfo", params={"access_token": access_token}, allow_redirects=False)

        if response.status_code == 200:
            return response.json()
    except NoServiceFoundError as e:
        raise connexion.exceptions.Forbidden(str(e))
    except Exception as e:
        raise connexion.exceptions.Unauthorized(str(e))


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


def exchange_refresh_token(refresh_token, client_id=PCGL_CLIENT_ID, client_secret=PCGL_CLIENT_SECRET):
    """
    Gets a token from the keycloak server.
    """
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "offline_access+openid+profile+email+org.cilogon.userinfo"
    }

    response = requests.post(f"{PCGL_ISSUER}/oauth2/token", data=payload)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        raise UserTokenError(response.text)
    raise AuthzError(response.text)


def get_secret_file_value_or_env(file_path: str, env_var: str) -> str:
    """
    Tries to reads and return the value contained at `file_path` if it exists.\n
    Otherwise tries to read the value from the `env_var` environment variable if it exists.\n
    Raises an `AuthzError` if neither can be found.
    """
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            secret = f.read().strip()
        return secret
    if env_var:
        return os.getenv(env_var)
    raise AuthzError(f"Couldn't read the secret from the {file_path} path or the {env_var} env variable.")


def get_vault_namespace_header() -> dict:
    if VAULT_NAMESPACE:
        return {
            "X-Vault-Namespace": VAULT_NAMESPACE
        }
    return {}


def get_vault_headers(token: str) -> dict:
    """
    Returns authentication headers for Vault API HTTP requests.\n
    The `token` argument is passed to the `X-Vault-Token` header.\n
    If the `VAULT_NAMESPACE` env var is set, includes its value in the `X-Vault-Namespace` header.
    """
    return {
        "X-Vault-Token": token,
        **get_vault_namespace_header()
    }


######
# General authorization methods
######

def get_opa_permissions(request=None, user_pcglid=None, method=None, path=None, study=None, assume_site_admin=False):
    token = get_auth_token(request)
    headers = {
        "Authorization": f"Bearer {token}"
    }
    input = {
        "token": token,
        "body": {
            "token_info": context["token_info"],
            "method": method,
            "path": path
        }
    }
    if method is not None:
        input["body"]["method"] = method.upper()
    if study is not None:
        input["body"]["study"] = study
    if user_pcglid is not None:
        input["body"]["user_pcglid"] = user_pcglid
    service_namespace = SERVICE_NAME
    if "X-Test-Mode" in request.headers and request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service_namespace = "test"
        input["body"]["test"] = True
    response = requests.post(
        OPA_URL + "/v1/data/permissions",
        headers=headers,
        json={"input": input}
        )
    if response.status_code == 401:
        raise UserTokenError("User token is not valid")

    ### Authorization control: only registered users
    if response.status_code == 200:
        permissions = response.json()["result"]

        # if this request is to check for site admin, just return here
        if assume_site_admin:
            return permissions, 200

        # check to see if the request has the needed headers:
        try:
            if "X-Service-Id" not in request.headers:
                raise AuthzError("no service id in headers")

            if "X-Service-Token" not in request.headers:
                raise AuthzError("no service token in headers")
        except AuthzError as e:
            raise ServiceHeadersError(f"Service headers incorrect: {str(e)}")

        # check to see if this is from a registered service:
        service_dict, status_code = get_service(request.headers['X-Service-Id'], service=service_namespace)

        if not verify_service_token(service=request.headers['X-Service-Id'], token=request.headers['X-Service-Token'], service_uuid=service_dict["service_uuid"], service_namespace=service_namespace):
            raise ServiceTokenError("Service token is not valid")
        client_id = service_dict["authorization"]["client_id"]
        if "user_aud" in permissions and client_id == permissions["user_aud"]:
            return permissions, 200
        raise UserServiceMismatchError(f"user token not issued by {request.headers['X-Service-Id']}")

    return response.text, response.status_code


def get_authorized_studies(request):
    """
    Get studies authorized for the user.
    Returns array of strings
    """

    if hasattr(request, 'path'):
        path = request.path
    elif hasattr(request, 'url'):
        path = request.url

    response, status_code = get_opa_permissions(request=request, method=request.method, path=path, assume_site_admin=True)
    if status_code == 200:
        if "studies" in response:
            return response["studies"], 200

    return [], status_code


def is_site_admin(request):
    """
    Is the user associated with the token a site admin?
    Returns boolean.
    """
    response, status_code = get_opa_permissions(request=request, assume_site_admin=True)

    if status_code == 200:
        if 'site_admin' in response:
            return response["site_admin"]
    if status_code == 401:
        raise AuthzError("User token is invalid")
    return False


def is_action_allowed_for_study(request, method=None, path=None, study=None):
    """
    Is the user allowed to perform this action on this study?
    """
    response, status_code = get_opa_permissions(request=request, method=method, path=path, study=study, assume_site_admin=True)
    if status_code == 200:
        if 'allowed' in response:
            return response["allowed"]
    return False


#####
# Users
#####

def write_user(user_dict, service=SERVICE_NAME):
    if "id" in user_dict:
        comanage_id = user_dict.pop("id")
        response, status_code = set_service_store_secret(service, key=f"users/{comanage_id}", value=json.dumps(user_dict))
        if status_code != 200:
            response = {"error": f"User {comanage_id} was not found"}
    return response, status_code


def get_user_by_pcglid(pcglid, service=SERVICE_NAME):
    user_index, status_code = get_service_store_secret(service, key=f"users/index")
    if status_code == 200:
        if pcglid in user_index:
            user, status_code = get_service_store_secret(service, key=f"users/{user_index[pcglid]}")
            user["id"] = user_index[pcglid]
            return user, status_code
    return {"error": f"no user found for pcglid {pcglid}"}, 404


def get_user_by_comanage_id(comanage_id, service=SERVICE_NAME):
    return get_service_store_secret(service, key=f"users/{comanage_id}")


def get_self(service=SERVICE_NAME):
    oidcsub = context["user"]
    user_index, status_code = get_service_store_secret(service, key=f"users/index")
    if status_code == 200:
        if oidcsub in user_index:
            return get_service_store_secret(service, key=f"users/{user_index[oidcsub]}")
        # try to see if we can create this record:
        get_user_record(oidcsub=oidcsub, force=True, service=service)
    return {"error": f"could not find user {oidcsub}"}, 404


def lookup_user_by_email(email, service=SERVICE_NAME):
    user_index, status_code = get_service_store_secret(service, key=f"users/index")
    if status_code == 200:
        if email in user_index:
            result = []
            for comanage_id in user_index[email]:
                user, status_code = get_service_store_secret(service, key=f"users/{comanage_id}")
                if status_code == 200:
                    user["id"] = comanage_id
                    result.append(user)
            return result, 200
    return {"error": f"no user found for email {email}"}, 404


######
# Studies
######

def get_study(study_id, service=SERVICE_NAME):
    """
    Returns a StudyAuthorization for the study_id
    Authorized only if the service requesting it is allowed to see Opa's vault secrets.
    """
    response, status_code = get_service_store_secret(service, key=f"studies/{study_id}")
    if status_code < 300:
        return response[study_id], status_code
    return {"message": f"{study_id} not found"}, status_code


def list_studies(service=SERVICE_NAME):
    response, status_code = get_service_store_secret(service, key="studies")
    if status_code == 200:
        return response['studies'], status_code
    return response, status_code


def add_study(study_auth, service=SERVICE_NAME):
    """
    Creates or updates a StudyAuthorization in Opa's vault service store for the study_id.
    Authorized only if the requesting service is allowed to write Opa's vault secrets.
    """
    study_id = study_auth["study_id"]
    response, status_code = get_study(study_id, service=service)
    if status_code < 300 or status_code == 404:
        # create or update the study itself
        if "date_created" not in study_auth:
            from datetime import datetime
            study_auth["date_created"] = datetime.today().strftime('%Y-%m-%d')
        response, status_code = set_service_store_secret(service, key=f"studies/{study_id}", value=json.dumps({study_id: study_auth}))
        if status_code < 300:
            # update the values for the study list
            response2, status_code = get_service_store_secret(service, key="studies")

            if status_code == 200:
                # check to see if it's already here:
                if study_id not in response2['studies']:
                    response2['studies'].append(study_id)
            else:
                response2 = {'studies': [study_id]}
            response2, status_code = set_service_store_secret(service, key="studies", value=json.dumps(response2))
            return response, status_code

    return {"message": f"{study_id} not added"}, status_code


def remove_study(study_id, service=SERVICE_NAME):
    """
    Removes the StudyAuthorization in Opa's vault service store for the study_id.
    Authorized only if the requesting service is allowed to write Opa's vault service store.
    """
    response, status_code = get_study(study_id, service=service)
    if status_code == 404:
        return response, status_code
    if status_code < 300:
        # create or update the study itself
        response, status_code = delete_service_store_secret(service, key=f"studies/{study_id}")

        # update the values for the study list
        response, status_code = get_service_store_secret(service, key="studies")

        if status_code == 200:
            # check to see if it's here:
            if study_id in response['studies']:
                response['studies'].remove(study_id)
                response, status_code = set_service_store_secret(service, key="studies", value=json.dumps(response))

        return {"success": f"{study_id} removed"}, status_code
    return {"message": f"{study_id} not removed"}, status_code


######
# Services
######

def get_service(service_id, service=SERVICE_NAME):
    """
    Returns a Service for the service_id
    """
    response, status_code = get_service_store_secret(service, key=f"services/{service_id}")
    if status_code < 300:
        return response, status_code
    raise NoServiceFoundError(f"{service_id} not found")


def list_services(service=SERVICE_NAME):
    result = []
    response, status_code = get_service_store_secret(service, key="services")
    if status_code == 200:
        services = response["services"]
        for service_id in services:
            response, status_code = get_service_store_secret(service, key=f"services/{service_id}")
            if status_code == 200:
                result.append(response)
    return result, 200


def add_service(service_dict, request=None, service=SERVICE_NAME):
    service_id = service_dict["service_id"]

    updated_service = False
    # list the service in the services index:
    services = []
    response, status_code = get_service_store_secret(service, key="services")
    if status_code == 200:
        services = response["services"]
    if service_id not in services:
        services.append(service_id)
        if request is not None and "X-Test-Mode" not in request.headers:
            service_dict["service_uuid"] = str(uuid.uuid1())
    else:
        updated_service = True
    set_service_store_secret(service, key="services", value=json.dumps({"services": services}))

    # add the actions to the paths
    paths_response, status_code = get_service_store_secret(service, key="paths")
    if status_code == 200:
        paths = paths_response["paths"]
    else:
        # initialize paths dict:
        paths = {"read": {}, "edit": {}}
    # add the actions:
    for action in service_dict["readable"]:
        if action["method"].lower() not in paths["read"]:
            paths["read"][action["method"].lower()] = []
        if not updated_service:
            if action["endpoint"] in paths["read"][action["method"].lower()]:
                return {"error": f"endpoint {action["endpoint"]} is already registered"}, 500
        paths["read"][action["method"].lower()].append(action["endpoint"])
    for action in service_dict["editable"]:
        if action["method"].lower() not in paths["edit"]:
            paths["edit"][action["method"].lower()] = []
        if not updated_service:
            if action["endpoint"] in paths["edit"][action["method"].lower()]:
                return {"error": f"endpoint {action["endpoint"]} is already registered"}, 500
        paths["edit"][action["method"].lower()].append(action["endpoint"])
    response, status_code = set_service_store_secret(service, key="paths", value=json.dumps({"paths": paths}))

    # write the service into its own store:
    # if updating, get the uuid:
    if updated_service:
        response, status_code = get_service_store_secret(service, key=f"services/{service_id}")
        if status_code == 200:
            service_dict["service_uuid"] = response["service_uuid"]
    response, status_code = set_service_store_secret(service, key=f"services/{service_id}", value=json.dumps(service_dict))
    return response, status_code


def remove_service(service_id, service=SERVICE_NAME):
    # remove the service from the services index:
    response, status_code = get_service_store_secret(service, key="services")
    if status_code == 200:
        services = response["services"]
        if service_id in services:
            services.remove(service_id)
        set_service_store_secret(service, key="services", value=json.dumps(response))

    # remove the actions from the paths
    service_dict, status_code = get_service_store_secret(service, key=f"services/{service_id}")
    paths_response, status_code = get_service_store_secret(service, key="paths")
    if status_code == 200:
        paths = paths_response["paths"]
        # remove the actions:
        for action in service_dict["readable"]:
            if action["endpoint"] in paths["read"][action["method"].lower()]:
                paths["read"][action["method"].lower()].remove(action["endpoint"])
        for action in service_dict["editable"]:
            if action["endpoint"] in paths["edit"][action["method"].lower()]:
                paths["edit"][action["method"].lower()].remove(action["endpoint"])
        response, status_code = set_service_store_secret(service, key="paths", value=json.dumps(paths_response))

    # remove the service's own store:
    response, status_code = delete_service_store_secret(service, key=f"services/{service_id}")
    return response, status_code


def list_group(service=SERVICE_NAME):
    groups, status_code = get_service_store_secret(service, key="groups")
    if group_id in groups["ids"]:
        group_id = groups["ids"][group_id]
    if status_code == 200:
        result = []
        for comanage_id in groups["index"][group_id]["members"]:
            user, status_code = get_user_by_comanage_id(comanage_id, service=service)
            if status_code == 200:
                if "pcglid" in user and user["pcglid"] not in result:
                    result.append(user["pcglid"])
        return result, 200
    return groups, status_code


def list_authz_for_user(pcgl_id, service=SERVICE_NAME):
    if pcgl_id == "me":
        user_dict, status_code = get_self(service=service)
    else:
        user_dict, status_code = get_user_by_pcglid(pcgl_id, service=service)
    if status_code == 200:
        # sync with COManage:
        get_user_record(comanage_id=user_dict["comanage_id"], service=service)
        if "pcglid" not in user_dict:
            return {"error": "User not found in PCGL"}, 404
        result = {
            "userinfo": {
                "emails": user_dict["emails"],
                "pcgl_id": user_dict["pcglid"]
            },
            "study_authorizations": {
            },
            "dac_authorizations": list(user_dict["study_authorizations"].values())
        }
        permissions, status_code = get_opa_permissions(request=connexion.request, user_pcglid=user_dict["pcglid"], method=None, path=None, study=None)
        if status_code == 200:
            result["study_authorizations"]["editable_studies"] = permissions["editable_studies"]
            result["study_authorizations"]["readable_studies"] = permissions["readable_studies"]
            result["userinfo"]["site_admin"] = permissions["user_is_site_admin"]
            result["userinfo"]["site_curator"] = permissions["user_is_site_curator"]
        else:
            return permissions, status_code
        groups, status_code = get_groups_for_user(user_dict["comanage_id"], service=service)
        if status_code == 200:
            result["groups"] = groups
        return result, status_code



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
        approle_token = get_secret_file_value_or_env(APPROLE_TOKEN_FILE, "APPROLE_TOKEN")
    if approle_token is None:
        raise AuthzError("no approle token found")

    # in CanDIGv2 docker stack, roleid should have been passed in
    if role_id is None:
        try:
            role_id = get_secret_file_value_or_env(f"/home/pcgl/{service}-roleid", f"{service.upper()}-ROLEID")
        except Exception as e:
            raise AuthzError(str(e))
    if role_id is None:
        raise AuthzError("no role_id found")

    # get the secret_id
    if secret_id is None:
        url = f"{VAULT_URL}/v1/auth/approle/role/{service}/secret-id"
        headers = get_vault_headers(token=approle_token)
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
        response = requests.post(url, json=data, headers=get_vault_namespace_header())
        if response.status_code == 200:
            return response.json()["auth"]["client_token"]
        else:
            raise AuthzError(f"login: {response.text}")
    return None


def set_service_store_secret(service=SERVICE_NAME, key=None, value=None, role_id=None, secret_id=None, token=None):
    """
    Set a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(service=service, role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = get_vault_headers(token=token)
    url = f"{VAULT_URL}/v1/{service}/{key}"
    if "dict" in str(type(value)):
        value = json.dumps(value)
    response = requests.post(url, headers=headers, data=value)
    if response.status_code >= 200 and response.status_code < 300:
        return get_service_store_secret(service, key, token=token, role_id=role_id, secret_id=secret_id)
    return response.json(), response.status_code


def get_service_store_secret(service=SERVICE_NAME, key=None, role_id=None, secret_id=None, token=None):
    """
    Get a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(service=service, role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = get_vault_headers(token)
    url = f"{VAULT_URL}/v1/{service}/{key}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        result = response.json()["data"]
        return result, 200
    return {"error": response.text}, response.status_code


def delete_service_store_secret(service=SERVICE_NAME, key=None, role_id=None, secret_id=None, token=None):
    """
    Delete a Vault service store secret. Should only be called from inside a container.
    """
    if token is None:
        try:
            token = get_vault_token_for_service(service=service, role_id=role_id, secret_id=secret_id)
        except Exception as e:
            return {"error": str(e)}, 500
    if token is None:
        return {"error": f"could not obtain token for {service}"}, 400
    if key is None:
        return {"error": "no key specified"}, 400

    headers = get_vault_headers(token)
    url = f"{VAULT_URL}/v1/{service}/{key}"
    response = requests.delete(url, headers=headers)
    return response.text, response.status_code


def create_service_token(service_uuid):
    """
    Create a token that can be used to verify this service. Should only be called from inside a container.
    """
    # this will get us a fresh approle token for this service
    role_id = None
    try:
        role_id = get_secret_file_value_or_env(VERIFY_ROLE_ID_FILE, "VERIFY_ROLE_ID")
    except Exception as e:
        raise AuthzError(str(e))

    token = get_vault_token_for_service("verify", role_id=role_id)

    headers = get_vault_headers(token)

    # create the random service-token:
    url = f"{VAULT_URL}/v1/cubbyhole/{token}"
    try:
        response = requests.post(url, headers=headers, data={"service": service_uuid})
    except Exception as e:
        raise Exception(f"Could not create_service_token from {service_uuid}: {str(e)}")
    return str(token)


def verify_service_token(service=None, token=None, service_uuid=None, service_namespace=SERVICE_NAME):
    """
    Verify that a token comes from a particular service. Should only be called from inside a container.
    """
    if service is None:
        return False
    if token is None:
        return False
    body = {
        "input": {
            "token": token,
            "body": {
                "service": service_uuid
            }
        }
    }

    if service_uuid is None:
        service_dict, status_code = get_service(service, service=service_namespace)
        if status_code == 200:
            body["input"]["body"]["service"] = service_dict["service_uuid"]
    response = requests.post(
        OPA_URL + "/v1/data/service/verified",
        json=body
    )
    return response.status_code == 200 and "result" in response.json() and response.json()["result"]


######
# Comanage calls
######


def get_user_record(comanage_id=None, oidcsub=None, force=False, service=SERVICE_NAME):
    if comanage_id is None and oidcsub is None:
        return {"error": "no user specified"}, 500

    user_index, status_code = get_service_store_secret(service, key=f"users/index")
    # initialize the user index if it doesn't exist
    if status_code != 200:
        user_index = {}

    if comanage_id is None:
        if oidcsub in user_index:
            comanage_id = user_index[oidcsub]
        else:
            lookup_user, status_code = get_comanage_user(oidcsub=oidcsub)
            if status_code == 200:
                comanage_id = lookup_user["CoPerson"]["meta"]["id"]
            else:
                return lookup_user, status_code

    response, status_code = get_service_store_secret(service, key=f"users/{comanage_id}")
    if status_code == 200 and not force:
        if "pcglid" in response:
            return response, status_code

    # either force re-create user or
    # this is a new user: set up the user and the index entry
    user = {"study_authorizations": {}, "comanage_id": comanage_id}

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
            if email["Mail"] not in emails and email["Verified"]:
                emails.append({"address": email["Mail"], "type": email["Type"]})
    user["emails"] = emails

    set_service_store_secret(service, key=f"users/{comanage_id}", value=json.dumps(user))
    status_code = 201 # Created

    response = user
    errors = []
    # set entries in user index
    if "oidcsub" not in response:
        errors.append({"error": f"user {comanage_id} does not have an oidcsub"})
    else:
        oidcsub = response["oidcsub"]
        user_index[oidcsub] = str(comanage_id)
    if "pcglid" not in response:
        errors.append({"error": f"user {comanage_id} does not have an PCGL ID"})
    else:
        pcglid = response["pcglid"]
        user_index[pcglid] = str(comanage_id)

    for email in user["emails"]:
        email = email["address"]
        if email not in user_index:
            user_index[email] = []
        if str(comanage_id) not in user_index[email]:
            user_index[email].append(str(comanage_id))

    set_service_store_secret(service, key=f"users/index", value=json.dumps(user_index))

    if len(errors) > 0:
        return errors, 500

    if len(errors) > 0:
        return errors, 500

    return response, status_code


def get_groups_for_user(comanage_id, service=SERVICE_NAME):
    result = []
    groups, status_code = get_service_store_secret(service, key="groups")
    if status_code == 200:
        if "groups" in context["token_info"]:
            # if we have been passed in the groups in the token, this is a bit faster
            for group_name in context["token_info"]["groups"]:
                group_id = groups["ids"][group_name]
                group = groups["index"][group_id]
                group.pop("members")
                result.append(group)
        else:
            # if we don't already know the group names, we have to run through all the groups and look for this comanage_id
            for group_id in groups["index"]:
                group = groups["index"][str(group_id)]
                members = group.pop("members")
                if comanage_id in members:
                    result.append(group)
        return result, 200
    return groups, status_code


def get_comanage_user(oidcsub=None, service=SERVICE_NAME):
    oidcsub = context["user"]
    response = requests.get(f"{PCGL_API_URL}/registry/api/co/{PCGL_COID}/core/v1/people", params={"identifier": oidcsub}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
    if response.status_code == 200:
        return response.json()["0"], 200
    return response.text, response.status_code


def get_comanage_groups(service=SERVICE_NAME):
    result = []
    response = requests.get(f"{PCGL_API_URL}/registry/co_groups.json", params={"coid": PCGL_COID}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
    if response.status_code == 200:
        for group in response.json()["CoGroups"]:
            new_group = {
                "id": group["Id"],
                "description": group["Description"],
                "name": group["Name"],
                "members": []
            }
            response = requests.get(f"{PCGL_API_URL}/registry/co_group_members.json", params={"coid": PCGL_COID, "cogroupid": group["Id"]}, auth=(PCGL_CORE_API_USER, PCGL_CORE_API_KEY))
            if response.status_code == 200:
                for member in response.json()["CoGroupMembers"]:
                    new_group["members"].append(str(member["Person"]["Id"]))
            result.append(new_group)
        data = {"ids": {}, "index": {}}
        for group in result:
            data["ids"][group["name"]] = str(group["id"])
            data["index"][str(group["id"])] = group
            # special groups:
            if group["name"] == PCGL_ADMIN_GROUP:
                data["ids"]["admin"] = str(group["id"])
                data["admin"] = group["members"]
            elif group["name"] == PCGL_CURATOR_GROUP:
                data["ids"]["curator"] = str(group["id"])
                data["curator"] = group["members"]
            elif group["name"] == PCGL_MEMBER_GROUP:
                data["ids"]["members"] = str(group["id"])
                data["members"] = group["members"]
        set_service_store_secret(service, key="groups", value=json.dumps(data))
        return data, 200

    return response.text, response.status_code


def reload_comanage(service=SERVICE_NAME):
    cached_groups, status_code = get_service_store_secret(service, key="groups")
    if status_code != 200:
        cached_groups = {"members": [], "ids": {}, "index": {}}

    comanage_groups, status_code = get_comanage_groups(service=service)
    if status_code == 200:
        comanage_groups, status_code = set_service_store_secret(service, key="groups", value=json.dumps(comanage_groups))
    else:
        return {"error": f"failed to save groups: {comanage_groups}"}, status_code
    result = []
    # initialize new users:
    try:
        for member in reversed(comanage_groups["members"]):
            result.append(get_user_record(member, force=True, service=service))
    except Exception as e:
        return {"error": f"failed to save users: {type(e)} {str(e)}"}, status_code
    return {"message": result}, 200
