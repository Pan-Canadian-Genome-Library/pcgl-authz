import connexion
import os
import urllib.parse
import auth
import config
import json
import requests


app = connexion.AsyncApp(__name__)

def handle_token(token, request=None):
    return auth.handle_token(token, request)


# API endpoints
def get_service_info():
    return {
        "id": "org.pcgl.authz",
        "name": "PCGL Authorization Service",
        "description": "A microservice used to authorize access to data in PCGL",
        "organization": {
            "name": "Pan-Canadian Genome Library",
            "url": "https://genomelibrary.ca/"
        },
        "version": config.VERSION
    }


####
# Groups
####

@app.route('/group/<path:group_id>')
def list_group(group_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"authz/group/{group_id}", service=service):
            return auth.list_group()
        return {"error": "User is not authorized to list groups"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


####
# Services
####

def list_services():
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"

    try:
        if auth.is_site_admin(connexion.request):
            services, status_code = auth.list_services(service=service)
            if status_code == 200:
                for service in services:
                    if "service_uuid" in service:
                        service.pop("service_uuid")
                    if "authorization" in service:
                        service.pop("authorization")
            return services, status_code
        return {"error": "User is not authorized to list services"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


async def add_service():
    service_dict = await connexion.request.json()
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"

    try:
        if auth.is_site_admin(connexion.request):
            result, status_code = auth.add_service(service_dict, request=connexion.request, service=service)
            result.pop("authorization")
            return result, status_code
        return {"error": "User is not authorized to add services"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/service/<path:service_id>')
def get_service(service_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_site_admin(connexion.request):
            service, status_code = auth.get_service(service_id, service=service)
            if status_code < 300:
                service.pop("service_uuid")
                service.pop("authorization")
                return service, 200
        return {"error": "User is not authorized to get services"}, 403
    except auth.NoServiceFoundError as e:
        return {"error": f"{type(e)} {str(e)}"}, 404
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/service/<path:service_id>')
def remove_service(service_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_site_admin(connexion.request):
            return auth.remove_service(service_id, service=service)
        return {"error": "User is not authorized to remove services"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/service/<path:service_id>')
async def create_service_token(service_id):
    request_body = await connexion.request.json()
    service_uuid = request_body["service_uuid"]
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        service_dict, status_code = auth.get_service(service_id, service=service)
        if status_code == 200:
            if service_dict["service_uuid"] != service_uuid:
                return {"error": f"Service UUID does not match service name"}
            token = auth.create_service_token(service_uuid)
            return {"token": token}, 200
    except auth.NoServiceFoundError as e:
        return {"error": f"{type(e)} {str(e)}"}, 404
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/service/<path:service_id>')
def verify_service_token(service_id):
    try:
        if "X-Service-Token" in connexion.request.headers:
            return {"result": auth.verify_service_token(service_id, connexion.request.headers["X-Service-Token"])}
        return {"error": "no X-Service-Token present"}, 500
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


####
# Study authorizations
####

def list_study_authorizations():
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"authz/study"):
            response, status_code = auth.list_studies(service=service)
            return response, status_code
        return {"error": "User is not authorized to list studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


async def add_study_authorization():
    study = await connexion.request.json()
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/study"):
            response, status_code = auth.add_study(study, service=service)
            return response, status_code
        return {"error": "User is not authorized to add studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/study/<path:study_id>')
def get_study_authorization(study_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/study/{study_id}", study=study_id):
            response, status_code = auth.get_study(study_id, service=service)
            return response, status_code
        return {"error": "User is not authorized to get studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/study/<path:study_id>')
def remove_study_authorization(study_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="DELETE", path=f"/study/{study_id}", study=study_id):
            response, status_code = auth.remove_study(study_id, service=service)
            return response, 200
        return {"error": "User is not authorized to remove studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


####
# DAC authorization for users
####

@app.route('/user/<path:pcgl_id>')
def list_authz_for_user(pcgl_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        return auth.list_authz_for_user(pcgl_id, service=service)
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    return user_dict, status_code


@app.route('/user/<path:pcgl_id>')
async def authorize_study_for_user(pcgl_id):
    study_dict = await connexion.request.json()
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/user/{pcgl_id}", study=study_dict["study_id"]):
            # we need to check to see if the study even exists in the system
            all_studies, status_code = auth.list_studies(service=service)
            if status_code != 200:
                return all_studies, status_code
            if study_dict["study_id"] not in all_studies:
                return {"error": f"Study {study_dict['study_id']} does not exist in {all_studies}"}

            user_dict, status_code = auth.get_user_by_pcglid(pcgl_id, service=service)
            if status_code == 200:
                user_dict["study_authorizations"][study_dict["study_id"]] = study_dict
                response, status_code = auth.write_user(user_dict, service=service)
                if status_code == 200:
                    return list(response["study_authorizations"].values()), 200
                return response, status_code
            return user_dict, status_code
        return {"error": "User is not authorized to authorize studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/user/<path:pcgl_id>/study/<path:study_id>')
def get_study_for_user(pcgl_id, study_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/user/{pcgl_id}/study/{study_id}", study=study_id):
            user_dict, status_code = auth.get_user_by_pcglid(pcgl_id, service=service)
            if status_code != 200:
                return user_dict, status_code
            for p in user_dict["study_authorizations"]:
                if p == study_id:
                    return user_dict["study_authorizations"][p], 200
            return {"error": f"No study {study_id} found for user"}, status_code
        return {"error": "User is not authorized to get studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


@app.route('/user/<path:pcgl_id>/study/<path:study_id>')
def remove_study_for_user(pcgl_id, study_id):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="DELETE", path=f"/user/{pcgl_id}/study/{study_id}", study=study_id):
            user_dict, status_code = auth.get_user_by_pcglid(pcgl_id, service=service)
            if status_code != 200:
                return user_dict, status_code
            for p in user_dict["study_authorizations"]:
                if p == study_id:
                    user_dict["study_authorizations"].pop(study_id)
                    response, status_code = auth.write_user(user_dict, service=service)
                    return list(response["study_authorizations"].values()), status_code
            return {"error": f"No study {study_id} found for user"}, status_code
        return {"error": "User is not authorized to delete studies"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


def lookup_user(email=None):
    service = "opa"
    if "X-Test-Mode" in connexion.request.headers and connexion.request.headers["X-Test-Mode"] == os.getenv("TEST_KEY"):
        service = "test"
    try:
        if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/user"):
            result = []
            users, status_code = auth.lookup_user_by_email(email, service=service)
            if status_code == 200:
                for user in users:
                    # only add users that have a pcgl id:
                    if "pcglid" in user:
                        result.append(user["pcglid"])
            return result, status_code
        return {"error": "User is not authorized to look up users"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


async def is_allowed():
    action_dict = await connexion.request.json()
    try:
        if "studies" in action_dict:
            result = []
            for study_id in action_dict["studies"]:
                result.append(auth.is_action_allowed_for_study(connexion.request, method=action_dict["action"]["method"], path=action_dict["action"]["endpoint"], study=study_id))
            return result, 200
        else:
            return auth.is_action_allowed_for_study(connexion.request, action_dict["action"]["method"], path=action_dict["action"]["endpoint"]), 200
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500


async def reload_comanage():
    try:
        if not auth.is_site_admin(connexion.request):
            return {"error": "User is not authorized to reload COManage"}, 403
    except auth.UserTokenError as e:
        return {"error": f"{type(e)} {str(e)}"}, 401
    except auth.AuthzError as e:
        return {"error": f"{type(e)} {str(e)}"}, 403
    except Exception as e:
        return {"error": f"{type(e)} {str(e)}"}, 500
    result, status_code = auth.reload_comanage()
    print(result)
    return result, status_code
