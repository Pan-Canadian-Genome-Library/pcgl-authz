import connexion
from flask import Flask
import os
import re
import urllib.parse

import auth
import config
import uuid
import json


app = Flask(__name__)

def get_headers():
    headers = {}
    if "Authorization" not in connexion.request.headers:
        return {"error": "Bearer token required"}, 403
    if not connexion.request.headers["Authorization"].startswith("Bearer "):
        return {"error": "Invalid bearer token"}, 403
    token = connexion.request.headers["Authorization"].split("Bearer ")[1]
    headers["Authorization"] = "Bearer %s" % token
    headers["Content-Type"] = "application/json"
    return headers


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
    try:
        #if auth.is_site_admin(connexion.request):
        result, status_code = auth.get_comanage_groups()
        return result, status_code
        return {"error": "User is not authorized to list groups"}, 403
    except Exception as e:
        return {"error": str(e)}, 500


####
# Study authorizations
####

def list_study_authorizations():
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]

    response, status_code = auth.list_studies(token)
    return response, status_code


async def add_study_authorization():
    study = await connexion.request.json()
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]

    response, status_code = auth.add_study(study, token)
    check_default_site_admin(response)
    return response, status_code


@app.route('/study/<path:study_id>')
def get_study_authorization(study_id):
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]

    response, status_code = auth.get_study(study_id, token)
    return response, status_code


@app.route('/study/<path:study_id>')
def remove_study_authorization(study_id):
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]
    response = {"errors": {}}

    opa_response, opa_status = auth.remove_study(study_id, token)

    if opa_status == 404:
        # htsget status is not included here because it doesn't have a 404 response
        return {"message": f"Study {study_id} not found"}, 404

    if opa_status != 200:
        response["errors"]["opa"] = {"message": opa_response, "status_code": opa_status}

    if len(response["errors"]) == 0:
        response.pop("errors")
        response["message"] = f"Study {study_id} successfully deleted"
        return response, 200

    return response, 500


####
# DAC authorization for users
####

@app.route('/user/<path:user_id>/study')
def list_studies_for_user(user_id):
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]
    user_name = urllib.parse.unquote_plus(user_id)
    response, status_code = auth.get_user(user_name, token)
    if status_code != 200:
        return response, status_code
    print(response)
    return {"results": list(response["studies"].values())}, status_code


@app.route('/user/<path:user_id>/study')
async def authorize_study_for_user(user_id):
    study_dict = await connexion.request.json()
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]
    user_name = urllib.parse.unquote_plus(user_id)
    response, status_code = auth.get_user(user_name, token)
    if status_code != 200:
        return response, status_code

    # we need to check to see if the study even exists in the system
    all_studies, status_code = auth.list_studies(token)
    if status_code != 200:
        return all_studies, status_code
    if study_dict["study_id"] not in all_studies:
        return {"error": f"Study {study_dict['study_id']} does not exist in {all_studies}"}
    response["studies"][study_dict["study_id"]] = study_dict
    response, status_code = auth.write_user(response, token)
    return response, status_code


@app.route('/user/<path:user_id>/study/<path:study_id>')
def get_study_for_user(user_id, study_id):
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]
    user_name = urllib.parse.unquote_plus(user_id)

    response, status_code = auth.get_user(user_name, token)
    if status_code != 200:
        return response, status_code
    for p in response["studies"]:
        if p == study_id:
            return p, 200
    return {"error": f"No study {study_id} found for user"}, status_code


@app.route('/user/<path:user_id>/study/<path:study_id>')
def remove_study_for_user(user_id, study_id):
    token = connexion.request.headers['Authorization'].split("Bearer ")[1]
    user_name = urllib.parse.unquote_plus(user_id)

    response, status_code = auth.get_user(user_name, token)
    if status_code != 200:
        return response, status_code
    for p in response["studies"]:
        if p == study_id:
            response["studies"].pop(study_id)
            response, status_code = auth.write_user(response, token)
            return response, status_code
    return {"error": f"No study {study_id} found for user"}, status_code
