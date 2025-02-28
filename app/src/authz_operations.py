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
    if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/group/{group_id}"):
        groups, status_code = auth.get_comanage_groups()
        if status_code == 200:
            result = []
            for comanage_id in groups[group_id]:
                user, status_code = auth.get_user_by_comanage_id(comanage_id)
                if status_code == 200:
                    if "pcglid" in user and user["pcglid"] not in result:
                        result.append(user["pcglid"])
            return result, 200
        return groups, status_code
    return {"error": "User is not authorized to list groups"}, 403


####
# Services
####

def list_services():
    if auth.is_site_admin(connexion.request):
        return auth.list_services()
    return {"error": "User is not authorized to list services"}, 403


async def add_service():
    service = await connexion.request.json()

    if auth.is_site_admin(connexion.request):
        return auth.add_service(service)
    return {"error": "User is not authorized to add services"}, 403


@app.route('/service/<path:service_id>')
def get_service(service_id):
    if auth.is_site_admin(connexion.request):
        return auth.get_service(service_id)
    return {"error": "User is not authorized to get services"}, 403


@app.route('/service/<path:service_id>')
def remove_service(service_id):
    if auth.is_site_admin(connexion.request):
        return auth.remove_service(service_id)
    return {"error": "User is not authorized to remove services"}, 403


####
# Study authorizations
####

def list_study_authorizations():
    if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/study"):
        response, status_code = auth.list_studies()
        return response, status_code
    return {"error": "User is not authorized to list studies"}, 403


async def add_study_authorization():
    study = await connexion.request.json()

    if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/study"):
        response, status_code = auth.add_study(study)
        return response, status_code
    return {"error": "User is not authorized to add studies"}, 403


@app.route('/study/<path:study_id>')
def get_study_authorization(study_id):
    if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/study/{study_id}", study=study_id):
        response, status_code = auth.get_study(study_id)
        return response, status_code
    return {"error": "User is not authorized to get studies"}, 403


@app.route('/study/<path:study_id>')
def remove_study_authorization(study_id):
    if auth.is_action_allowed_for_study(connexion.request, method="DELETE", path=f"/study/{study_id}", study=study_id):
        response, status_code = auth.remove_study(study_id)
        return response, 200
    return {"error": "User is not authorized to remove studies"}, 403


####
# DAC authorization for users
####

@app.route('/user/<path:user_id>/study')
def list_studies_for_user(user_id):
    if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/user/{user_id}/study"):
        user_dict, status_code = auth.get_user_by_pcglid(user_id)
        if status_code == 200:
            return list(user_dict["study_authorizations"].values()), status_code
        return user_dict, status_code
    return {"error": "User is not authorized to list studies"}, 403


@app.route('/user/<path:user_id>/study')
async def authorize_study_for_user(user_id):
    study_dict = await connexion.request.json()
    if auth.is_action_allowed_for_study(connexion.request, method="POST", path=f"/user/{user_id}/study", study=study_dict["study_id"]):
        # we need to check to see if the study even exists in the system
        all_studies, status_code = auth.list_studies()
        if status_code != 200:
            return all_studies, status_code
        if study_dict["study_id"] not in all_studies:
            return {"error": f"Study {study_dict['study_id']} does not exist in {all_studies}"}

        user_dict, status_code = auth.get_user_by_pcglid(user_id)
        if status_code == 200:
            user_dict["study_authorizations"][study_dict["study_id"]] = study_dict
            response, status_code = auth.write_user(user_dict)
            if status_code == 200:
                return list(response["study_authorizations"].values()), 200
            return response, status_code
        return user_dict, status_code
    return {"error": "User is not authorized to authorize studies"}, 403


@app.route('/user/<path:user_id>/study/<path:study_id>')
def get_study_for_user(user_id, study_id):
    if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/user/{user_id}/study/{study_id}", study=study_id):
        user_dict, status_code = auth.get_user_by_pcglid(user_id)
        if status_code != 200:
            return user_dict, status_code
        for p in user_dict["study_authorizations"]:
            if p == study_id:
                return user_dict["study_authorizations"][p], 200
        return {"error": f"No study {study_id} found for user"}, status_code
    return {"error": "User is not authorized to get studies"}, 403


@app.route('/user/<path:user_id>/study/<path:study_id>')
def remove_study_for_user(user_id, study_id):
    if auth.is_action_allowed_for_study(connexion.request, method="DELETE", path=f"/user/{user_id}/study/{study_id}", study=study_id):
        user_dict, status_code = auth.get_user_by_pcglid(user_id)
        if status_code != 200:
            return user_dict, status_code
        for p in user_dict["study_authorizations"]:
            if p == study_id:
                user_dict["study_authorizations"].pop(study_id)
                response, status_code = auth.write_user(user_dict)
                return list(response["study_authorizations"].values()), status_code
        return {"error": f"No study {study_id} found for user"}, status_code
    return {"error": "User is not authorized to delete studies"}, 403


def lookup_user(email=None):
    if auth.is_action_allowed_for_study(connexion.request, method="GET", path=f"/user"):
        result = []
        users, status_code = auth.lookup_user_by_email(email)
        if status_code == 200:
            for user in users:
                # only add users that have a pcgl id:
                if "pcglid" in user:
                    result.append(user["pcglid"])
        return result, status_code
    return {"error": "User is not authorized to look up users"}, 403


async def is_allowed():
    action_dict = await connexion.request.json()
    if "studies" in action_dict:
        result = []
        for study_id in action_dict["studies"]:
            result.append(auth.is_action_allowed_for_study(connexion.request, method=action_dict["method"], path=action_dict["path"], study=study_id))
        return result, 200
    else:
        return auth.is_action_allowed_for_study(connexion.request, method=action_dict["method"], path=action_dict["path"]), 200
