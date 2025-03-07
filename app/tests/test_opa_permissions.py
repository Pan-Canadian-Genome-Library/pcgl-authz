import json
import os
import re
import sys
import pytest
import subprocess
import tempfile
import connexion
from datetime import date


TODAY = date.today()
THE_PAST = str(date(TODAY.year - 1, TODAY.month, TODAY.day))
THE_FUTURE = str(date(TODAY.year + 1, TODAY.month, TODAY.day))

# assumes that we are running pytest from the repo directory
REPO_DIR = os.path.abspath(f"{os.path.dirname(os.path.realpath(__file__))}/..")
DEFAULTS_DIR = f"{REPO_DIR}/defaults"
sys.path.insert(0, os.path.abspath(f"{REPO_DIR}/src"))
import authz_operations
import auth

GROUPS = {
  "admin": [
    "site_admin"
  ],
  "curator": [
    "user2"
  ],
  "member": [
    "user1",
    "user2",
    "other1"
  ]
}


STUDIES = {
  "SYNTHETIC-1": {
    "date_created": "2020-01-01",
    "study_curators": [
      "PCGLuser1"
    ],
    "study_id": "SYNTHETIC-1",
    "team_members": [
      "PCGLuser1"
    ]
  },
  "SYNTHETIC-2": {
    "date_created": "2020-03-01",
    "study_curators": [
      "PCGLuser2"
    ],
    "study_id": "SYNTHETIC-2",
    "team_members": [
      "PCGLuser2"
    ]
  },
  "SYNTHETIC-3": {
    "date_created": "2020-03-01",
    "study_curators": [
      "PCGLuser1",
      "PCGLuser3"
    ],
    "study_id": "SYNTHETIC-3",
    "team_members": [
      "PCGLuser1",
      "PCGLuser2",
      "PCGLuser3"
    ]
  },
  "SYNTHETIC-4": {
    "date_created": "2020-03-01",
    "study_curators": [
      "PCGLuser4"
    ],
    "study_id": "SYNTHETIC-4",
    "team_members": [
      "PCGLuser1",
      "PCGLuser4"
    ]
  }
}


USERS = {
    "user1": {
        # user1 is curator for SYNTHETIC-1, SYNTHETIC-3
        # user1 is member of SYNTHETIC-1, SYNTHETIC-3, SYNTHETIC-4
        "emails": [
            "user1@test.ca"
        ],
        "oidcsub": "http://cilogon.org/serverF/users/user1",
        "pcglid": "PCGLuser1",
        "study_authorizations": {
            "SYNTHETIC-1": {
                "study_id": "SYNTHETIC-1",
                "start_date": THE_PAST,
                "end_date": THE_FUTURE
            }
        }
    },
    "user2": {
        # user2 is curator for SYNTHETIC-2
        # user2 is member of SYNTHETIC-2, SYNTHETIC-3
        "emails": [
            "user2@test.ca"
        ],
        "oidcsub": "http://cilogon.org/serverF/users/user2",
        "pcglid": "PCGLuser2",
        "study_authorizations": {
            "SYNTHETIC-1": {
                "study_id": "SYNTHETIC-1",
                "start_date": THE_PAST,
                "end_date": THE_FUTURE
            },
            "SYNTHETIC-4": {
                "study_id": "SYNTHETIC-4",
                "start_date": THE_PAST,
                "end_date": THE_FUTURE
            }
        }
    },
    "user3": {
        # user3 is curator for SYNTHETIC-3
        # user3 is member of SYNTHETIC-3
        "emails": [
            "user3@test.ca"
        ],
        "oidcsub": "http://cilogon.org/serverF/users/user3",
        "pcglid": "PCGLuser3",
        "study_authorizations": {
            "SYNTHETIC-1":{ # this study is already OVER
                "study_id": "SYNTHETIC-1",
                "start_date": THE_PAST,
                "end_date": THE_PAST
            },
            "SYNTHETIC-4": {
                "study_id": "SYNTHETIC-4",
                "start_date": THE_PAST,
                "end_date": THE_FUTURE
            }
        }
    },
    "dac_user": {
        "emails": [
            "dac_user@test.ca"
        ],
        "oidcsub": "http://cilogon.org/serverF/users/dac_user",
        "pcglid": "PCGLdac_user",
        "study_authorizations": {
            "SYNTHETIC-3":{
                "study_id": "SYNTHETIC-3",
                "start_date": THE_PAST,
                "end_date": THE_FUTURE
            }
        }
    },
    "site_admin": {
        "emails": [
            "site_admin@test.ca"
        ],
        "oidcsub": "http://cilogon.org/serverF/users/site_admin",
        "pcglid": "PCGLsite_admin",
        "study_authorizations": {
        }
    }
}


STORE = {}


class FakeRequest:
    def __init__(self, token, path=None, method=None, study=None, body=None):
        self.headers = {"Authorization": f"Bearer {token}"}
        self.path = path
        self.method = method
        self.study = study
        self.body = body

    @pytest.mark.asyncio
    async def json(self):
        return self.body


@pytest.fixture(autouse=True)
def vault():
    data = {"vault": {}}
    data["vault"]["study_auths"] = STUDIES
    data["vault"]["all_studies"] = list(STUDIES.keys())
    data["vault"]["groups"] = GROUPS
    with open(f"{DEFAULTS_DIR}/paths.json") as f:
        paths = json.load(f)
        STORE["paths"] = paths
        data["vault"]["paths"] = paths["paths"]
    return data


def permissions(*args, **kwargs):
    if "bearer_token" in kwargs:
        bearer_token = kwargs["bearer_token"]
    input_body = {
        "token": bearer_token,
        "body": {}
    }
    if "path" in kwargs:
        input_body["body"]["path"] = kwargs["path"]
    if "method" in kwargs:
        input_body["body"]["method"] = kwargs["method"]
    if "study" in kwargs:
        input_body["body"]["study"] = kwargs["study"]
    result = evaluate_opa(bearer_token, input_body)["permissions"]
    print(json.dumps(result, indent=2))
    return result, 200


@pytest.fixture(autouse=True)
def setup_service_store(monkeypatch):
    monkeypatch.setattr(auth, "get_opa_permissions", permissions)
    monkeypatch.setattr(auth, "get_service_store_secret", get_service_store_secret)
    monkeypatch.setattr(auth, "set_service_store_secret", set_service_store_secret)


def get_service_store_secret(*args, **kwargs):
    if kwargs["key"] not in STORE:
        return {"error": "error"}, 404
    return STORE[kwargs["key"]], 200


def set_service_store_secret(*args, **kwargs):
    STORE[kwargs["key"]] = json.loads(kwargs["value"])
    return STORE[kwargs["key"]], 200


def evaluate_opa(user, input, vault=None):
    args = [
        "./opa", "eval",
        "--data", "permissions_engine/authz.rego",
        "--data", "permissions_engine/calculate.rego",
        "--data", "permissions_engine/permissions.rego",
    ]
    vault = {"vault": {}}
    vault["vault"]["study_auths"] = STUDIES
    vault["vault"]["all_studies"] = list(STUDIES.keys())
    vault["vault"]["groups"] = GROUPS
    with open(f"{DEFAULTS_DIR}/paths.json") as f:
        paths = json.load(f)
        STORE["paths"] = paths
        vault["vault"]["paths"] = paths["paths"]

    user_read_auth = USERS[user]
    if "study_authorizations" in user_read_auth:
        vault["vault"]["user_studies"] = user_read_auth["study_authorizations"]
        vault["vault"]["user_auth"] = {"status_code": 200}
        vault["vault"]["user_id"] = user
        vault["vault"]["user_pcglid"] = user_read_auth["pcglid"]
    else:
        vault["vault"]["user_studies"] = []
        vault["vault"]["user_auth"] = {"status_code": 403}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as vault_fp:
        json.dump(vault, vault_fp)
        args.extend(["--data", vault_fp.name])
        vault_fp.close()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as idp_fp:
            idp = {"idp": {
                    "user_key": USERS[user]["oidcsub"],
                    "valid_token": True
                }
            }
            json.dump(idp, idp_fp)
            idp_fp.close()
            args.extend(["--data", idp_fp.name])
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fp:
                json.dump(input, fp)
                fp.close()
                args.extend(["--input", fp.name])

            # finally, query arg:
            args.append("data.permissions")
            p = subprocess.run(args, stdout=subprocess.PIPE)
            r =  json.loads(p.stdout)
            permissions =r['result'][0]['expressions'][0]['value']

            return {
                "vault": vault,
                "idp": idp,
                "permissions": permissions
            }

def evaluate_permissions(user, input, key, expected_result, vault):
    r = evaluate_opa(user, input)
    print(json.dumps(r))
    result = r["permissions"]
    if key in result:
        print(result[key])
        assert result[key] == expected_result
    else:
        assert expected_result == False


def get_site_admin_tests():
    return [
        ( # user1 is not a site admin
            "user1",
            False
        ),
        ( # site_admin is a site admin
            "site_admin",
            True
        )
    ]


@pytest.mark.parametrize('user, expected_result', get_site_admin_tests())
def test_site_admin(user, expected_result, vault):
    evaluate_permissions(user, {}, "site_admin", expected_result, vault)


def get_user_studies():
    return [
        (  # site admin should be able to read all studies
            "site_admin",
            {"body": {"path": "/authz/study", "method": "GET"}},
            ["SYNTHETIC-1", "SYNTHETIC-2", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user1 can view the studies it's a member of
            "user1",
            {"body": {"path": "/authz/study", "method": "GET"}},
            ["SYNTHETIC-1", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user3 can view the studies it's a member of + DAC studies,
            # but SYNTHETIC-1's authorized dates are in the past
            "user3",
            {"body": {"path": "/authz/study", "method": "GET"}},
            ["SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (
            "dac_user",
            {"body": {"path": "/authz/study", "method": "GET"}},
            ["SYNTHETIC-3"],
        ),
    ]


@pytest.mark.parametrize('user, input, expected_result', get_user_studies())
def test_user_studies(user, input, expected_result, vault):
    evaluate_permissions(user, input, "studies", expected_result, vault)


def get_curation_allowed():
    return [
        ( # site admin should be able to edit all studies
            "site_admin",
            {
                "body": {
                  "path": "/authz/study",
                  "method": "POST"
                }
            },
            True
        ),
        ( # user2 can edit the studies it's not a curator of because they're a site curator
            "user2",
            {
                "body": {
                  "path": "/authz/study",
                  "method": "POST",
                  "study": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 can edit the studies it's a curator of
            "user1",
            {
                "body": {
                  "path": "/authz/study",
                  "method": "POST",
                  "study": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 can edit the studies it's a curator of
            "user1",
            {
                "body": {
                  "path": "/authz/study",
                  "method": "DELETE",
                  "study": "SYNTHETIC-1"
                }
            },
            True
        ),
        ( # user1 cannot edit the studies it's not a curator of
            "user1",
            {
                "body": {
                  "path": "/authz/study",
                  "method": "POST",
                  "study": "SYNTHETIC-2"
                }
            },
            False
        )
    ]

@pytest.mark.parametrize('user, input, expected_result', get_curation_allowed())
def test_curation_allowed(user, input, expected_result, vault):
    evaluate_permissions(user, input, "allowed", expected_result, vault)


def test_groups(monkeypatch):
    monkeypatch.setattr(connexion, "request", FakeRequest("site_admin"))

    response, status_code = authz_operations.list_group("admin")
    print(response)
    assert len(response) == 0


@pytest.mark.asyncio
async def test_add_service(monkeypatch):
    body = {
      "readable": [],
      "editable": [
        {
          "method": "GET",
          "endpoint": "fake_service/?.*"
        }
      ],
      "service_id": "fake_service"
    }
    request = FakeRequest("site_admin", "/authz/services", "post", "synth1", body)

    monkeypatch.setattr(connexion, "request", request)
    response = await authz_operations.add_service()
    response, status_code = authz_operations.list_services()
    print(response)

    assert len(response) > 0

    response, status_code = authz_operations.get_service("fake_service")
    assert "service_id" in response
    assert response["service_id"] == "fake_service"


def test_remove_service(monkeypatch):
    monkeypatch.setattr(connexion, "request", FakeRequest("site_admin"))

    response, status_code = authz_operations.remove_service("fake_service")
    response, status_code = authz_operations.list_services()
    assert len(response) == 0
