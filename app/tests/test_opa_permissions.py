import json
import os
import re
import sys
import pytest
import subprocess
import tempfile
from datetime import date


TODAY = date.today()
THE_PAST = str(date(TODAY.year - 1, TODAY.month, TODAY.day))
THE_FUTURE = str(date(TODAY.year + 1, TODAY.month, TODAY.day))

# assumes that we are running pytest from the repo directory
REPO_DIR = os.path.abspath(f"{os.path.dirname(os.path.realpath(__file__))}/..")
DEFAULTS_DIR = f"{REPO_DIR}/defaults"
sys.path.insert(0, os.path.abspath(f"{REPO_DIR}"))

@pytest.fixture
def groups():
    return {
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


@pytest.fixture
def studies():
    return {
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


@pytest.fixture
def users():
    return {
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


def setup_vault(user, groups, users, studies):
    vault = {"vault": {}}
    vault["vault"]["study_auths"] = studies
    vault["vault"]["all_studies"] = list(studies.keys())
    vault["vault"]["groups"] = groups
    user_read_auth = users[user]
    if "study_authorizations" in user_read_auth:
        vault["vault"]["user_studies"] = user_read_auth["study_authorizations"]
        vault["vault"]["user_auth"] = {"status_code": 200}
        vault["vault"]["user_id"] = user
        vault["vault"]["user_pcglid"] = user_read_auth["pcglid"]
    else:
        vault["vault"]["user_studies"] = []
        vault["vault"]["user_auth"] = {"status_code": 403}
    with open(f"{DEFAULTS_DIR}/paths.json") as f:
        paths = json.load(f)
        vault["vault"]["paths"] = paths["paths"]
    return vault


def evaluate_opa(user, input, key, expected_result, groups, users, studies):
    args = [
        "./opa", "eval",
        "--data", "permissions_engine/authz.rego",
        "--data", "permissions_engine/calculate.rego",
        "--data", "permissions_engine/permissions.rego",
    ]
    vault = setup_vault(user, groups, users, studies)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as vault_fp:
        json.dump(vault, vault_fp)
        args.extend(["--data", vault_fp.name])
        vault_fp.close()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as idp_fp:
            idp = {"idp": {
                    "user_key": users[user]["oidcsub"],
                    "valid_token": True
                }
            }
            json.dump(idp, idp_fp)
            idp_fp.close()
            args.extend(["--data", idp_fp.name])
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as input_fp:
                json.dump(input, input_fp)
                input_fp.close()
                args.extend(["--input", input_fp.name])

                # finally, query arg:
                args.append("data.permissions")
                print(json.dumps(vault))
                print(json.dumps(idp))
                print(json.dumps({"input": input}))
                p = subprocess.run(args, stdout=subprocess.PIPE)
                r =  json.loads(p.stdout)
                result =r['result'][0]['expressions'][0]['value']
                print(result)
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
def test_site_admin(user, expected_result, groups, users, studies):
    evaluate_opa(user, {}, "site_admin", expected_result, groups, users, studies)


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
def test_user_studies(user, input, expected_result, groups, users, studies):
    evaluate_opa(user, input, "studies", expected_result, groups, users, studies)


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
def test_curation_allowed(user, input, expected_result, groups, users, studies):
    evaluate_opa(user, input, "allowed", expected_result, groups, users, studies)

