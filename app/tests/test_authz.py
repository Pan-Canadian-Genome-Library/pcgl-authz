import json
import os
import sys
import pytest
import requests
from datetime import date


TODAY = date.today()
THE_PAST = str(date(TODAY.year - 1, TODAY.month, TODAY.day))
THE_FUTURE = str(date(TODAY.year + 1, TODAY.month, TODAY.day))

# assumes that we are running pytest from the repo directory
REPO_DIR = os.path.abspath(f"{os.path.dirname(os.path.realpath(__file__))}/..")
sys.path.insert(0, os.path.abspath(f"{REPO_DIR}/src"))
import authz_operations
import auth


HOST = os.getenv("HOST", "http://flask:1235")

def test_setup_vault():
    # remove any extra stores:
    print(auth.delete_service_store_secret(service="test", key="services"))
    print(auth.delete_service_store_secret(service="test", key="services/*"))
    print(auth.delete_service_store_secret(service="test", key="studies"))
    print(auth.delete_service_store_secret(service="test", key="studies/*"))
    print(auth.delete_service_store_secret(service="test", key="paths"))
    print(auth.delete_service_store_secret(service="test", key="groups"))
    print(auth.delete_service_store_secret(service="test", key="users/*"))

    # check to see if that worked:
    paths, status_code = auth.get_service_store_secret(service="test", key="users/index")
    assert status_code == 404

    with open(f"{REPO_DIR}/config.json") as f:
        authz_service = json.load(f)["service"]
        authz_service["authorization"]["client_id"] = os.getenv("PCGL_CLIENT_ID")
        authz_service["authorization"]["client_secret"] = os.getenv("PCGL_CLIENT_SECRET")
        auth.add_service(authz_service, service="test")

    groups, status_code = auth.get_comanage_groups(service="test")
    assert status_code == 200


def test_setup_users(users):
    user_index, status_code = auth.get_service_store_secret(service="test", key="users/index")
    print(user_index, status_code)
    assert status_code == 404
    user_index = {}

    for user in users:
        r, s_c = auth.get_user_record(comanage_id=users[user]["comanage_id"], test_ids=users[user]["ids"], test_emails=users[user]["emails"], force=True, service="test")

    user_index, status_code = auth.get_service_store_secret(service="test", key="users/index")
    print(user_index)
    assert status_code == 200
    assert len(user_index) > 0

def test_add_service(service_uuid):
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    service_body = {
      "service_id": "test",
      "service_uuid": service_uuid,
      "authorization": {
        "client_id": "test",
        "client_secret": "test",
        "token_type": "access"
      },
      "editable": [
          {
            "method": "POST",
            "endpoint": "test/?.*"
          }
        ],
      "readable": [
        {
          "method": "GET",
          "endpoint": "test/?.*"
        }
      ]
    }
    response = requests.post(f"{HOST}/service", headers=headers, json=service_body)
    print(response.text)
    service_dict = response.json()
    assert "service_uuid" in service_dict
    assert service_dict["service_uuid"] == service_uuid
    assert "authorization" not in service_dict


def test_remove_service():
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    service_body = {
      "service_id": "remove_me",
      "service_uuid": "remove-me",
      "authorization": {
        "client_id": "test",
        "client_secret": "test",
        "token_type": "access"
      },
      "editable": [
          {
            "method": "POST",
            "endpoint": "remove/?.*"
          }
        ],
      "readable": [
        {
          "method": "GET",
          "endpoint": "remove/?.*"
        }
      ]
    }

    # add service
    response = requests.post(f"{HOST}/service", headers=headers, json=service_body)
    print(response.text)
    service_dict = response.json()
    assert "service_uuid" in service_dict

    # list services: should have three: authz, test, and remove_me
    response = requests.get(f"{HOST}/service", headers=headers)
    assert len(response.json()) == 3

    # remove remove_me
    response = requests.delete(f"{HOST}/service/remove_me", headers=headers)

    # list services: should have two: authz and test
    response = requests.get(f"{HOST}/service", headers=headers)
    print(response.text)
    assert len(response.json()) == 2


def get_service_token(service_uuid):
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    response = requests.post(f"{HOST}/service/test/verify", headers=headers, json={"service_uuid": service_uuid})
    service_token = response.json()["token"]
    return service_token


def test_service_token(service_uuid):
    headers = {
        "Authorization": f"Bearer user2",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    # if there is no service provided, this won't work
    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert response.status_code == 403

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    # if there is a service provided, should work
    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert response.status_code == 200

    # if there is an invalid service provided, this won't work
    headers["X-Service-Id"] = "testtest"

    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert response.status_code == 403

    # if there is an invalid service token provided, this won't work
    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = "notatoken"

    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert response.status_code == 403


def test_reload(service_uuid):
    headers = {
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    # check that reload works with only service token:
    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    response = requests.post(f"{HOST}/reload", headers=headers)
    print(response.text)
    assert response.status_code == 200

    # if the service token is wrong, should be forbidden
    headers["X-Service-Token"] = "notatoken"

    response = requests.post(f"{HOST}/reload", headers=headers)
    print(response.text)
    assert response.status_code == 403

    # if the service isn't valid, should be forbidden
    headers["X-Service-Id"] = "testtest"

    response = requests.post(f"{HOST}/reload", headers=headers)
    print(response.text)
    assert response.status_code == 403


def test_add_studies(studies, service_uuid):
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }
    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    for study in studies:
        response = requests.post(f"{HOST}/study", headers=headers, json=studies[study])
        print(response.text)
        assert response.status_code == 200

    response = requests.get(f"{HOST}/study", headers=headers)
    print(response.text)
    assert len(response.json()) == len(studies)

    headers = {
        "Authorization": f"Bearer data_admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    response = requests.get(f"{HOST}/study", headers=headers)
    print(response.text)
    assert len(response.json()) == len(studies)


def test_remove_study(studies, service_uuid):
    headers = {
        "Authorization": f"Bearer data_admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }
    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    study = "SYNTHETIC-0"
    response = requests.delete(f"{HOST}/study/{study}", headers=headers)
    print(response.text)
    assert response.status_code == 200

    response = requests.get(f"{HOST}/study", headers=headers)
    print(response.text)
    assert len(response.json()) == len(studies) - 1


def get_user_tests():
    return [
        (
            "admin"
        ),
        (
            "user2"
        )
    ]

@pytest.mark.parametrize('user', get_user_tests())
def test_get_users(service_uuid, users, user):
    headers = {
        "Authorization": f"Bearer {user}",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    # get their own info
    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert "userinfo" in response.json()
    assert response.json()["userinfo"]["emails"][0]["address"] == users[user]["emails"][0]["Mail"]

    # get a user's info
    response = requests.get(f"{HOST}/user/{user}", headers=headers)
    print(response.text)
    assert "userinfo" in response.json()
    assert response.json()["userinfo"]["emails"][0]["address"] == users[user]["emails"][0]["Mail"]


def test_admin_user(users):
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    # get their own info
    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    assert "userinfo" in response.json()
    assert response.json()["userinfo"]["emails"][0]["address"] == users["admin"]["emails"][0]["Mail"]


def get_dacs():
    return [
        ("user1",
            [
                {
                    "study_id": "SYNTHETIC-1",
                    "user_emails": ["user1@test.ca"],
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        ),
        ("user2",
            [
                {
                    "study_id": "SYNTHETIC-1",
                    "user_emails": ["user2@test.ca"],
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                },
                {
                    "study_id": "SYNTHETIC-4",
                    "user_emails": ["user2@test.ca"],
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        ),
        ("user3",
            [
                { # this study is already OVER
                    "study_id": "SYNTHETIC-1",
                    "user_emails": ["user3@test.ca"],
                    "start_date": THE_PAST,
                    "end_date": THE_PAST
                },
                {
                    "study_id": "SYNTHETIC-4",
                    "user_emails": ["user3@test.ca"],
                    "start_date": THE_PAST,
                    "end_date": THE_FUTURE
                }
            ]
        )
    ]


@pytest.mark.parametrize('user, input', get_dacs())
def test_add_dacs(user, input, service_uuid):
    headers = {
        "Authorization": f"Bearer {user}",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    pcglid = response.json()["userinfo"]["pcgl_id"]

    headers["Authorization"] = f"Bearer admin"
    for study in input:
        study_id = study.pop("study_id")
        response = requests.post(f"{HOST}/study/{study_id}/dac_authorizations", headers=headers, json=study)
        study["study_id"] = study_id
        print(response.text)
        assert response.status_code == 200

    headers["Authorization"] = f"Bearer {user}"
    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    for study in input:
        if TODAY >= date.fromisoformat(study["start_date"]) and TODAY <= date.fromisoformat(study["end_date"]):
            assert study["study_id"] in response.json()["study_authorizations"]["readable_studies"]


def test_add_potential_user():
    headers = {
        "Authorization": f"Bearer admin",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    # this user doesn't exist yet:
    response = requests.get(f"{HOST}/user/lookup", params={"email": "newuser@test.ca"}, headers=headers)
    print(response.text)
    assert response.status_code == 404

    study = {
        "study_id": "SYNTHETIC-4",
        "user_emails": ["newuser@test.ca"],
        "start_date": THE_PAST,
        "end_date": THE_FUTURE
    }
    study_id = study.pop("study_id")
    response = requests.post(f"{HOST}/study/{study_id}/dac_authorizations", headers=headers, json=study)
    study["study_id"] = study_id
    print(response.text)
    assert response.status_code == 200

    new_comanage_user = {
        "comanage_id": "005",
        "ids": [
            {
                "Identifier": "user5",
                "Type": "oidcsub"
            },
            {
                "Identifier": "PCGLuser5",
                "Type": "pcglid"
            }
        ],
        "emails": [
            {
                "Mail": "newuser@test.ca",
                "Type": "official",
                "Verified": True
            }
        ],
        "study_authorizations": {}
    }

    auth.get_user_record(comanage_id=new_comanage_user["comanage_id"], test_ids=new_comanage_user["ids"], test_emails=new_comanage_user["emails"], service="test")

    # this user should exist now:
    response = requests.get(f"{HOST}/user/lookup", params={"email": "newuser@test.ca"}, headers=headers)
    print(response.text)
    assert response.status_code == 200


def get_user_studies():
    return [
        (  # site admin should be able to read all studies
            "admin",
            {"endpoint": "test/study", "method": "GET"},
            ["SYNTHETIC-1", "SYNTHETIC-2", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user1 can view the studies it's a member of
            "user1",
            {"endpoint": "test/study", "method": "GET"},
            ["SYNTHETIC-1", "SYNTHETIC-3", "SYNTHETIC-4"],
        ),
        (  # user3 can view the studies it's a member of + DAC studies,
            # but SYNTHETIC-1's authorized dates are in the past
            "user3",
            {"endpoint": "test/study", "method": "GET"},
            ["SYNTHETIC-3", "SYNTHETIC-4"],
        )
    ]


@pytest.mark.parametrize('user, input, expected_result', get_user_studies())
def test_user_studies(user, input, expected_result, service_uuid):
    headers = {
        "Authorization": f"Bearer {user}",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    body = {
        "action": input,
        "studies": expected_result
    }

    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    response = requests.post(f"{HOST}/allowed", headers=headers, json=body)
    print(response.text)
    for i in range(len(expected_result)):
        assert response.json()[i] == True


def test_remove_dac(service_uuid):
    headers = {
        "Authorization": f"Bearer user2",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    response = requests.get(f"{HOST}/user/me", headers=headers)
    print(response.text)
    pcglid = response.json()["userinfo"]["pcgl_id"]

    headers["Authorization"] = f"Bearer admin"
    body = {"user_emails": ["user2@test.ca"]}
    response = requests.delete(f"{HOST}/study/SYNTHETIC-1/dac_authorizations", headers=headers, json=body)

    print(response.text)

    response = requests.get(f"{HOST}/user/{pcglid}", headers=headers)
    print(response.text)
    assert "SYNTHETIC-1" not in response.json()["study_authorizations"]["readable_studies"]


def get_dac_authz_access():
    # SYNTHETIC-2 is assigned the dac_id "PCGLDA0002"
    return [
        # user2 is a chair for PCGLDA0002, so can add a user to the DAC list for SYNTHETIC-2
        ("user2", "PCGL:DACO:CHAIR:PCGLDA0002", "SYNTHETIC-2", True, True),
        # SYNTHETIC-3 doesn't have a DAC, so user2 cannot add a user to the DAC list for SYNTHETIC-3
        ("user2", "PCGL:DACO:CHAIR:PCGLDA0002", "SYNTHETIC-3", False, False),
        # user1 is a member for PCGLDA0002, so can view the DAC list for SYNTHETIC-2, but cannot add
        ("user1", "PCGL:DACO:MEMBER:PCGLDA0002", "SYNTHETIC-2", True, False),
        # user3 has no DAC memberships, so cannot view any DACs for SYNTHETIC-2
        ("user3", "", "SYNTHETIC-2", False, False)
    ]


@pytest.mark.parametrize('user, daco_group, study_id, can_view, can_add', get_dac_authz_access())
def test_dac_access(user, daco_group, study_id, can_view, can_add, service_uuid, users):
    headers = {
        "Authorization": f"Bearer {user}~{daco_group}",
        "X-Test-Mode": os.getenv("TEST_KEY")
    }

    headers["X-Service-Id"] = "test"
    headers["X-Service-Token"] = get_service_token(service_uuid)

    study = {
        "study_id": study_id,
        "user_emails": ["user8@test.ca"],
        "start_date": THE_PAST,
        "end_date": THE_FUTURE
    }
    response = requests.post(f"{HOST}/study/{study_id}/dac_authorizations", headers=headers, json=study)
    print(response.text)
    assert (response.status_code == 200) == can_add

    response = requests.get(f"{HOST}/study/{study_id}/dac_authorizations", headers=headers)
    print(response.text)
    assert (response.status_code == 200) == can_view


####
# Fixtures
####

@pytest.fixture
def service_uuid():
    return "test-serv-uuid"


@pytest.fixture
def users():
    return {
        "admin": {
            "comanage_id": "000",
            "ids": [
                {
                    "Identifier": "admin",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser0",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "admin@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        },
        "data-admin": {
            "comanage_id": "111",
            "ids": [
                {
                    "Identifier": "data_admin",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser10",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "data-admin@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        },
        "user1": {
            "comanage_id": "001",
            "ids": [
                {
                    "Identifier": "user1",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser1",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "user1@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        },
        "user2": {
            "comanage_id": "002",
            "ids": [
                {
                    "Identifier": "user2",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser2",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "user2@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        },
        "user3": {
            "comanage_id": "003",
            "ids": [
                {
                    "Identifier": "user3",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser3",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "user3@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        },
        "user4": {
            "comanage_id": "004",
            "ids": [
                {
                    "Identifier": "user4",
                    "Type": "oidcsub"
                },
                {
                    "Identifier": "PCGLuser4",
                    "Type": "pcglid"
                }
            ],
            "emails": [
                {
                    "Mail": "user4@test.ca",
                    "Type": "official",
                    "Verified": True
                }
            ],
            "study_authorizations": {}
        }
    }


@pytest.fixture
def studies():
    return {
      "SYNTHETIC-0": {
        "date_created": "2020-03-01",
        "data_submitters": [
            "PCGLuser4"
        ],
        "study_id": "SYNTHETIC-0",
        "team_members": [
            "PCGLuser1",
            "PCGLuser4"
        ]
      },
      "SYNTHETIC-1": {
        "date_created": "2020-01-01",
        "data_submitters": [
          "PCGLuser1"
        ],
        "study_id": "SYNTHETIC-1",
        "team_members": [
          "PCGLuser1"
        ]
      },
      "SYNTHETIC-2": {
        "date_created": "2020-03-01",
        "dac_id": "PCGLDA0002",
        "data_submitters": [
          "PCGLuser2"
        ],
        "study_id": "SYNTHETIC-2",
        "team_members": [
          "PCGLuser2"
        ]
      },
      "SYNTHETIC-3": {
        "date_created": "2020-03-01",
        "data_submitters": [
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
        "data_submitters": [
          "PCGLuser4"
        ],
        "study_id": "SYNTHETIC-4",
        "team_members": [
          "PCGLuser1",
          "PCGLuser4"
        ]
      }
    }
