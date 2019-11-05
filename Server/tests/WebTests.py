import unittest
import random
import hashlib
import string
import requests
import json


def create_new_user(username, password):
    email = "test_{0}@gm.com".format(username)
    return requests.post("https://idahub.live/api/users", data={"username": str(username), "password": str(password), "email": email}   )

class TestWebAPI(unittest.TestCase):
    def test_create_username_with_same_name(self):
        username = "test" + ''.join(random.choice(string.letters) for i in range(4))
        password = "1234"
        self.assertEqual(create_new_user(username, password).status_code, 200)
        self.assertEqual(create_new_user(username, password).status_code, 500)

    def test_create_project_and_search(self):
        project_name = "testProject" + ''.join(random.choice(string.letters) for i in range(4))
        project_desc = "This is desc"
        project_hash = hashlib.sha256(project_name).hexdigest().upper()
        create_new_user("testUser", "1234")
        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": "testUser", "password": "1234"}).content)
        token_value = token["body"]["token"]
        headers = {"Authorization": "Bearer " + token_value}
        project_header = {"name": project_name, "description": project_desc, "contributors": [], "public": True, "hash": project_hash}
        self.assertEqual(requests.post("https://idahub.live/api/projects", json={"project-header": project_header}, headers=headers).status_code, 200)
        self.assertGreaterEqual(len(json.loads(requests.get("https://idahub.live/api/projects", headers = headers, params="query="+ project_name).content)["body"]["data"]), 1)

    def test_search_for_private_project(self):
        #Create 2 users, one is the private user, that creates the projects, and one is the public user, that is trying to search for the project.
        create_new_user("testUserPrivate","1234")
        create_new_user("testUserPublic","1234")
        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": "testUserPrivate", "password": "1234"}).content)
        token_value_private = token["body"]["token"]
        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": "testUserPublic", "password": "1234"}).content)
        token_value_public = token["body"]["token"]

        #Create the private project
        headers = {"Authorization": "Bearer " + token_value_private}
        project_name = "PrivateProject" + ''.join(random.choice(string.letters) for i in range(4))
        project_header = {"name": project_name, "description": "PrivateProject", "contributors": [], "public": False, "hash": hashlib.sha256(project_name).hexdigest()}
        requests.post("https://idahub.live/api/projects", json={"project-header": project_header}, headers=headers)

        headers = {"Authorization": "Bearer " + token_value_public}
        self.assertEqual(len(json.loads(requests.get("https://idahub.live/api/projects", headers = headers, params="query="+ project_name).content)["body"]["data"]), 0)
        
    def test_open_sessions(self):
        user_name_1 = "TestUser1" + ''.join(random.choice(string.letters) for i in range(4))
        user_name_2 = "TestUser2" + ''.join(random.choice(string.letters) for i in range(4))
        user_dict_1 = json.loads(create_new_user(user_name_1,"1234").content)["body"]
        user_dict_2 = json.loads(create_new_user(user_name_2,"1234").content)["body"]

        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": user_name_1, "password": "1234"}).content)
        token_value_user_1 = token["body"]["token"]
        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": user_name_2, "password": "1234"}).content)
        token_value_user_2 = token["body"]["token"]
        headers_user_1 = {"Authorization": "Bearer " + token_value_user_1}
        headers_user_2 = {"Authorization": "Bearer " + token_value_user_2}
        project_name = "SomeProjectForSession" + ''.join(random.choice(string.letters) for i in range(4))
        project_header = {"name": project_name, "description": "desc", "contributors": [{"username":user_dict_2["username"], "id": user_dict_2["id"]}], "public": True, "hash": hashlib.sha256(project_name).hexdigest()}
        create_project_request = requests.post("https://idahub.live/api/projects", json={"project-header": project_header}, headers=headers_user_1)
        self.assertEqual(create_project_request.status_code, 200)
        id_of_project = json.loads(create_project_request.content)["body"]["project-header"]["id"]

        # Check in login logout of 1 user
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/start",headers = headers_user_1)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 1)
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/stop",headers = headers_user_1)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 0)
        
        #Check in login logout of 2 users
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/start",headers = headers_user_1)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 1)
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/start",headers = headers_user_2)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 2)
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/stop",headers = headers_user_2)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 1)
        requests.post("https://idahub.live/api/projects/" + id_of_project + "/session/stop",headers = headers_user_1)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["onlineCount"], 0)
        
		
    def test_modification(self):
        #Create new user and new project for the test.
        user_name_1 = "1Mod" + ''.join(random.choice(string.letters) for i in range(4))
        create_new_user(user_name_1, "1234")
        token = json.loads(requests.get("https://idahub.live/api/users/token", params={"username": user_name_1, "password": "1234"}).content)
        token_value_user_1 = token["body"]["token"]
        headers_user_1 = {"Authorization": "Bearer " + token_value_user_1}
        project_name = "SomeProjectForModification" + ''.join(random.choice(string.letters) for i in range(4))
        project_header = {"name": project_name, "description": "desc", "contributors": [], "public": True, "hash": hashlib.sha256(project_name).hexdigest()}
        create_project_request = requests.post("https://idahub.live/api/projects", json={"project-header": project_header}, headers=headers_user_1)
        self.assertEqual(create_project_request.status_code, 200)
        id_of_project = json.loads(create_project_request.content)["body"]["project-header"]["id"]
        # Test 1 modification, the change comment.
        event_dict = {"event-id": 4, "linear-address": "10000", "value":"Hello", "projectId": id_of_project}
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["modifications"], 0)
        self.assertEqual(requests.post("https://idahub.live/api/projects/" + id_of_project + "/push",params={"projectId": id_of_project}, json = event_dict, headers = headers_user_1).status_code, 200)
        self.assertEqual(json.loads(requests.get("https://idahub.live/api/projects/" + id_of_project + "/statistics",headers = headers_user_1).content)["body"]["modifications"], 1)
		

if __name__ == "__main__":
    unittest.main()    