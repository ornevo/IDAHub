import unittest
import random
import string
import requests

class TestWebAPI(unittest.TestCase):
    def test_create_username_with_same_name(self):
        username = "test_" + ''.join(random.choice(string.letters) for i in range(4))
        password = "1234"
        email = "test_{0}@gm.com".format(username)
        self.assertEqual(requests.post("https://idahub.live/api/users", data={"username": username, "password": password, "email": email}).status_code, 200)
        self.assertEqual(requests.post("https://idahub.live/api/users", data={"username": username, "password": password, "email": email}).status_code, 500)

    def test_create_project_and_search(self):
        #Ignore this, WIP.
        project_name = "test_project_" + ''.join(random.choice(string.letters) for i in range(4))
        project_desc = "This is desc"
        project_hash = "123456"
        requests.post("https://idahub.live/api/users", data={"username": "test_user", "password": "1234", "email": "testMail@gam.com"})
        token = requests.get("https://idahub.live/api/users", data={"username": "test_user", "password": "1234"}).content

if __name__ == "__main__":
    unittest.main()    