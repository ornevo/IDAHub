import unittest
import random
import string
import json
import requests


URL = "http://localhost"
LOGIN_URI = "/api/users/token"
SIGNUP_URI = "/api/users"
REQUEST_JOIN_URI = "/api/projects/{}/join-request"
UPDATE_REQUEST_URI = "/api/join-requests/{}"
GET_PENDING_REQUESTS_URI = "/api/users/{}/pending-requests"

IS_LOCALHOST = "localhost" in URL


TEST_MAIN_USER_CREDENTIALS = {
    "username": "TESTUSER",
    "password": "Q5u1zALdFTkL!",
    "id": "5dc1a29dad9b9a627f6d48e5" if not IS_LOCALHOST else '5dc1ba9e51bfc6125cf2be36'
}
TEST_SECOND_USER_CREDENTIALS = {
    "username": "SECONDARYTEST",
    "password": "Q5u1zALdFTkL!"
}
# Owned by TESTUSER
TEST_PUBLIC_PROJECT = {
    "name": "TEST PROJECT",
    "id": "5dc1a2cfad9b9a627f6d48e6" if (not IS_LOCALHOST) else '5dc1babd51bfc6125cf2be37'
}


# Helpers
def get_test_loggedin_session(credentials):
    '''
    returns a requests session already authenticated as test user
    '''
    s = requests.Session()
    resp = s.get(URL + LOGIN_URI, params=credentials)
    if resp.status_code != 200:
        return False
    token = get_response_body_safe(resp).get('token')
    if token == '' or not token:
        return False

    print("Logged in '" + credentials['username'] + "' user. Got token: " + token)
    s.headers.update({"Authorization": "Bearer " + token})
    return s

def create_tmp_user():
    '''
    Returns its credentials
    '''
    username = "test" + ''.join(random.choice(string.letters) for i in range(14))
    password = "1234"
    email = "test_{0}@gm.com".format(username)
    creds = {"username": username, "password": password, "email": email}
    resp = requests.post(URL + SIGNUP_URI, data=creds)
    if resp.status_code != 200:
        print("Error creating tmp user: " + str(resp.status_code) + ": " + resp.text)
        return None
    return creds

def get_response_body_safe(response):
    if not response:
        return None

    return (json.loads(response.text).get('body') or {})


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

    def test_admin_approval_privilage(self):
        '''
        This test makes sure only a project's admin is able to approve join requests
        '''
        # Admin user
        sess_admin = get_test_loggedin_session(TEST_MAIN_USER_CREDENTIALS)
        # other user
        tmp_user_creds = create_tmp_user()
        self.assertNotEqual(tmp_user_creds, None, "Failed to create temporary user")
        sess_other = get_test_loggedin_session(tmp_user_creds)

        if not sess_other or not sess_admin:
            self.assertTrue(False, msg="Error logging in")
        
        # Make a join request from the other user
        resp = sess_other.post(URL + REQUEST_JOIN_URI.format(TEST_PUBLIC_PROJECT['id']))
        if resp.status_code != 200:
            print()
            self.assertTrue(False, msg="Unable to send join request: " + str(resp.status_code) + ": " + resp.text)
        
        # Get request id
        resp = sess_admin.get(URL + GET_PENDING_REQUESTS_URI.format(TEST_MAIN_USER_CREDENTIALS['id']))
        self.assertEqual(resp.status_code, 200, msg="Unable to get pending join requests: bad status code " + str(resp.status_code) + ": " + resp.text)

        # Find the request we just sent
        pending_requests = get_response_body_safe(resp)
        if not pending_requests or type(pending_requests) != list:
            self.assertTrue(False, msg="Unable to get pending join requests: bad response")

        our_request = [rd for rd in pending_requests if
            ((rd or {}).get('requester') or {}).get('username') == tmp_user_creds.get('username')] or [ None ]
        if not our_request[-1] or not our_request[-1].get('id'):
            self.assertTrue(False, msg="Unable to get pending join request: missing from list")
        request_id = our_request[-1].get('id')

        print("Created join request with id " + request_id)

        # Try to approve from other user
        resp = sess_other.post(URL + UPDATE_REQUEST_URI.format(request_id), data=json.dumps({'approved': True}),
            headers={"Content-Type": "application/json;charset=utf-8"})
        self.assertNotEqual(resp.status_code, 200, "Failed: Success accepting our own join request")

        # For cleanup, dismiss the request.
        resp = sess_admin.post(URL + UPDATE_REQUEST_URI.format(request_id), data=json.dumps({'dismissed': True}),
            headers={"Content-Type": "application/json;charset=utf-8"})
        self.assertEqual(resp.status_code, 200, "Failed in cleanup: " + str(resp.status_code) +  ": " + resp.text)


if __name__ == "__main__":
    unittest.main()    