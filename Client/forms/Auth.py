from idaapi import Form, warning
import requests
import jwt
import json
import constants
import shared
import json

class AuthForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:iUserName}
BUTTON YES* Login
BUTTON CANCEL Cancel
Login form
{FormChangeCb}
<##Enter your username:{iUserName}>
<##Enter your password:{iPassword}>
{iResult}
""", {
            'FormChangeCb': Form.FormChangeCb(self.OnFormChange),
            'iUserName': Form.StringInput(tp=Form.FT_ASCII),
            'iPassword': Form.StringInput(tp=Form.FT_ASCII),
            "iResult": Form.StringLabel(tp=Form.FT_ASCII, value="", sz=1024)
        })
    def OnFormChange(self, fid):
        if fid == -2: # click on ok
            print "Clicked on login"
            user_token = try_to_log_in(self.GetControlValue(self.iUserName), self.GetControlValue(self.iPassword))
            if user_token == -1:
                warning("Error, invalid username and password {0} {1}".format(self.GetControlValue(self.iUserName), self.GetControlValue(self.iPassword)))
            else:
                try:
                    decoded_token = jwt.decode(user_token, constants.SERVER_PUBLIC_KEY, algorithms=["RS256"], audience=self.GetControlValue(self.iUserName))
                    shared.USERID = decoded_token["id"]
                    shared.USERNAME = decoded_token["username"]
                    shared.USER_TOKEN = user_token                                                                          
                except Exception as e:
                    warning("Problem with server signing!")
                    return 0
                return 1
        else:
            return 1

def try_to_log_in(username,password):
    try:
        try:
            content = requests.get("{0}{1}".format(shared.BASE_URL, constants.LOGIN_PATH), params={"username":username, "password": password}).content
        except Exception as e:
            warning("Cantconnect to server")
            return -1
        json_object = json.loads(content)
        if json_object["status"] != "OK":
            return -1
        return json_object["body"]["token"]
    except Exception as e:
        warning(str(e))
        return -1
