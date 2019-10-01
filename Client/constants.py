import os
import win32api
import win32con
import struct
from array import array
import ctypes
import ctypes.wintypes
import pywintypes
import sys
import json

LOGIN_PATH = "api/users/token"
GET_PROJECT_CHANGES_PATH = "api/projects/{0}/changes"
PUSH_DATA_TO_PROJECT  = "api/projects/{0}/push"
LIST_USER_PROJECT = "api/users/{0}/projects"
START_SESSION = "api/projects/{0}/session/start"
END_SESSION = "api/projects/{0}/session/end"
PROJECT_DATA_FILE = "{0}\\IDAHub\\projects.dat".format(os.getenv("APPDATA"))
GENERAL_CONFIG_FILE = "{0}\\IDAHub\\config.cfg".format(os.getenv("APPDATA"))
SUBMODULE_KEY = "Software\\Hex-Rays\\IDA\\IPC\\Handler"
SERVER_PUBLIC_KEY_PATH = "{0}\\IDAHub\\key.pub".format(os.getenv("APPDATA"))
SERVER_PUBLIC_KEY = ""

with open(SERVER_PUBLIC_KEY_PATH, "r") as f:
	SERVER_PUBLIC_KEY = f.read()

context64bit = sys.maxsize > 2**32
if context64bit:
  class COPYDATASTRUCT(ctypes.Structure):
	_fields_ = [('dwData', ctypes.c_ulonglong),
	  ('cbData', ctypes.wintypes.DWORD),
	  ('lpData', ctypes.c_void_p)]
else:
  class COPYDATASTRUCT(ctypes.Structure):
	_fields_ = [('dwData', ctypes.wintypes.DWORD),
	  ('cbData', ctypes.wintypes.DWORD),
	  ('lpData', ctypes.c_void_p)]

PCOPYDATASTRUCT = ctypes.POINTER(COPYDATASTRUCT)
def send_data_to_window(window_handler, message_type, data):
	if data:
		buf = ctypes.create_string_buffer(data)
		cds = COPYDATASTRUCT()
		cds.dwData = 1337
		cds.cbData = buf._length_
		cds.lpData = ctypes.cast(buf, ctypes.c_void_p)
	else:
		cds = '1'
	win32api.SendMessage(int(window_handler), win32con.WM_COPYDATA, int(message_type), cds)


## Create path for the project config file
def create_config_file():
	if not os.path.exists(PROJECT_DATA_FILE):
		try:
			os.makedirs(os.path.dirname(PROJECT_DATA_FILE))
		except OSError as err:
			pass
		with open(PROJECT_DATA_FILE, 'w') as f:
			f.write(json.dumps({}))

## need to create general config file, the general config file is holding the Debug key, and the server key and the log key.
## Return True if file created, and false if not.
def create_general_config_file():
	if not os.path.exists(GENERAL_CONFIG_FILE):
		try:
			os.makedirs(os.path.dirname(GENERAL_CONFIG_FILE))
		except OSError as err: # the dir's could be created
			pass
		with open(GENERAL_CONFIG_FILE, 'w') as f:
			f.write(json.dumps({"log": False, "server": "http://192.168.14.7:3000/"}))
		return True
	return False


def get_data_from_config_file(config_key):
	with open(GENERAL_CONFIG_FILE, 'r') as f:
		try:
			data = json.loads(f.read())
		except TypeError as err: # need to create config file again.
			create_config_file()
			return ""
		if config_key in data:
			return data[config_key]
		else:
			return ""

def set_data_to_config_file(config_key, value):
	with open(GENERAL_CONFIG_FILE, 'r') as f:
		try:
			data = json.loads(f.read())
		except TypeError as err: # need to create config file again.
			create_config_file()
			return ""
	data[config_key] = value
	with open(GENERAL_CONFIG_FILE, 'w') as f:
		f.write(json.dumps(data))
## Messages id
SEND_DATA_TO_IDA  = 1337
KILL_COMMUNICATION_MANAGER_MESSAGE_ID = 1338
SEND_DATA_TO_SERVER = 1339

#Data: {"project-id": <project-id>}
CHANGE_PROJECT_ID = 1400

#Data: {"username": <username>, "id": <userid>, "token": <token>}
CHANGE_USER = 1401

SET_LOGGED_USER = 1402
SET_LOGGED_OFF_USER = 1403
CHANGE_BASE_URL = 1404
SET_COMMUNICATION_MANAGER_ID = 1405
## Events id.

CHANGE_FUNCTION_NAME_ID = 1
CHANGE_GLOBAL_VARIABLE_NAME_ID = 2
CHANGE_LABEL_NAME_ID = 3
SET_COMMENT_ID = 4
CHANGE_TYPE_ID = 5
NEW_FUNCTION_ID = 6
UNDEFINE_DATA_ID = 7
CHANGE_FUNCTION_START_ID = 8
CHANGE_FUNCTION_END_ID = 9
CREATE_STRUCT_ID = 10
CREATE_STRUCT_VARIABLE_ID = 11
DELETE_STRUCT_VARIABLE_ID = 12
CHANGE_STRUCT_ITEM_TYPE_ID = 13
DELETE_STRUCT_ID = 14
CHANGE_STRUCT_NAME_ID = 15
CREATE_ENUM_ID = 16
CREATE_ENUM_ITEM_ID = 17
CHANGE_ENUM_ITED_ID = 18
DELETE_ENUM_ID = 19
CHANGE_ENUM_NAME_ID = 20
CHANGE_FUNCTION_HEADER_ID = 21
IDA_CURSOR_CHANGE_ID = 22
EXIT_FROM_IDA_ID = 23
START_IDA_ID = 24
CHANGE_STRUCT_MEMBER_NAME_ID = 25
DELETE_ENUM_MEMBER_ID = 26


## Settings
PULLING_TIME = 1
KEEP_ALIVE_TIME = 0.01

## User colors
BLACK_COLOR = 0x0F0000
RED_COLOR = 0x6666FF
ORANGE_COLOR = 0x6699FF
YELLOW_COLOR = 0xC0FFFF
GREEN_COLOR = 0x33FF66
LTGREEN_COLOR = 0x99FF99
BLUE_COLOR = 0xFF9999
PURPLE_COLOR = 0xCC6699
PINK_COLOR = 0x9966FF
GREY_COLOR = 0x999999