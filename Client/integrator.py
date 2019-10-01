import idaapi
import ctypes
import win32api
import win32gui
import win32con
import winnt
import os
import struct
import constants
import shared
from all_events import *
import time
from forms.StatusWidget import StatusWidget
from PyQt5.QtWidgets import qApp, QMainWindow

INTEGRATOR_OBJECT = None
def log(data):
	if shared.LOG:
		print("[Integrator] " + data)
	else:
		pass

def create_hidden_window():
	window_handler = win32gui.CreateWindow("EDIT", "Integrator window hook", 0, 0, 0, 0, 0, 0, 0, 0, None)
	if not window_handler:
		raise Exception("Cannot create hidded window!")
	win32gui.SetWindowLong(window_handler, win32con.GWL_WNDPROC, message_handler)
	return window_handler
	
def message_handler(window_handler, msg, wParam, lParam):
	if wParam == constants.SEND_DATA_TO_IDA:
		copy_data = ctypes.cast(lParam, constants.PCOPYDATASTRUCT)
		event_data = json.loads(ctypes.string_at(copy_data.contents.lpData))
		event_object = create_event_from_dict(event_data)
		log("Received object: " + str(event_data))
		shared.PAUSE_HOOK = True
		event_object.implement()
		shared.PAUSE_HOOK = False
	elif wParam == constants.SET_LOGGED_USER:
		copy_data = ctypes.cast(lParam, constants.PCOPYDATASTRUCT)
		event_data = json.loads(ctypes.string_at(copy_data.contents.lpData))
		add_logged_user(event_data)
	elif wParam == constants.SET_LOGGED_OFF_USER:
		copy_data = ctypes.cast(lParam, constants.PCOPYDATASTRUCT)
		event_data = json.loads(ctypes.string_at(copy_data.contents.lpData))
		add_logged_off_user(event_data)
	elif wParam == constants.SET_COMMUNICATION_MANAGER_ID:
		copy_data = ctypes.cast(lParam, constants.PCOPYDATASTRUCT)
		event_data = json.loads(ctypes.string_at(copy_data.contents.lpData))
		shared.COMMUNICATION_MANAGER_WINDOW_ID = event_data["id"]
		shared.IS_COMMUNICATION_MANAGER_STARTED = True
		if shared.USERID != -1: #started.
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_PROJECT_ID, json.dumps({"project-id": shared.PROJECT_ID}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_USER, json.dumps({"username":shared.USERNAME, "id": shared.USERID, "token": shared.USER_TOKEN}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_BASE_URL, json.dumps({"url": shared.BASE_URL}))
	return True

def add_logged_user(json_dict):
	manager = INTEGRATOR_OBJECT.get_manager()
	manager.add_logged_user(json_dict["username"])

def add_logged_off_user(json_dict):
	manager = INTEGRATOR_OBJECT.get_manager()
	manager.add_logged_off_user(json_dict["username"])

def create_event_from_dict(json_dict):
	event_id = json_dict["id"]
	if event_id == constants.CHANGE_FUNCTION_NAME_ID: 
		return ChangeFunctionNameEvent(str(json_dict["value"]), json_dict["linear-address"])
	elif event_id == constants.CHANGE_GLOBAL_VARIABLE_NAME_ID: 
		if str(json_dict["label-type"]) == "public":
			is_public = True
		else:
			is_public = False
		return ChangeGlobalVariableNameEvent(json_dict["linear-address"], str(json_dict["value"]), is_public)
	elif event_id == constants.CHANGE_LABEL_NAME_ID: 
		return ChangeLabelNameEvent(json_dict["linear-address"], str(json_dict["value"]))
	elif event_id == constants.SET_COMMENT_ID: 
		return ChangeCommentEvent(json_dict["linear-address"], str(json_dict["value"]) ,str(json_dict["comment-type"]))
	elif event_id == constants.CHANGE_TYPE_ID: 
		if ":" in str(json_dict["variable-type"]):
			ea, flags, tid, size = str(json_dict["variable-type"]).split(':')
			return ChangeTypeEvent(int(json_dict["linear-address"]), int(flags), int(tid), int(size))
		else:	
			return ChangeTypeEvent(json_dict["linear-address"], str(json_dict["variable-type"]))
	elif event_id == constants.NEW_FUNCTION_ID: 
		return NewFunctionEvent(json_dict["linear-address"],json_dict["value"])
	elif event_id == constants.UNDEFINE_DATA_ID: 
		return UndefineDataEvent(json_dict["linear-address"])
	elif event_id == constants.CHANGE_FUNCTION_START_ID: 
		return ChangeFunctionStartEvent(json_dict["linear-address"], str(json_dict["value"]))
	elif event_id == constants.CHANGE_FUNCTION_END_ID: #Checjed
		return ChangeFunctionEndEvent(json_dict["linear-address"], str(json_dict["value"]))
	elif event_id == constants.CREATE_STRUCT_ID: 
		return CreateStructEvent(str(json_dict["name"]), json_dict["id"])
	elif event_id == constants.CREATE_STRUCT_VARIABLE_ID: #Checed
		return CreateStructVariableEvent(json_dict["id"], json_dict["offset"], str(json_dict["variable-type"]))
	elif event_id == constants.DELETE_STRUCT_VARIABLE_ID: #Chcked
		return DeleteStructVariableEvent(json_dict["id"], json_dict["offset"])
	elif event_id == constants.DELETE_STRUCT_ID: 
		return DeleteStructEvent(json_dict["id"])
	elif event_id == constants.CHANGE_STRUCT_NAME_ID: 
		return ChangeStructNameEvent(json_dict["id"], str(json_dict["value"]))
	elif event_id == constants.CREATE_ENUM_ID: 
		return CreateEnumEvent(str(json_dict["name"]), json_dict["id"])
	elif event_id == constants.CREATE_ENUM_ITEM_ID: 
		return CreateEnumItemEvent(json_dict["id"], str(json_dict["name"]), str(json_dict["value"]))
	elif event_id == constants.DELETE_ENUM_ID: 
		return DeleteEnumEvent(json_dict["id"])
	elif event_id == constants.CHANGE_ENUM_NAME_ID: 
		return ChangeEnumNameEvent(json_dict["id"], str(json_dict["value"]))
	elif event_id == constants.CHANGE_FUNCTION_HEADER_ID: 
		return ChangeTypeEvent(json_dict["linear-address"], str(json_dict["value"]))
	elif event_id == constants.IDA_CURSOR_CHANGE_ID: 
		return IDACursorEvent(json_dict["linear-address"])
	elif event_id == constants.EXIT_FROM_IDA_ID: 
		return ExitIDBEvent()
	elif event_id == constants.START_IDA_ID: 
		return StartIDAEvent()
	elif event_id == constants.CHANGE_STRUCT_MEMBER_NAME_ID: 
		return ChangeStructItemEvent(json_dict["id"], json_dict["offset"], str(json_dict["value"]))
	elif event_id == constants.DELETE_ENUM_MEMBER_ID: 
		return DeleteEnumMemberEvent(json_dict["id"], json_dict["value"])

class ChangeServer(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		new_server = idc.AskStr(str(shared.BASE_URL), "Server:")
		constants.set_data_to_config_file("server",new_server)
		constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_BASE_URL, json.dumps({"url": shared.BASE_URL}))
		return 1

	def update(self,ctx):
		return idaapi.AST_ENABLE_ALWAYS

action_change_server = idaapi.action_desc_t(
	"sync:change_server",
	"Change main server",
	ChangeServer(),
	"Ctrl+Alt+A"
)

class user_manager():
	def __init__(self):
		self._users = []
	
	def add_logged_user(self, user):
		self._users.append({"user": user, "logged": True})
	
	def add_logged_off_user(self, user):
		self._users.append({"user": user, "logged": False})
	
	def get_users(self):
		return self._users

class integrator(idaapi.UI_Hooks, idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
	comment = " "
	help = " "
	wanted_name = "Integrator"
	wanted_hotkey = ""

	def run(self, arg):
		pass

	def ready_to_run(self):
		idaapi.register_action(action_change_server)
		idaapi.attach_action_to_menu("Edit/Plugins/IDAHub/ChangeServer","sync:change_server", idaapi.SETMENU_APP)
		self._manager = user_manager()
		self._widget = StatusWidget(self._manager)
		self._widget.install(self._window)

	def init(self):	
		if constants.create_general_config_file(): # if the Config file didnt exist, we want to ask for a server name.
			server = idc.AskStr("", "Server:")	
			constants.set_data_to_config_file("server", server)
				
		shared.BASE_URL = constants.get_data_from_config_file("server")
		shared.LOG = constants.get_data_from_config_file("log")

		self._window_handler = create_hidden_window()
		log("Created window")

		shared.INTEGRATOR_WINDOW_ID = self._window_handler
		si = subprocess.STARTUPINFO()
		si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		subprocess.Popen(["python", "{0}\communication_manager.py".format(idaapi.idadir("plugins")), str(shared.INTEGRATOR_WINDOW_ID)])
		time.sleep(1.5)
		
		self.hook()
		for widget in qApp.topLevelWidgets():
			if isinstance(widget, QMainWindow):
				self._window = widget
				break
		return idaapi.PLUGIN_KEEP

	def term(self):
		self._widget.uninstall(self._window)
	
	def get_manager():
		return self._manager

def PLUGIN_ENTRY():
	global INTEGRATOR_OBJECT
	INTEGRATOR_OBJECT = integrator()
	return INTEGRATOR_OBJECT
