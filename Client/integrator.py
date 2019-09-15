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

def log(data):
	print("[Integrator] " + data)

def create_hidden_window():
	window_handler = win32gui.CreateWindow("EDIT", "Integrator window hook", 0, 0, 0, 0, 0, 0, 0, 0, None)
	if not window_handler:
		raise Exception("Cannot create hidded window!")
	win32gui.SetWindowLong(window_handler, win32con.GWL_WNDPROC, message_handler)
	return window_handler

def insert_to_registery(window_handle):
	id_of_instance = struct.unpack(">I", os.urandom(4))[0]
	try:
		key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, constants.SUBMODULE_KEY, 0, win32con.KEY_ALL_ACCESS)
	except Exception:
		key = win32api.RegCreateKeyEx(win32con.HKEY_CURRENT_USER, constants.SUBMODULE_KEY, win32con.KEY_ALL_ACCESS, None, winnt.REG_OPTION_NON_VOLATILE, None)[0]
	win32api.RegSetValueEx(key, str(id_of_instance), 0, win32con.REG_SZ, str(window_handle))
	return id_of_instance
	
def remove_key_from_reg(id_of_instance):
	try:
		key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, constants.SUBMODULE_KEY, 0, win32con.KEY_ALL_ACCESS)
		if key:
			win32api.RegDeleteValue(key, str(id_of_instance))
	except Exception as e:
		pass


def message_handler(window_handler, msg, wParam, lParam):
	if wParam == constants.SEND_DATA_TO_IDA: #pass
		copy_data = ctypes.cast(lParam, constants.PCOPYDATASTRUCT)
		event_data = json.loads(ctypes.string_at(copy_data.contents.lpData))
		event_object = create_event_from_dict(event_data)
		log("Received object: " + str(event_data))
		shared.PAUSE_HOOK = True
		event_object.implement()
		shared.PAUSE_HOOK = False
	return True

def create_event_from_dict(json_dict):
	event_id = json_dict["id"]
	event_data = json_dict["data"]
	if event_id == constants.CHANGE_FUNCTION_NAME_ID: 
		return ChangeFunctionNameEvent(str(event_data["value"]), event_data["linear-address"])
	elif event_id == constants.CHANGE_GLOBAL_VARIABLE_NAME_ID: 
		if str(event_data["label-type"]) == "public":
			is_public = True
		else:
			is_public = False
		return ChangeGlobalVariableNameEvent(event_data["linear-address"], str(event_data["value"]), is_public)
	elif event_id == constants.CHANGE_LABEL_NAME_ID: 
		return ChangeLabelNameEvent(event_data["linear-address"], str(event_data["value"]))
	elif event_id == constants.SET_COMMENT_ID: 
		return ChangeCommentEvent(event_data["linear-address"], str(event_data["value"]) ,str(event_data["comment-type"]))
	elif event_id == constants.CHANGE_TYPE_ID: 
		if ":" in str(event_data["variable-type"]):
			ea, flags, tid, size = str(event_data["variable-type"]).split(':')
			return ChangeTypeEvent(int(event_data["linear-address"]), int(flags), int(tid), int(size))
		else:	
			return ChangeTypeEvent(event_data["linear-address"], str(event_data["variable-type"]))
	elif event_id == constants.NEW_FUNCTION_ID: 
		return NewFunctionEvent(event_data["linear-address-start"],event_data["linear-address-end"])
	elif event_id == constants.UNDEFINE_DATA_ID: 
		return UndefineDataEvent(event_data["linear-address"])
	elif event_id == constants.CHANGE_FUNCTION_START_ID: 
		return ChangeFunctionStartEvent(event_data["linear-address"], str(event_data["value"]))
	elif event_id == constants.CHANGE_FUNCTION_END_ID: #Checjed
		return ChangeFunctionEndEvent(event_data["linear-address"], str(event_data["value"]))
	elif event_id == constants.CREATE_STRUCT_ID: 
		return CreateStructEvent(str(event_data["name"]), event_data["id"])
	elif event_id == constants.CREATE_STRUCT_VARIABLE_ID: #Checed
		return CreateStructVariableEvent(event_data["id"], event_data["offset"], str(event_data["variable-type"]))
	elif event_id == constants.DELETE_STRUCT_VARIABLE_ID: #Chcked
		return DeleteStructVariableEvent(event_data["id"], event_data["offset"])
	elif event_id == constants.DELETE_STRUCT_ID: 
		return DeleteStructEvent(event_data["id"])
	elif event_id == constants.CHANGE_STRUCT_NAME_ID: 
		return ChangeStructNameEvent(event_data["id"], str(event_data["value"]))
	elif event_id == constants.CREATE_ENUM_ID: 
		return CreateEnumEvent(str(event_data["name"]), event_data["id"])
	elif event_id == constants.CREATE_ENUM_ITEM_ID: 
		return CreateEnumItemEvent(event_data["id"], str(event_data["name"]), str(event_data["value"]))
	elif event_id == constants.DELETE_ENUM_ID: 
		return DeleteEnumEvent(event_data["id"])
	elif event_id == constants.CHANGE_ENUM_NAME_ID: 
		return ChangeEnumNameEvent(event_data["id"], str(event_data["value"]))
	elif event_id == constants.CHANGE_FUNCTION_HEADER_ID: 
		return ChangeFunctionHeaderEvent(event_data["linear-address"], str(event_data["value"]))
	elif event_id == constants.IDA_CURSOR_CHANGE_ID: 
		return IDACursorEvent(event_data["linear-address"])
	elif event_id == constants.EXIT_FROM_IDA_ID: 
		return ExitIDBEvent()
	elif event_id == constants.START_IDA_ID: 
		return StartIDAEvent()
	elif event_id == constants.CHANGE_STRUCT_MEMBER_NAME_ID: 
		return ChangeStructItemEvent(event_data["id"], event_data["offset"], str(event_data["value"]))
	elif event_id == constants.DELETE_ENUM_MEMBER_ID: 
		return DeleteEnumMemberEvent(event_data["id"], event_data["value"])

class ChangeServer(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		new_server = idc.AskStr(str(shared.BASE_URL), "Server:")
		constants.set_data_to_config_file("server",new_server)
		return 1

	def update(self,ctx):
		return idaapi.AST_ENABLE_ALWAYS

action_change_server = idaapi.action_desc_t(
	"sync:change_server",
	"Change main server",
	ChangeServer(),
	"Ctrl+Alt+A"
)

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
	
	def init(self):	
		constants.create_general_config_file()
		shared.BASE_URL = constants.get_data_from_config_file("server")
		shared.LOG = constants.get_data_from_config_file("log")

		self._window_handler = create_hidden_window()
		self._id = insert_to_registery(self._window_handler)
		log("Created window")

		shared.INTEGRATOR_WINDOW_ID = self._id
		shared.COMMUNICATION_MANAGER_WINDOW_ID = struct.unpack(">I", os.urandom(4))[0]
		si = subprocess.STARTUPINFO()
		si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		subprocess.Popen(["python", "{0}\communication_manager.py".format(idaapi.idadir("plugins")), str(shared.INTEGRATOR_WINDOW_ID), str(shared.COMMUNICATION_MANAGER_WINDOW_ID)])
		time.sleep(1)
		
		shared.IS_COMMUNICATION_MANAGER_STARTED = True
		if shared.USERID != -1: #started.
			communication_manager_window_handler = constants.get_window_handler_by_id(shared.COMMUNICATION_MANAGER_WINDOW_ID)
			constants.send_data_to_window(communication_manager_window_handler, constants.CHANGE_PROJECT_ID, json.dumps({"project-id": shared.PROJECT_ID}))
			constants.send_data_to_window(communication_manager_window_handler, constants.CHANGE_USER, json.dumps({"username":shared.USERNAME, "id": shared.USERID, "token": shared.USER_TOKEN}))
		self.hook()
		return idaapi.PLUGIN_KEEP

	def term(self):
		remove_key_from_reg(self._id)
		self._id = 0
		
def PLUGIN_ENTRY():
	return integrator()
