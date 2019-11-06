import idaapi
import random
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
from forms.painter import Painter
from PyQt5.QtWidgets import qApp, QMainWindow
from all_events import StartIDAEvent

def pass_to_manager(ev):
	log("Pass to manager: " + str(ev))
	try:
		constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.SEND_DATA_TO_SERVER, ev.encode_to_json())
	except Exception as e:
		pass

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
		prev_hook = shared.PAUSE_HOOK
		shared.PAUSE_HOOK = True
		event_object.implement()
		if not shared.MASTER_PAUSE_HOOK and prev_hook == False:
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
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_PROJECT_ID, json.dumps({"project-id": shared.PROJECT_ID, "need-to-pull": False}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_USER, json.dumps({"username":shared.USERNAME, "id": shared.USERID, "token": shared.USER_TOKEN}))
			constants.send_data_to_window(shared.COMMUNICATION_MANAGER_WINDOW_ID, constants.CHANGE_BASE_URL, json.dumps({"url": shared.BASE_URL}))
	return True

def add_logged_user(json_dict):
	shared.USER_MANAGER.add_logged_user(json_dict["username"])
	shared.PAINTER.refresh()

def add_logged_off_user(json_dict):
	shared.USER_MANAGER.remove_logged_user(json_dict["username"])
	shared.PAINTER.refresh()

def create_event_from_dict(json_dict):
	event_id = json_dict["eventId"]
	if event_id == constants.CHANGE_FUNCTION_NAME_ID: 
		return ChangeFunctionNameEvent(json_dict["linearAddress"], str(json_dict["value"]))
	elif event_id == constants.CHANGE_GLOBAL_VARIABLE_NAME_ID: 
		if str(json_dict["labelType"]) == "public":
			is_public = True
		else:
			is_public = False
		return ChangeGlobalVariableNameEvent(json_dict["linearAddress"], str(json_dict["value"]), is_public)
	elif event_id == constants.CHANGE_LABEL_NAME_ID: 
		return ChangeLabelNameEvent(json_dict["linearAddress"], str(json_dict["value"]))
	elif event_id == constants.SET_COMMENT_ID: 
		return ChangeCommentEvent(json_dict["linearAddress"], str(json_dict["value"]) ,str(json_dict["commentType"]), json_dict["name"])
	elif event_id == constants.CHANGE_TYPE_ID: 
		try:
			type_string = str(json_dict["variableType"])
			if ":" in type_string:
				ea, flags, tid, size = type_string.split(':')
				return ChangeTypeEvent(int(json_dict["linearAddress"]), int(flags), int(tid), int(size), True)
			else:	
				return ChangeTypeEvent(json_dict["linearAddress"], type_string, is_make_data = False)
		except UnicodeEncodeError:
			return ChangeTypeEvent(json_dict["linearAddress"], json_dict["variableType"], is_make_data = False)
	elif event_id == constants.NEW_FUNCTION_ID: 
		return NewFunctionEvent(json_dict["linearAddress"],json_dict["value"])
	elif event_id == constants.UNDEFINE_DATA_ID: 
		return UndefineDataEvent(json_dict["linearAddress"])
	elif event_id == constants.CHANGE_FUNCTION_START_ID: 
		return ChangeFunctionStartEvent(json_dict["linearAddress"], str(json_dict["value"]))
	elif event_id == constants.CHANGE_FUNCTION_END_ID: #Checjed
		return ChangeFunctionEndEvent(json_dict["linearAddress"], str(json_dict["value"]))
	elif event_id == constants.CREATE_STRUCT_ID: 
		return CreateStructEvent(str(json_dict["name"]), json_dict["id"])
	elif event_id == constants.CREATE_STRUCT_VARIABLE_ID: #Checed
		return CreateStructVariableEvent(str(json_dict["id"]), str(json_dict["offset"]), str(json_dict["variableType"]), str(json_dict["value"]))
	elif event_id == constants.CHANGE_STRUCT_ITEM_TYPE_ID:
		return ChangeStructItemTypeEvent(str(json_dict["id"]), json_dict["offset"], json_dict["variableType"])
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
	elif event_id == constants.CHANGE_ENUM_MEMBER_NAME_ID:
		return ChangeEnumMemberName(json_dict["id"], str(json_dict["value"]))
	elif event_id == constants.IDA_CURSOR_CHANGE_ID: 
		return IDACursorEvent(json_dict["linearAddress"], json_dict["name"], shared.USER_MANAGER)
	elif event_id == constants.EXIT_FROM_IDA_ID: 
		return ExitIDBEvent()
	elif event_id == constants.START_IDA_ID: 
		return StartIDAEvent()
	elif event_id == constants.CHANGE_STRUCT_MEMBER_NAME_ID: 
		return ChangeStructItemEvent(json_dict["id"], json_dict["offset"], str(json_dict["value"]))
	elif event_id == constants.DELETE_ENUM_MEMBER_ID: 
		value, serial, bmask = json_dict["value"].split(":")
		return DeleteEnumMemberEvent(json_dict["id"], value, serial, bmask)

class user_manager():
	def __init__(self):
		self._users = []
		self._used_colors = []
		self.add_logged_user(shared.USERNAME)
	
	def add_logged_user(self, user):
		if not shared.MASTER_PAUSE_HOOK:
			for user_dict in self._users:
				if user == user_dict["user"]:
					user_dict["logged"] = True
					return 0
			color = random.choice(list(set(constants.COLOR_ARRAY) - set(self._used_colors)))
			self._used_colors.append(color)
			self._users.append({"user": user, "logged": True, "ea": 0, "color": color})

	def change_ea_of_user(self, user, ea):
		if not shared.MASTER_PAUSE_HOOK:
			for user_dict in self._users:
				if  user == shared.USERNAME:
					continue
				if user_dict["user"] == user:
					user_dict["ea"] = ea
			shared.PAINTER.refresh()

	def remove_logged_user(self, user):
		if not shared.MASTER_PAUSE_HOOK:
			#In the case we get logged of user, that is our's from the last session.
			
			if user == shared.USERNAME:
				return 0
			# we need to assign color to the user so we add it first.
			self.add_logged_user(user)
			# Than we can set the logged to false.
			for user_dict in self._users:
				if user == user_dict["user"]:
					user_dict["logged"] = False
	
	def get_users(self):
		return self._users

shared.USER_MANAGER = user_manager()
shared.PAINTER = Painter(shared.USER_MANAGER)

class integrator(idaapi.UI_Hooks, idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
	comment = " "
	help = " "
	wanted_name = "Integrator"
	wanted_hotkey = ""

	def run(self, arg):
		pass

	def ready_to_run(self):
		self._widget = StatusWidget(shared.USER_MANAGER)
		self._widget.install(self._window)

	def init(self):	
		constants.create_general_config_file()
		shared.BASE_URL = constants.get_data_from_config_file("server")
		shared.LOG = constants.get_data_from_config_file("log")

		self._window_handler = create_hidden_window()
		log("Created window")

		shared.INTEGRATOR_WINDOW_ID = self._window_handler
		si = subprocess.STARTUPINFO()
		si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
		subprocess.Popen(["python", "{0}\communication_manager.py".format(idaapi.idadir("plugins")), str(shared.INTEGRATOR_WINDOW_ID)])
		time.sleep(1.5)

		if not shared.PAUSE_HOOK:
			pass_to_manager(StartIDAEvent())
		self.hook()
		for widget in qApp.topLevelWidgets():
			if isinstance(widget, QMainWindow):
				self._window = widget
				break
		return idaapi.PLUGIN_KEEP

	def term(self):
		self._widget.uninstall(self._window)
	
def PLUGIN_ENTRY():
	return integrator()
