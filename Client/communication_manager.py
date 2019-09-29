import base64
import win32con
import win32api
import win32gui
import win32process
import json
import argparse
from Queue import Queue
import requests
from threading import Thread, Timer
from constants import * 

BASE_URL = ""
SECRECT_KEY = ""
TIMER_ARRAY = []
THREAD_ARRAY = []
ID_OF_INSTANCE = -1
WINDOW_HANDLER = -1
USERNAME_ID = -1
USERNAME = ""
PROJECT_ID = -1
DEBUG = False

def create_hidden_window():
	message_map = {win32con.WM_COPYDATA: message_handler}

	window_class = win32gui.WNDCLASS()
	window_class.lpfnWndProc = message_map
	window_class.lpszClassName = "Communication"
	class_atom = win32gui.RegisterClass(window_class)
	window_handler = win32gui.CreateWindow(class_atom, "Communication manager", 0, 0, 0, 0, 0, 0, 0, 0, None)
	print window_handler
	if not window_handler:
		raise Exception("Cannot create hidded window!")
	return window_handler

def insert_to_registery(window_handle):
	try:
		key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, SUBMODULE_KEY, 0, win32con.KEY_ALL_ACCESS)
	except Exception:
		key = win32api.RegCreateKeyEx(win32con.HKEY_CURRENT_USER, SUBMODULE_KEY, win32con.KEY_ALL_ACCESS, None, winnt.REG_OPTION_NON_VOLATILE, None)[0]
	win32api.RegSetValueEx(key, str(ID_OF_INSTANCE), 0, win32con.REG_SZ, str(window_handle))
	

def remove_key_from_reg():
	key = win32api.RegOpenKeyEx(win32con.HKEY_CURRENT_USER, SUBMODULE_KEY, 0, win32con.KEY_ALL_ACCESS)
	if key:
		win32api.RegDeleteValue(key, str(ID_OF_INSTANCE))

def decode_data(lParam):
	copy_data = ctypes.cast(lParam, PCOPYDATASTRUCT)
	data_size = copy_data.contents.cbData
	data_pointer = copy_data.contents.lpData
	data = ctypes.string_at(data_pointer, data_size)
	print data
	return data.replace("\x00","")

def message_handler(window_handler, msg, wParam, lParam): 
	global PROJECT_ID, USERNAME, USERNAME_ID, SECRECT_KEY,BASE_URL
	if wParam == SEND_DATA_TO_SERVER:
		Thread(target=send_data_to_server, args=(decode_data(lParam), )).start()
	elif wParam == CHANGE_PROJECT_ID:
		data = json.loads(decode_data(lParam))
		PROJECT_ID = data["project-id"]
	elif wParam == CHANGE_USER:
		data = json.loads(decode_data(lParam))
		USERNAME_ID = data["id"]
		USERNAME = data["username"]
		SECRECT_KEY = data["token"]
	elif wParam == KILL_COMMUNICATION_MANAGER_MESSAGE_ID:
		print "Kill start"
		kill()
	elif wParam == CHANGE_BASE_URL:
		data = json.loads(decode_data(lParam))
		BASE_URL = data["url"]

def send_data_to_server(data):
	if PROJECT_ID == -1 or SECRECT_KEY == "":
		return -1
	data_to_send_json = json.loads(data)
	print data_to_send_json
	data_to_send_json["project-id"] = PROJECT_ID
	request_data = {}
	request_data["push-data"] = data_to_send_json
	headers = {"Authorization" : "Bearer {0}".format(base64.b64encode(SECRECT_KEY))}
	if data_to_send_json["event-id"] == START_IDA_ID:
			requests.post("{0}{1}".format(BASE_URL, START_SESSION.format(PROJECT_ID)), headers=headers, timeout=5)
	elif data_to_send_json["event-id"] == EXIT_FROM_IDA_ID:
			requests.post("{0}{1}".format(BASE_URL, END_SESSION.format(PROJECT_ID)), headers=headers, timeout=5)
	else:
			requests.post("{0}{1}".format(BASE_URL, PUSH_DATA_TO_PROJECT.format(PROJECT_ID)), data=data, headers=headers, timeout=5)

def get_last_update_time_from_config():
	with open(PROJECT_DATA_FILE, 'r') as f:
		try:
			data = json.loads(f.read())
		except ValueError:
			return 0
	if PROJECT_ID in data:
		return data[PROJECT_ID]["last-update"]
	else:
		update_the_config_file(0)
		return get_data_from_config_file()

def update_the_config_file(current_time):
	data = {}
	with open(PROJECT_DATA_FILE, 'r') as f:
		try:
			data = json.loads(f.read())
		except ValueError:
			data = {}
		if PROJECT_ID not in data:
			data[PROJECT_ID] = {}
	with open(PROJECT_DATA_FILE, 'w') as f:
		data[PROJECT_ID]["last-update"] = current_time
		f.write(json.dumps(data))
	
def pull_from_server(integrator_window_key):
	if PROJECT_ID == -1 or SECRECT_KEY == "":
		return -1
	params = {"project-id": PROJECT_ID, "last-update": get_last_update_time_from_config()}
	headers = {"Authorization" : "Bearer {0}".format(base64.b64encode(SECRECT_KEY))}
	try:
			req = requests.get("{0}{1}".format(BASE_URL, GET_PROJECT_CHANGES_PATH.format(PROJECT_ID)), params=params, headers = headers, timeout=2)
	except Exception as e:
		print e
		return -1	
	data = req.content
	print data
	try:
		data_parsed = json.loads(data)	
	except ValueError:
		return -1
	update_the_config_file(data_parsed["current-time"])
	new_symbols = data_parsed["symbols"]
	window_handler_of_integrator = get_window_handler_by_id(integrator_window_key)
	for symbol in new_symbols:
		print json.dumps(symbol)
		send_data_to_window(window_handler_of_integrator, SEND_DATA_TO_IDA, json.dumps(symbol))

	#logged_users = data_parsed["logged-on"]
	#for user in logged_users:
#		send_data_to_window(window_handler_of_integrator, SET_LOGGED_USER, json.dumps(user))
	#logged_off_users = data_parsed["logged-off"]
	#for user in logged_off_users:
#		send_data_to_window(window_handler_of_integrator, SET_LOGGED_OFF_USER, json.dumps(user))

		
def remove_done_timers():
	global TIMER_ARRAY
	tmp_array = []
	for t in TIMER_ARRAY:
		if t.isAlive():
			tmp_array.append(t)
	TIMER_ARRAY = tmp_array

def remove_done_threads():
	global THREAD_ARRAY
	tmp_array = []
	for t in THREAD_ARRAY:
		if t.isAlive():
			tmp_array.append(t)
	THREAD_ARRAY = tmp_array

def pulling(integrator_window_key):
	global TIMER_ARRAY
	def call_to_pull(integrator_window_key):
		pulling(integrator_window_key)
		pull_from_server(integrator_window_key)
	timer_thread = Timer(PULLING_TIME, call_to_pull, args=(integrator_window_key,  ))
	timer_thread.start()
	remove_done_timers()
	TIMER_ARRAY.append(timer_thread)

def keep_alive_op():
	global TIMER_ARRAY
	def keep_alive():
		keep_alive_op()
	keep_alive_thread = Timer(KEEP_ALIVE_TIME, keep_alive)
	keep_alive_thread.start()
	remove_done_timers()
	remove_done_threads()
	TIMER_ARRAY.append(keep_alive_thread)

def parse_args():
	parser = argparse.ArgumentParser(description="Puller for the IDA Plugin IReal")
	parser.add_argument("integrator_window_key", type=str)
	parser.add_argument("communication_manager_id", type=str)
	args  = parser.parse_args()
	return (args.integrator_window_key, args.communication_manager_id)

def main(integrator_window_key, communication_manager_id):
	global TIMER_ARRAY, WINDOW_HANDLER, ID_OF_INSTANCE, SECRECT_KEY, PROJECT_ID
	ID_OF_INSTANCE = communication_manager_id
	WINDOW_HANDLER = create_hidden_window()
	insert_to_registery(WINDOW_HANDLER)
	pulling(integrator_window_key)
	keep_alive_op()
	win32gui.PumpMessages()

def kill():
	try:
		remove_key_from_reg()
		print "Kill removed reg"
		for thread in TIMER_ARRAY:
			thread.cancel()
		print "Kill timers"
		for thread in THREAD_ARRAY:
			thread.join()
		print "Kill threadss"
	except Exception as e:
		print str(e)
	win32process.ExitProcess(0)

if __name__ == "__main__":
	integrator_window_key, communication_manager_id = parse_args()
	main(integrator_window_key, communication_manager_id)