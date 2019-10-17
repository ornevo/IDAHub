import base64
import win32con
import win32api
import win32gui
import win32process
import time
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
INTEGRATOR_WINDOW_KEY = ""
NEED_TO_PULL = True

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

def decode_data(lParam):
	copy_data = ctypes.cast(lParam, PCOPYDATASTRUCT)
	data_size = copy_data.contents.cbData
	data_pointer = copy_data.contents.lpData
	data = ctypes.string_at(data_pointer, data_size)
	print data
	return data.replace("\x00","")

def message_handler(window_handler, msg, wParam, lParam): 
	global PROJECT_ID, USERNAME, USERNAME_ID, SECRECT_KEY,BASE_URL, NEED_TO_PULL
	if wParam == SEND_DATA_TO_SERVER:
		if not NEED_TO_PULL:
			Thread(target=send_data_to_server, args=(decode_data(lParam), )).start()
	elif wParam == CHANGE_PROJECT_ID:
		data = json.loads(decode_data(lParam))
		PROJECT_ID = data["project-id"]
		NEED_TO_PULL = data["need-to-pull"]
	elif wParam == CHANGE_USER:
		data = json.loads(decode_data(lParam))
		USERNAME_ID = data["id"]
		USERNAME = data["username"]
		SECRECT_KEY = data["token"]
	elif wParam == KILL_COMMUNICATION_MANAGER_MESSAGE_ID:
		headers = {"Authorization" : "Bearer {0}".format(SECRECT_KEY)}
		requests.post("{0}/{1}".format(BASE_URL, END_SESSION.format(PROJECT_ID)), headers=headers, timeout=5)
		print "Kill start"
		kill()
	elif wParam == CHANGE_BASE_URL:
		data = json.loads(decode_data(lParam))
		BASE_URL = data["url"]
	elif wParam == MANUAL_PULL_ID:
		pull_from_server(INTEGRATOR_WINDOW_KEY, True)

def send_data_to_server(data):
	if PROJECT_ID == -1 or SECRECT_KEY == "":
		return -1
	data_to_send_json = json.loads(data)
	data = data_to_send_json["data"]
	data_to_send_json.pop("data")
	data_to_send_json.update(data)
	data_to_send_json["projectId"] = PROJECT_ID
	print data_to_send_json
	
	headers = {"Authorization" : "Bearer {0}".format(SECRECT_KEY)}
	if data_to_send_json["event-id"] == START_IDA_ID:
			requests.post("{0}/{1}".format(BASE_URL, START_SESSION.format(PROJECT_ID)), headers=headers, timeout=5)
	elif data_to_send_json["event-id"] == EXIT_FROM_IDA_ID:
			requests.post("{0}/{1}".format(BASE_URL, END_SESSION.format(PROJECT_ID)), headers=headers, timeout=5)
	else:
			requests.post("{0}/{1}".format(BASE_URL, PUSH_DATA_TO_PROJECT.format(PROJECT_ID)), data=data_to_send_json, headers=headers, timeout=5)

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
		return get_last_update_time_from_config()

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
	
def pull_from_server(integrator_window_key, forced_pull = False):
	if NEED_TO_PULL and not forced_pull:
		return -1
	if PROJECT_ID == -1 or SECRECT_KEY == "":
		return -1
	params = {"projectId": PROJECT_ID, "lastUpdate": get_last_update_time_from_config()}
	headers = {"Authorization" : "Bearer {0}".format(SECRECT_KEY)}
	try:
			req = requests.get("{0}/{1}".format(BASE_URL, GET_PROJECT_CHANGES_PATH.format(PROJECT_ID)), data=params, headers = headers, timeout=2)
	except Exception as e:
		print e
		return -1	
	data = req.content
	print data
	try:
		data_parsed = json.loads(data)	
	except ValueError:
		return -1
	data_parsed = data_parsed["body"]
	update_the_config_file(data_parsed["curtimestamp"])
	new_symbols = data_parsed["symbols"]
	for symbol in new_symbols:
		send_data_to_window(integrator_window_key, SEND_DATA_TO_IDA, json.dumps(symbol))
	logged_users = data_parsed["loggedOn"]
	for user in logged_users:
		send_data_to_window(integrator_window_key, SET_LOGGED_USER, json.dumps(user))
	logged_off_users = data_parsed["loggedOff"]
	for user in logged_off_users:
		send_data_to_window(integrator_window_key, SET_LOGGED_OFF_USER, json.dumps(user))

		
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
	if not NEED_TO_PULL:
		def call_to_pull(integrator_window_key):
			pull_from_server(integrator_window_key)
			pulling(integrator_window_key)
		timer_thread = Timer(PULLING_TIME, call_to_pull, args=(integrator_window_key,  ))
		timer_thread.start()
		remove_done_timers()
		TIMER_ARRAY.append(timer_thread)

def parse_args():
	parser = argparse.ArgumentParser(description="Puller for the IDA Plugin IReal")
	parser.add_argument("integrator_window_key", type=str)
	args  = parser.parse_args()
	return args.integrator_window_key

def main(integrator_window_key):
	global TIMER_ARRAY, WINDOW_HANDLER, SECRECT_KEY, PROJECT_ID, INTEGRATOR_WINDOW_KEY
	WINDOW_HANDLER = create_hidden_window()
	INTEGRATOR_WINDOW_KEY = integrator_window_key
	send_data_to_window(integrator_window_key, SET_COMMUNICATION_MANAGER_ID, json.dumps({"id": WINDOW_HANDLER}))
	pulling(integrator_window_key)
	win32gui.PumpMessages()

def kill():
	try:
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
	integrator_window_key = parse_args()
	main(integrator_window_key)