from IEvent import IEvent
from constants import *
class IDACursorEvent(IEvent):
	def __init__(self, linear_address, username,user_manager = None):
		super(IDACursorEvent, self).__init__(IDA_CURSOR_CHANGE_ID, "IDA cursor change", {"linear-address": linear_address, "name": username})
		self._username = username
		self._ea = linear_address
		self._user_manager = user_manager
	
	def implement(self):
		if self._user_manager:
			self._user_manager.change_ea_of_user(self._username, self._ea)