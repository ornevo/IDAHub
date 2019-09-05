from IEvent import IEvent
from constants import *
class IDACursorEvent(IEvent):
	def __init__(self, linear_address):
		super(IDACursorEvent, self).__init__(IDA_CURSOR_CHANGE_ID, "IDA cursor change", {"linear-address": linear_address})