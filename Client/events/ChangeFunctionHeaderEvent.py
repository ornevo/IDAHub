from IEvent import IEvent
from constants import *
class ChangeFunctionHeaderEvent(IEvent):
	def __init__(self, linear_address, value):
		super(ChangeFunctionHeaderEvent, self).__init__(CHANGE_FUNCTION_HEADER_ID, "Change function header", {"linear-address": linear_address, 'value': value})