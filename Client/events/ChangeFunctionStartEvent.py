from IEvent import IEvent
import ida_funcs
from constants import *
class ChangeFunctionStartEvent(IEvent):
	def __init__(self, ea, value):
		super(ChangeFunctionStartEvent,self).__init__(CHANGE_FUNCTION_START_ID, "Change function start", {"linear-address": ea, "value": value})
		self._ea = ea
		self._value = value
		
	def implement(self):
		ida_funcs.set_func_start(self._ea, self._value)