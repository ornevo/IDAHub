from IEvent import IEvent
import ida_funcs
from constants import *
class ChangeFunctionEndEvent(IEvent):
	def __init__(self, ea, value):
		super(ChangeFunctionEndEvent, self).__init__(CHANGE_FUNCTION_END_ID, "Change function end", {"linear-address": ea, "value": value})
		self._ea = ea
		self._new_end = value
	
	def implement(self):
		ida_funcs.set_func_end(self._ea, self._new_end)