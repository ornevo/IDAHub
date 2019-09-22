from IEvent import IEvent
import idc
import ida_name
from constants import *
class ChangeGlobalVariableNameEvent(IEvent):
	def __init__(self, linear_address, new_name, is_public):
		super(ChangeGlobalVariableNameEvent, self).__init__(CHANGE_GLOBAL_VARIABLE_NAME_ID,"Change global variable name", {"linear_address": linear_address, "value": new_name, "label-type": ("public" if is_public else "local") })
		self._linear_address = linear_address
		self._new_name = new_name
		self._is_public = is_public
	
	def implement(self):
		idc.set_name(self._linear_address, self._new_name, ida_name.SN_PUBLIC if self._is_public else ida_name.SN_LOCAL)