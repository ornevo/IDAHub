from IEvent import IEvent
import idc
import ida_name
from constants import *
import ida_kernwin
class ChangeGlobalVariableNameEvent(IEvent):
	def __init__(self, linear_address, new_name, is_public):
		super(ChangeGlobalVariableNameEvent, self).__init__(CHANGE_GLOBAL_VARIABLE_NAME_ID,"Change global variable name", {"linear-address": linear_address, "value": new_name, "label-type": ("public" if is_public else "local") })
		self._linear_address = linear_address
		self._new_name = new_name
		self._is_public = is_public
	
	def implement(self):
		if self._is_public:
			if idc.get_name(self._linear_address) != self._new_name:
				idc.set_name(self._linear_address, self._new_name, ida_name.SN_PUBLIC if self._is_public else ida_name.SN_LOCAL)
		else:
			if idc.get_name(self._linear_address, ida_name.GN_LOCAL) != self._new_name:
				idc.set_name(self._linear_address, self._new_name, ida_name.SN_PUBLIC if self._is_public else ida_name.SN_LOCAL)
		ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)