from IEvent import IEvent, decode_bytes, encode_bytes
import ida_typeinf
import ida_bytes
from constants import *
class ChangeTypeEvent(IEvent):
	def __init__(self, linear_address, variable_type):
		super(ChangeTypeEvent, self).__init__(CHANGE_TYPE_ID, "Change type", {"linear-address": linear_address, "variable-type": [decode_bytes(t) for t in variable_type]})
		self._ea = linear_address
		self._type = [decode_bytes(t) for t in variable_type]
		self._is_make_data = False

	def __init__(self, ea, flags, tid, len):
		super(ChangeTypeEvent, self).__init__(CHANGE_TYPE_ID, "Change type", {"linear-address": ea, "variable-type": "{0}:{1}:{2}:{3}".format(ea,flags,tid,len)})
		self._ea = ea
		self._type = "{0}:{1}:{2}:{3}".format(ea,flags,tid,len)
		self._is_make_data = True

	def implement(self):
		if self._is_make_data:
			ea, flags, tid, len = self._type.split(":")
			ida_bytes.create_data(int(ea), int(flags), int(len), int(tid))
		else:
			py_type = [encode_bytes(t) for t in self._type]
			if len(py_type) == 3:
				py_type = py_type[1:]
			if len(py_type) >= 2:
				ida_typeinf.apply_type(
					None,
					py_type[0],
					py_type[1],
					self._ea,
					ida_typeinf.TINFO_DEFINITE,
				)
