from IEvent import IEvent
import idc
class ChangeStructItemTypeEvent(IEvent):
	def __init__(self, id_of_struct, offset, variable_type):
		super(ChangeStructItemTypeEvent, self).__init__(13, "Change struct item type", {"id": id_of_struct, "offset": offset, "variable-type": variable_type})
		self._id = id_of_struct
		self._offset = offset
		self._value = variable_type
	
	def implement(self):
		type_id = -1
		if idc.is_struct(self._value):
			type_id = self._value
		flags = 0
		if self._value == "db":
			flags = ida_bytes.FF_BYTE
		elif self._value == "dw":
			flags = ida_bytes.FF_WORD
		elif self._value == "dd":
			flags = ida_bytes.FF_DWORD
		elif self._value == "dq":
			flags = ida_bytes.QWORD
		elif type_id != -1:
			flags = ida_bytes.FF_STRUCT
		idc.set_member_type(self._id, self._offset, flags, type_id)
