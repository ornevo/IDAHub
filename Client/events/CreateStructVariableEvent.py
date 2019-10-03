from IEvent import IEvent
import ida_struct
import ida_bytes
from constants import *
class CreateStructVariableEvent(IEvent):
	def __init__(self, id_of_struct, offset, variable_type, value):
		super(CreateStructVariableEvent,self).__init__(CREATE_STRUCT_VARIABLE_ID, "Create struct variable", {"id": str(id_of_struct), "offset": str(offset), "variable-type": variable_type, "value": value})	
		self._id = id_of_struct
		self._offset = offset
		self._variable_type = variable_type
		self._value = value
	
	def implement(self):
		id_of_struct = ida_struct.get_struc_id(self._id)
		sturct_obj = ida_struct.get_struc(long(id_of_struct))
		val_type  = ""
		size = 0
		if self._variable_type == "db":
			val_type = ida_bytes.FF_BYTE
			size = 1
		elif self._variable_type == "dw":
			val_type = ida_bytes.FF_WORD
			size = 2
		elif self._variable_type == "dd":
			val_type = ida_bytes.FF_DWORD
			size = 4
		elif self._variable_type == "dq":
			val_type = ida_bytes.FF_QWORD
			size = 8
		else:
			val_type = ida_bytes.FF_STRUCT
			size = 0
		ida_struct.add_struc_member(sturct_obj, self._value, int(self._offset), val_type, None, size)