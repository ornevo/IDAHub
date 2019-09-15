from IEvent import IEvent
import ida_struct
from constants import *
class CreateStructVariableEvent(IEvent):
	def __init__(self, id_of_struct, offset, variable_type, value):
		super(CreateStructVariableEvent,self).__init__(CREATE_STRUCT_VARIABLE_ID, "Create struct variable", {"id": id_of_struct, "offset": offset, "variable-type": variable_type, "value": value})	
		self._id = id_of_struct
		self._offset = offset
		self._variable_type = variable_type
		self._value = value
	
	def implement(self):
		sturct_obj = ida_struct.get_struc(self._id)
		val_type  = ""
		if self._variable_type == "db":
			val_type = ida_sturct.FF_BYTE
		elif self._variable_type == "dw":
			val_type = ida_sturct.FF_WORD
		elif self._variable_type == "dd":
			val_type = ida_sturct.FF_DWORD
		elif self._variable_type == "dq":
			val_type = ida_sturct.FF_QWORD
		else:
			val_type = ida_sturct.FF_STRUCT
		ida_sturct.add_struc_member(sturct_obj, self._value, self._offset, val_type, None, 0 )