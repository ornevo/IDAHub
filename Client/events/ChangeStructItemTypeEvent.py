from IEvent import IEvent
import idc
import constants
import ida_bytes
import ida_struct
import ida_nalt
class ChangeStructItemTypeEvent(IEvent):
	def __init__(self, id_of_struct, offset, variable_type):
		super(ChangeStructItemTypeEvent, self).__init__(constants.CHANGE_STRUCT_ITEM_TYPE_ID, "Change struct item type", {"id": id_of_struct, "offset": offset, "variable-type": variable_type})
		self._id = id_of_struct
		self._offset = offset
		self._value = variable_type
	
	def implement(self):
		id_of_struct = ida_struct.get_struc_id(str(self._id))
		sturct_obj = ida_struct.get_struc(long(id_of_struct))
		flags = 0
		size = 0
		if self._value == "db":
			flags = ida_bytes.FF_BYTE
			size = 1
		elif self._value == "dw":
			flags = ida_bytes.FF_WORD
			size = 2
		elif self._value == "dd":
			flags = ida_bytes.FF_DWORD
			size = 4
		elif self._value == "dq":
			flags = ida_bytes.QWORD
			size = 8
		ida_struct.set_member_type(sturct_obj, int(self._offset), flags, ida_nalt.opinfo_t(), size)
