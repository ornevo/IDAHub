from IEvent import IEvent
import idc
import ida_struct
from constants import *
class ChangeStructItemEvent(IEvent):
	def __init__(self, id_of_struct, offset, value):
		super(ChangeStructItemEvent, self).__init__(CHANGE_STRUCT_MEMBER_NAME_ID, "Change struct item name", {"offset":offset, "id": id_of_struct, "value": value})
		self._id = id_of_struct
		self._offset = offset
		self._value = value

	def implement(self):
		id_of_struct = ida_struct.get_struc_id(str(self._id))
		ida_struct.set_member_name(ida_struct.get_struc(id_of_struct), int(self._offset), str(self._value))