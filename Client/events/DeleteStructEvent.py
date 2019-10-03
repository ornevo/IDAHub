from IEvent import IEvent
import ida_struct
from constants import *
class DeleteStructEvent(IEvent):
	def __init__(self, id_of_struct):
		super(DeleteStructEvent, self).__init__(DELETE_STRUCT_ID, "Delete struct", {"id": str(id_of_struct)})
		self._id = id_of_struct
	def implement(self):
		id_of_struct = ida_struct.get_struc_id(str(self._id))
		sturct_obj = ida_struct.get_struc(long(id_of_struct))
		ida_struct.del_struc(sturct_obj)