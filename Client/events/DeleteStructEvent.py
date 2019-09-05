from IEvent import IEvent
import ida_struct
from constants import *
class DeleteStructEvent(IEvent):
	def __init__(self, id_of_struct):
		super(DeleteStructEvent, self).__init__(DELETE_STRUCT_ID, "Delete struct", {"id": id_of_struct})
		self._id = id_of_struct
	def implement(self):
		ida_struct.del_struc(ida_struct.get_struc(self._id))