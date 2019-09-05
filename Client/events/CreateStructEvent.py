from IEvent import IEvent
import ida_struct
from constants import *
class CreateStructEvent(IEvent):
	def __init__(self, name_of_struct, id_of_struct):
		super(CreateStructEvent, self).__init__(CREATE_STRUCT_ID, "Create new struct", {"name": name_of_struct, "id": id_of_struct})
		self._name = name_of_struct
		self._id = id_of_struct
	
	def implement(self):
		ida_struct.add_struc(self._id, self._name)