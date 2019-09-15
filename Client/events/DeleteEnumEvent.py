from IEvent import IEvent
import ida_enum
from constants import *
class DeleteEnumEvent(IEvent):
	def __init__(self, id_of_enum):
		super(DeleteEnumEvent, self).__init__(DELETE_ENUM_ID, "Delete enum", {"id": id_of_enum})
		self._id = id_of_enum
	
	def implement(self):
		ida_enum.del_enum(self._id)