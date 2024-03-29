from IEvent import IEvent
import ida_enum
from constants import *

class ChangeEnumNameEvent(IEvent):
	def __init__(self, id_of_enum, value):
		super(ChangeEnumNameEvent, self).__init__(CHANGE_ENUM_NAME_ID, "Change enum name", {"id": id_of_enum, "value": value})
		self._id = id_of_enum
		self._value = value

	def implement(self):
		id_of_enum = ida_enum.get_enum(str(self._id))
		ida_enum.set_enum_name(id_of_enum, self._value)