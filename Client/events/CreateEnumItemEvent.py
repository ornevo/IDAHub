from IEvent import IEvent
import ida_enum
from constants import *
class CreateEnumItemEvent(IEvent):
	def __init__(self, id_of_enum, name, value):
		super(CreateEnumItemEvent, self).__init__(CREATE_ENUM_ITEM_ID, "Create enum item", {"id": id_of_enum, "name": name, "value": value})
		self._id = id_of_enum
		self._name = name
		self._value = value

	def implement(self):
		id_of_enum = ida_enum.get_enum(str(self._id))
		ida_enum.add_enum_member(id_of_enum, self._name, long(self._value))