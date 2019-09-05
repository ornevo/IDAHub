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
		ida_enum.add_enum_member(self._id, self._name, self._value)