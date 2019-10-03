from IEvent import IEvent
import ida_enum
from constants import *

class ChangeEnumMemberName(IEvent):
	def __init__(self, id_of_enum, value):
		super(ChangeEnumMemberName, self).__init__(CHANGE_ENUM_MEMBER_NAME_ID, "Change enum member name", {"id": id_of_enum, "value": value})
		self._id = id_of_enum
		self._value = value

	def implement(self):
		id_of_enum_member = ida_enum.get_enum_member_by_name(str(self._id))
		ida_enum.set_enum_member_name(id_of_enum_member, self._value)