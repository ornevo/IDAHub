from IEvent import IEvent
import ida_enum
from constants import *
class DeleteEnumMemberEvent(IEvent):
	def __init__(self, id_of_struct, member_id):
		super(DeleteEnumMemberEvent, self).__init__(DELETE_ENUM_MEMBER_ID, "Delete enum member", {"id": id_of_struct, "value": member_id})
		self._member_id = member_id
		self._id = id_of_struct

	def implement(self):
		enum_name = ida_enum.get_enum_name(self._id)
		value = ida_enum.get_enum_member_value(self._member_id)
		serial = ida_enum.get_enum_member_serial(self._member_id)
		bmask = ida_enum.get_enum_member_bmask(self._member_id)
		ida_enum.del_enum_member(enum_name, value, serial, bmask)