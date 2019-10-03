from IEvent import IEvent
import ida_enum
from constants import *
class DeleteEnumMemberEvent(IEvent):
	def __init__(self, id_of_struct, value, serial, bmask):
		super(DeleteEnumMemberEvent, self).__init__(DELETE_ENUM_MEMBER_ID, "Delete enum member", {"id": id_of_struct, "value": "{0}:{1}:{2}".format(value, serial, bmask)})
		self._value = int(value)
		self._serial = int(serial)
		self._bmask = int(bmask)
		self._id = id_of_struct

	def implement(self):
		enum_id = ida_enum.get_enum(str(self._id))
		ida_enum.del_enum_member(enum_id, self._value, self._serial, self._bmask)