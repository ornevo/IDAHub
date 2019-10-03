from IEvent import IEvent
import idaapi
import idc
import ida_lines
from constants import *

class ChangeCommentEvent(IEvent):
	def __init__(self, linear_address, value, comment_type, line_idx):
		super(ChangeCommentEvent, self).__init__(SET_COMMENT_ID, "Comments", {"linear-address": linear_address, "value": value, "comment-type": comment_type, "name": str(line_idx)})
		self._linear_address = linear_address
		self._comment_type = comment_type
		self._value = value
		self._idx = int(line_idx)
		

	def implement(self):
		if self._comment_type == "regular":
			idaapi.set_cmt(self._linear_address, self._value, 0)
		elif self._comment_type == "repetable":
			idaapi.set_cmt(self._linear_address, self._value, 1)
		elif self._comment_type == "function":
			idc.set_func_cmt(self._linear_address, self._value, 0)
		elif self._comment_type == "anterior" or self._comment_type == "posterior":
			ida_lines.del_extra_cmt(self._linear_address, self._idx)
			is_anterior = 1 if self._idx - 1000 < 1000 else 0
			if not self._value:
				return 0
			ida_lines.add_extra_cmt(self._linear_address, is_anterior, self._value)