from IEvent import IEvent
import idaapi
import idc
import ida_lines
from constants import *

class ChangeCommentEvent(IEvent):
	def __init__(self, linear_address, value, comment_type):
		super(ChangeCommentEvent, self).__init__(SET_COMMENT_ID, "Comments", {"linear-address": linear_address, "value": value, "comment-type": comment_type})
		self._linear_address = linear_address
		self._comment_type = comment_type
		self._value = value
		

	def implement(self):
		if self._comment_type == "regular":
			idaapi.set_cmt(self._linear_address, self._value, 0)
		elif self._comment_type == "repetable":
			idaapi.set_cmt(self._linear_address, self._value, 1)
		elif self._comment_type == "function":
			idc.set_func_cmt(self._linear_address, self._value, 0)
		elif self._comment_type == "anterior":
			ida_lines.add_extra_cmt(self._linear_address, 1, self._value)
		elif self._comment_type == "posterior":
			ida_lines.add_extra_cmt(self._linear_address, 0, self._value)