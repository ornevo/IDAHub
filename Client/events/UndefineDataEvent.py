from IEvent import IEvent
import ida_bytes
from constants import *
class UndefineDataEvent(IEvent):
	def __init__(self, linear_address):
		super(UndefineDataEvent, self).__init__(UNDEFINE_DATA_ID, "Undefine data", {"linear-address": linear_address})
		self._ea = linear_address

	def implement(self):
		ida_bytes.del_items(self._ea)