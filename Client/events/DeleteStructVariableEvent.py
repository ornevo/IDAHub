from IEvent import IEvent
import ida_struct
class DeleteStructVariableEvent(IEvent):
	def __init__(self, id_of_struct, offset):
		super(DeleteStructVariableEvent, self).__init__(12, "Delete struct variable", {"id": str(id_of_struct), "offset": offset})
		self._id = id_of_struct
		self._offset = offset
		
	def implement(self):
		id_of_struct = ida_struct.get_struc_id(str(self._id))
		ida_struct.del_struc_member(ida_struct.get_struc(id_of_struct), int(self._offset))