from IEvent import IEvent
import idc
from constants import *
class CreateEnumEvent(IEvent):
	def __init__(self, name, id_of_enum):
		super(CreateEnumEvent, self).__init__(CREATE_ENUM_ID, "Create enum", {"name": name, "id" :id_of_enum})
		self._id = id_of_enum
		self._name = name

	def implement(self):
		idc.AddEnum(self._id, self._name, 0)