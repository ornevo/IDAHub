from IEvent import IEvent
from constants import *

class ExitIDBEvent(IEvent):
	def __init__(self):
		super(ExitIDBEvent, self).__init__(EXIT_FROM_IDA_ID, "Exit from IDA", {})