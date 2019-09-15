from IEvent import IEvent
from constants import *

class StartIDAEvent(IEvent):
	def __init__(self):
		super(StartIDAEvent, self).__init__(START_IDA_ID, "Start IDA", {})