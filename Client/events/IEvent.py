import json

def decode_bytes(val):
	if not isinstance(val, str):
		return val
	return val.decode("raw_unicode_escape")

def encode_bytes(val):
	if not isinstance(val, str):
		return val
	return val.encode("raw_unicode_escape")
	
class IEvent(object):
	def __init__(self, event_id, name, data):
		self.id_ = event_id
		self.name_ = name
		self.data_ = data

	def encode_to_json(self):
		return json.dumps({"event-id": self.id_,
				"name": self.name_,
				"data": self.data_})

	def implement(self):
		pass