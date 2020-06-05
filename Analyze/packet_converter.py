import base64
from scapy.all import *


def encode_packet(packet):
	#encode to bytes
	bytes_encoded = bytes(packet)
	#encode to b64
	base64_encoded = base64.b64encode(bytes_encoded)
	#encode utf8
	utf8_encoded = base64_encoded.decode('utf8')
	print(type(utf8_encoded))
	return utf8_encoded
 
def decode_packet(utf8_encoded_packet):
	# decode to base 64
	base64_encoded = utf8_encoded_packet.encode('utf8')
	# decode to bytes
	bytes_encoded = base64.b64decode(base64_encoded)
	# convert to scapy packet object
	packet = Ether(bytes_encoded)
	return packet
