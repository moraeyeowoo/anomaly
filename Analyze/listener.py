from scapy.all import *
from DeviceFingerprint.models import 

def encode_packet(packet):
	#encode to bytes
	bytes_encoded = bytes(packet)
	#encode to b64
	base64_encoded = base64.b64encode(bytes_encoded)
	#encode utf8
	utf8_encoded = base64_encoded.decode('utf8')
	print(type(utf8_encoded))
	return utf8_encoded



class Observer:
    def update(observable, arg):
        pass

class PacketObserver(Observer):

	def __init__(self, mac_address):
		Observer.__init__(self)
		self.device_mac_address = mac_address
		self.packets = []
		self.starttime = None

	def update(self, packet):
		if packet.src == self.device_mac_address:
			print("match")
			self.packets.append(packet)
		else:
			print("not my packet")
		
		start_pk = self.packets[0]
		if packet.time - start_pk.time > 10:
			print("fingerprinting")


class Observable:
	def __init__(self):
		self.obs = []
		self.changed = 0

	def addObserver(self, observer):
		if observer not in self.obs:
			self.obs.append(observer)

	def deleteObserver(self, observer):
		self.obs.remove(observer)

	def notifyObservers(self, arg):
		for observer in self.obs:
			observer.update(arg)

	def deleteObservers(self):
		self.obs=[]


 
class PacketCapturedNotifier(Observable):

	def __init__(self):
		self.mac_list = set()
		Observable.__init__(self)


class PacketListener:
    def __init__(self):
        self.packetCapturedNotifier = PacketCapturedNotifier()

    def process_packets(self,pk):
    	mac_list = self.packetCapturedNotifier.mac_list
    	if not pk.src in mac_list:
    		self.packetCapturedNotifier.mac_list.add(pk.src)
    		observer = PacketObserver(pk.src)
    		# save device name to database

    		self.packetCapturedNotifier.addObserver(observer)

    	self.packetCapturedNotifier.notifyObservers(pk)