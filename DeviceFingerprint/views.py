from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics,mixins
from DeviceFingerprint.models import * 
from scapy.all import *
from DeviceFingerprint.serializers import *
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework import generics


def decode_packet(utf8_encoded_packet):
	import base64
	# decode to base 64
	base64_encoded = utf8_encoded_packet.encode('utf8')
	# decode to bytes
	bytes_encoded = base64.b64decode(base64_encoded)
	# convert to scapy packet object
	packet = Ether(bytes_encoded)
	return packet

class ControlPanel(generics.RetrieveAPIView):
	renderer_classes = [TemplateHTMLRenderer]
	template_name = 'index.html'

	def get(self, request):
		devices = {"device1":"mac address"}
		return Response(devices)

 
@api_view(['GET'])
def get_devices(request):
	devices = Device.objects.all()
	serializer = DeviceSerializer(devices,many=True)
	return Response(serializer.data, status=status.HTTP_200_OK)


# Create your views here.
@api_view(['POST'])
def receive_packet(request):
	b64packet = request.data["b64packet"]
	packet = decode_packet(b64packet)
	packet_time = Decimal(request.data["packet_time"])
	print(packet_time)
	# get device mac address
	try:
		pkt_src_addr = packet.src
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)
	# check if it is already in Device
	devices = Device.objects.filter(device_mac_address=pkt_src_addr)
	# if not save to Device
	if len(devices) == 0:
		print("registering device")
		data = {"device_mac_address":pkt_src_addr}
		serializer = DeviceSerializer(data=data,partial=True)
		if not serializer.is_valid():
			return Response(status=status.HTTP_404_NOT_FOUND)
		serializer.save()
	# save packet 
	try:
		device = Device.objects.get(device_mac_address=pkt_src_addr)
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)

	data = {"device":device.pk, "packet":b64packet,"packet_time":packet_time }
	serializer = PacketSerializer(data=data)
	valid = serializer.is_valid()
	serializer.save()
	return Response(status = status.HTTP_200_OK)

@api_view(['POST'])
def get_packet(request, format=None):
	b64_packet = request.data["packet"]
	packet_time = Decimal(request.data["timestamp"])
	packet = decode_packet(b64_packet)

	try:
		device_mac_address = packet.src
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)
	devices = Device.objects.filter(device_mac_address=device_mac_address)
	if len(devices) == 0:
		data = {"device_mac_address":device_mac_address}
		serializer = DeviceSerializer(data=data,partial=True)
		serializer.is_valid()
		serializer.save()

	try:
		device = Device.objects.get(device_mac_address=pkt_src_addr)
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)

	data = {"device":device.pk, "packet":b64_packet, "packet_time":packet_time}
	serializer = PacketSerializer(data=data)
	if not serializer.is_valid():
		return Response(status=status.HTTP_404_NOT_FOUND)
	serializer.save()
	return Response(status=status.HTTP_200_OK)



@api_view(['POST'])
def echo_packet(request):
	payload = request.data["b64packet"]
	print(type(payload))
	packet = decode_packet(payload)
	print(packet.time)
	packet_time = request.data["packet_time"]
	print(packet_time)

	return Response(payload, status = status.HTTP_200_OK)

# choice 1. User observers and wait for 30 mins before capture
# choice 2. Save whole packet 
# choice 2. Lets go with choice 2
 
@api_view(['GET'])
def identify_device(request,pk):
	try:
		device = Device.objects.get(pk=pk)
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)

	# get packet for 30 mins 
	packets = device.packet_set.all().order_by('-packet_time')
	end_time = packets[0].packet_time
	packets = device.packet_set.all().filter(packet_time__gte=end_time-3600)

	# fingerprint
	filtered_packets = list(filter(lambda x:ARP in decode_packet(x.packet), list(packets))) 
	# call KNN model


	# classify 


	# return type 

@api_view(['GET'])
def save_packet(request, pk):
	import datetime 
	
	device = Device.objects.get(pk=pk)
	pkt_base64_list = device.packet_set.all()
	suffix = str(datetime.datetime.now()).replace(":","").replace(" ","-")
	prefix = device.device_mac_address.replace(":","")
	filename = prefix+"-"+suffix+".pcap"
	for pkt_base64 in pkt_base64_list:
		pkt = decode_packet(pkt_base64.packet)
		wrpcap(filename, pkt)

	return Response(status=status.HTTP_200_OK)

@api_view(['POST'])
def label_device(request,pk):
	return Response(status=status.HTTP_200_OK)


class ControlPanel(generics.RetrieveAPIView):
	renderer_classes = [TemplateHTMLRenderer]
	template_name = 'anomaly.html'

	def get(self, request):
		devices = {"device1":"mac address"}
		return Response(devices)

class AnomalyDetail(generics.RetrieveAPIView):

	# query the last n packets and detect anomaly 
	def get(self, request, pk):
		ANOMALY_INPUT_COUNT = 100
		# load model from path
		try:
			device = Device.objects.get(pk=pk)
		except:
			content = {"error":"device not found"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		# query last n number of packets
		detection_sequence = list(device.packet_set.order_by('pk')[:ANOMALY_INPUT_COUNT])
		if len(detection_sequence) <= ANOMALY_INPUT_COUNT:
			content = {"error": "not enough packets to do anomaly detection"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		# fingerprint, convert to pytorch tensor 


		# load model, query model, get recon error 
		try:
			model_path = device.anomaly_path
		except:
			content = {"error":"model not trained"}
			return Response(content, status=status.HTTP_404_NOT_FOUND)


		# return response 
		content = {"message": "Anomaly Query"}
		return Response(content, status = status.HTTP_200_OK)

	# create a new model for anomaly, this may take long time. may need to use async  
	def post(self, request, pk):
		ANOMALY_TRAIN_MIN_COUNT = 1500
		ANOMALY_INPUT_COUNT = 100
		WINDOW_OVERLAP_SIZE = 50 
		# create models
		import math

		try:
			device = Device.objects.get(pk=pk)
		except:
			content = {"error":"device not found"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		# query all data 
		packets = list(device.packet_set.all())
		if len(packets) <= ANOMALY_TRAIN_MIN_COUNT:
			content = {"error":"not enough packets"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		collected_count = len(packets)
		steps = math.floor(collected_count/ANOMALY_INPUT_COUNT)
		
		# list of packets each length given by anomaly_input_count
		packet_segments = []
		for k in range(0,steps):
			low = ANOMALY_TRAIN_MIN_COUNT *k
			high = ANOMALY_TRAIN_MIN_COUNT *(k+1)
			packet_segment = packets[low:high]
			packet_segments.append(packet_segment)

		# record pk of the last index 
		high_water_mark = packets[-1].pk
		device.anomaly_hwm = high_water_mark
		device.save()



		# train 


		# save model 

		content = {"message": "Train Model"}
		return Response(content, status = status.HTTP_200_OK)

	# update existing model 
	def put(self, request, pk):

		# load model from path
		ANOMALY_TRAIN_MIN_COUNT = 1500
		ANOMALY_INPUT_COUNT = 100
		WINDOW_OVERLAP_SIZE = 50 
		# create models
		import math

		try:
			device = Device.objects.get(pk=pk)
		except:
			content = {"error":"device not found"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)
		# query everything starting from high water mark 

		# update model starting from high water mark

		# save model to path 

		content = {"message": "Update Model"}
		return Response(content, status = status.HTTP_200_OK)
