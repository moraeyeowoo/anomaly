from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics,mixins
from DeviceFingerprint.models import * 
from scapy.all import *
from DeviceFingerprint.serializers import *

def decode_packet(utf8_encoded_packet):
	import base64
	# decode to base 64
	base64_encoded = utf8_encoded_packet.encode('utf8')
	# decode to bytes
	bytes_encoded = base64.b64decode(base64_encoded)
	# convert to scapy packet object
	packet = Ether(bytes_encoded)
	return packet

# Create your views here.
@api_view(['POST'])
def receive_packet(request):
	payload = request.data["payload"]
	print(type(payload))
	packet = decode_packet(payload)
	print(packet.time)

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

	timestamp = packet.time
	type(timestamp)
	data = {"device":device.pk, "packet":payload,"packet_time":timestamp }
	serializer = PacketSerializer(data=data)
	valid = serializer.is_valid()
	print(valid)
	serializer.save()
	return Response(status = status.HTTP_200_OK)

@api_view(['POST'])
def echo_packet(request):
	payload = request.data["payload"]
	print(type(payload))
	packet = decode_packet(payload)
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

	packets = device.packet_set.all()
	# fingerprint

	# call KNN model

	# classify 

	# return type 

@api_view(['POST'])
def label_device(request,pk):
	return Response(status=status.HTTP_200_OK)