from rest_framework import serializers
from DeviceFingerprint.models import *

class DeviceSerializer(serializers.ModelSerializer):
	class Meta:
		model = Device
		fields = ['id','device_mac_address','device_type']

class PacketSerializer(serializers.ModelSerializer):
	class Meta:
		model = PacketData
		fields = ['device', 'packet', 'packet_time']