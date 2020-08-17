from rest_framework import serializers
from DeviceFingerprint.models import *

class DeviceSerializer(serializers.ModelSerializer):
	class Meta:
		model = Device
		fields = ['id','device_mac_address','device_ip_address', 'device_type', 'model_trained', 'updated_time']

	def to_representation(self, instance):
		ret = super().to_representation(instance)
		packets = list(instance.packet_set.all())
		ret["packet_count"] = len(packets)
		if not len(packets) == 0:
			ret["duration"] = int(packets[-1].packet_time - packets[0].packet_time)
		else:
			ret["duration"]  = 0
		return ret


class PacketSerializer(serializers.ModelSerializer):
	class Meta:
		model = PacketData
		fields = ['device', 'packet', 'packet_time', 'anomaly_water', 'benign','direction']
