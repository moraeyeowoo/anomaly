from rest_framework import serializers
from DeviceFingerprint.models import *
import datetime


class DeviceSerializer(serializers.ModelSerializer):
	class Meta:
		model = Device
		fields = ['id','device_mac_address','device_ip_address', 'device_type', 'model_trained', 'updated_time']

	def to_representation(self, instance):
		ret = super().to_representation(instance)
		packets = list(instance.packet_set.all())
		ret["packet_count"] = len(packets)
		#ret["first_capture"] = str(datetime.timedelta(seconds = int(packets[0].packet_time)))
		#ret["last_capture"] = str(datetime.timedelta(seconds = int(packets[-1].packet_time)))

		if not len(packets) == 0:
			duration = int(packets[-1].packet_time - packets[0].packet_time)
			a= datetime.timedelta(seconds = duration)
			ret["duration"] = str(a)
		else:
			a = datetime.timedelta(seconds = 0)
			ret["duration"]  = str(a)
		return ret


class PacketSerializer(serializers.ModelSerializer):
	class Meta:
		model = PacketData
		fields = ['device', 'packet', 'packet_time', 'anomaly_water', 'benign','direction']

class DeviceModelsSerializer(serializers.ModelSerializer):
	class Meta:
		model = DeviceModels
		fields = ['internal_model_id','model_name']