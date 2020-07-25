from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.
class Device(models.Model):
	device_mac_address = models.CharField(max_length=25,unique=True)
	device_ip_address = models.CharField(max_length=25,null=True)
	device_type = models.CharField(max_length=25,null=True)
	collected_time = models.IntegerField(null=True)
	anomaly_hwm = models.IntegerField(null=True)
	anomaly_path = models.CharField(max_length=256,null=True)

class PacketData(models.Model):
	device = models.ForeignKey(Device, related_name='packet_set', on_delete=models.CASCADE)
	packet = models.TextField(default='')
	packet_time = models.DecimalField(max_digits=64, decimal_places=32,default=0.0)

class TypeFingerprint(models.Model):
	device = models.ForeignKey(Device,related_name='type_fingerprint',on_delete=models.CASCADE)
	flow = ArrayField(models.IntegerField())
	fingerprint = ArrayField(models.IntegerField())

class AnomalyFingerprint(models.Model):
	device = models.ForeignKey(Device,related_name='anomaly_fingerprint',on_delete=models.CASCADE)
	fingerprint = ArrayField(models.IntegerField())