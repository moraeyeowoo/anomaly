from django.db import models
from django.contrib.postgres.fields import ArrayField

# Create your models here.
class Device(models.Model):
	device_mac_address = models.CharField(max_length=25,unique=True)
	device_type = models.CharField(max_length=25,null=True)

class PacketData(models.Model):
	device = models.ForeignKey(Device, related_name='packet_set', on_delete=models.CASCADE)
	packet = models.TextField(default='')
	packet_time = models.DecimalField(max_digits=16, decimal_places=16,default=0.0)
	arrival_time = models.TimeField(auto_now=True)

class TypeFingerprint(models.Model):
	device = models.ForeignKey(Device,related_name='type_fingerprint',on_delete=models.CASCADE)
	flow = ArrayField(models.IntegerField())
	fingerprint = ArrayField(models.IntegerField())

class AnomalyFingerprint(models.Model):
	device = models.ForeignKey(Device,related_name='anomaly_fingerprint',on_delete=models.CASCADE)
	fingerprint = ArrayField(models.IntegerField())