from DeviceFingerprint.models import Device, PacketData
from Analyze.packet_converter import *
from Analyze.model import *

from celery import shared_task


@shared_task
def train_anomaly_model(device_mac_address):
	
	import math
	print("called celery task!!")
	try:
		device = Device.objects.get(device_mac_address=device_mac_address)
	except:
		return 'device not found'

	PATH = device.anomaly_path

	packet_set = device.packet_set.all()
	if device.anomaly_hwm != -1:
		# we have to filter
		print("hwm was updated")
	detection_sequence = list(device.packet_set.order_by('pk'))
	packets = [ decode_packet(k.packet) for k in detection_sequence ]
	tcp_packets = [ pkt for pkt in packets if TCP in pkt ]

	tcp_packets_count = len(tcp_packets)
	train_packets_count = math.floor(tcp_packets_count/20) * 20
	tcp_packet_symbols = get_packet_symbols(tcp_packets,device_mac_address)
	train_dataset = torch.tensor(tcp_packet_symbols[:train_packets_count]).reshape(-1,20,1)

	# get high water mark 
	train_count = len(detection_sequence)
	hwm = detection_sequence[train_count-1]
	device.anomaly_hwm = hwm 

	model = RecurrentAutoencoder(20,1)
	print("--------------------")
	train_model(model, train_dataset, 20)
	device.model_trained = True

	if PATH == None:
		PATH = device.device_mac_address.replace(":","")+"model"
		device.anomaly_path = PATH

	torch.save(model, PATH)
	device.model_trained = True
	device.save()

	return 'Anomaly model trained'


@shared_task
def create_random_user_accounts(total):
    for i in range(total):
        username = 'user_{}'.format(get_random_string(10, string.ascii_letters))
        email = '{}@example.com'.format(username)
        password = get_random_string(50)
        User.objects.create_user(username=username, email=email, password=password)
    return '{} random users created with success!'.format(total)