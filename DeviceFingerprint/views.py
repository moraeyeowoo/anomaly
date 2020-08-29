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
from Analyze.model import *
from Analyze.packet_converter import *
from core.tasks import train_anomaly_model
from Analyze.classification import *
from sklearn.neighbors import KNeighborsClassifier
import pickle

def decode_packet(utf8_encoded_packet):
	import base64
	# decode to base 64
	base64_encoded = utf8_encoded_packet.encode('utf8')
	# decode to bytes
	bytes_encoded = base64.b64decode(base64_encoded)
	# convert to scapy packet object
	packet = Ether(bytes_encoded)
	return packet

class DeviceList(APIView):

	def get(self, request):
		devices = Device.objects.all()
		serializer = DeviceSerializer(devices,many=True)
		return Response(serializer.data, status = status.HTTP_200_OK)		

	def post(self, request):
		"""
		dlink cam 1, dlink2 sensor 2, xiaomi 3, edimax 4 
		"""

		labels = request.data["labels"]
		print(labels)
		device_map = {}
		knn_map = {}
		device_type_id = 0

		device_models = DeviceModels.objects.all()
		for device_model in device_models:
			device_model.delete()

		for key in labels:
			device_id = int(key)
			device_name = labels[key]
			print(device_name)
			# record the name of the device in database 
			device = Device.objects.get(pk=device_id)
			device.device_type = device_name
			device.save()

			packets = device.packet_set.all()
			if len(packets) < 100:
				continue

			if not (device_name == None or device_name ==""):
				device_map[device_id] = device_type_id
				print(device_name)
				data = {"internal_model_id": device_type_id,"model_name": device_name}
				print(data)
				serializer = DeviceModelsSerializer(data=data)
				serializer.is_valid()
				print("errors -----------------------")
				print(serializer.errors)
				print("-------------------------")
				serializer.save()
				device_type_id+=1

		# train KNN
		print(device_map)
		
		print("Obtaining fingerprint from device packets")
		for key in device_map:
			device = Device.objects.get(pk=key)
			packets = device.packet_set.all()
			packets = list(packets)
			packets.sort(key = lambda x: x.packet_time)
			if len(packets) > 3000:
				packets = packets[1000:]
			device_type_id = device_map[key]
			print(key)
			print(device_type_id)
			fingerprints = []
			if not len(packets) == 0:
				device_mac = device.device_mac_address
				sub_periods = get_sub_periods(packets, device_mac)
				filtered_periods = filter_periods(sub_periods)
				fingerprint = get_fingerprint(filtered_periods)	
				knn_map[device_type_id] = fingerprint
				print(fingerprint)

		# train the model here 
		print("Training K Nearest Neighborhood Model")
		X = []
		y = []
		for key in knn_map:
			y.append(key)
			y.append(key)
			y.append(key)
			fp = knn_map[key]
			X.append(fp)
			X.append(fp)
			X.append(fp)

		print(X)
		print(y)

		# train Knn model
		neigh = KNeighborsClassifier(n_neighbors=5)
		neigh.fit(X, y)
		
		print(neigh)
		knnPickle = open('knn_models/classifier', 'wb') 
		pickle.dump(neigh, knnPickle)   
		# save model 
		print("Training Complete")
		return Response(status = status.HTTP_200_OK)

class DeviceDetail(APIView):
	
	def get(self, request, pk):
		
		# to be used by ajax, 

		return Response(status = status.HTTP_200_OK)

	def post(self, request, pk):
		print("POST REQUEST")
		print(pk)
		device = Device.objects.get(pk=pk)
		packets = device.packet_set.all()
		# alert if collected packet is less than 30 seconds 
		packet_list = list(packets)
		if len(packet_list) == 0:
			print(len(packet_list))
			print("no enough packets")
			content ={"resp":"Not enough packets captured"}
			return Response(content, status.HTTP_404_NOT_FOUND)

		capture_duration = int(packet_list[-1].packet_time - packet_list[0].packet_time)
		print(capture_duration)
		if capture_duration < 1600:
			print("not enough packets")
			content ={"resp":"Not enough packets captured"}
			return Response(content, status.HTTP_404_NOT_FOUND)

		sub_periods = get_sub_periods(packets, device.device_mac_address)
		filtered_periods = filter_periods(sub_periods)
		fingerprint = get_fingerprint(filtered_periods)
		print(fingerprint)
		# load KNN model 
		PATH = "knn_models/classifier"
		loaded_model = pickle.load(open(PATH, 'rb'))
 
		# get integer from KNN predict
		print(fingerprint)
		result = loaded_model.predict([fingerprint])
		prob = loaded_model.predict_proba([fingerprint])
		print("result")
		print(result)
		print(result[0])
		print("prob")
		print(prob)
		device_type_id = int(result[0])
		device_model = DeviceModels.objects.get(internal_model_id=device_type_id)
		print(device_model.model_name)
		content = {"device_type":device_model.model_name}
		device.device_type = device_model.model_name
		device.save()
		#upate the model name of the unknown device 
		return Response(content, status = status.HTTP_200_OK)

class DeviceDetailPanel(APIView):
	renderer_classes = [TemplateHTMLRenderer]

	def get(self, request, pk):

		device = Device.objects.get(pk=pk)
		packets = device.packet_set.all()
		
		sub_periods = get_sub_periods(packets, device.device_mac_address)
		filtered_periods = filter_periods(sub_periods)
		metrics = get_characteristic_metric(filtered_periods)
		protocols = []
		L = []
		for key in metrics:
		    if not len(metrics[key]) == 0:
		        protocols.append(key)
		        for periods in metrics[key]:
		            l = []
		            l.append(key)
		            l.append(periods[0])
		            l.append(periods[1])
		            l.append(periods[2])
		            L.append(l)
		print(L)

		# draw graphs here 
		import matplotlib.pyplot as plt

		plt.subplots_adjust(hspace=0.1)
		x = list(range(0,900))
		fig, axs = plt.subplots(len(protocols), sharex=True, sharey=True,figsize=(10,10))

		"""
		axs[0].plot(x, edimax1_arp_ts[900:1800],'-x',color='magenta')
		axs[0].set_ylim([0, 2])
		axs[0].legend(['ARP'])
		"""

		index = 0
		for protocol in protocols:
			# get time stamps
			# draw 
			ts = get_time_series(packets, protocol, device.device_mac_address)
			axs[index].plot(x, ts[0:900], '-x', color='magenta')
			axs[index].legend([protocol])
			index+=1

		plt.savefig("graphs/test.png")
		data = {"metrics": L}
		return Response(data, template_name='classification_details.html')

		# variable number of pictures, path identified by pk

		# variable number of characteristic metrics


class ControlPanel(generics.RetrieveAPIView):
	renderer_classes = [TemplateHTMLRenderer]
	def get(self, request):
		devices = Device.objects.all()
		serializer = DeviceSerializer(devices,many=True)
		data = serializer.data
		devicelist = {"devices":data}
		return Response(devicelist, template_name='index.html')


class AnomalyPanel(generics.RetrieveAPIView):
	renderer_classes = [TemplateHTMLRenderer]
	def get(self, request):
		devices = Device.objects.all()
		serializer = DeviceSerializer(devices,many=True)
		data = serializer.data
		devicelist = {"devices":data}
		return Response(devicelist, template_name = 'anomaly.html')		




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
		pkt_dst_addr = packet.dst
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)
	# check if it is already in Device
	devices = Device.objects.filter(device_mac_address=pkt_src_addr)
	# if not save to Device
	# save regardless of source dst 
	ip_addr = " "


	# sometimes device gets registered without IP 
	if len(devices) == 0 and IP in packet:
		ip_addr = packet[IP].src
		print("registering device")
		data = {"device_mac_address":pkt_src_addr, "device_ip_address": ip_addr}
		serializer = DeviceSerializer(data=data,partial=True)
		if not serializer.is_valid():
			return Response(status=status.HTTP_404_NOT_FOUND)
		serializer.save()
	# save packet 
	# we need to save packets both originating from and headed to the device

	# direction 0 is source, 1 is dst

	try:
		device = Device.objects.get(device_mac_address=pkt_src_addr)
	except:
		return Response(status=status.HTTP_404_NOT_FOUND)

	data = {"device":device.pk, "packet":b64packet,"packet_time":packet_time,"direction":0 }
	serializer = PacketSerializer(data=data,partial=True)
	valid = serializer.is_valid()
	serializer.save()

	# also save if destination address match
	try:
		device = Device.objects.filter(device_mac_address=pkt_dst_addr)
	except:
		return Resposne(status=status.HTTP_404_NOT_FOUND)

	if len(devices) !=0:
		device = devices[0]
		data = {"device":device.pk, "packet":b64packet, "packet_time":packet_time,"direction":1}
		serializer = PacketSerializer(data=data, partial=True)
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


class AnomalyDetail(generics.RetrieveAPIView):
	#renderer_classes = [TemplateHTMLRenderer]
	# query the last n packets and detect anomaly 
	def get(self, request, pk):
		ANOMALY_INPUT_COUNT = 100
		# load model from path
		try:
			device = Device.objects.get(pk=pk)
		except:
			content = {"error":"device not found"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		# query last n number of packets, this works, i double checked
		detection_sequence = device.packet_set.order_by('pk')
		#no, this should apply to TCP packets, otherwise usesless 
		if len(detection_sequence) <= ANOMALY_INPUT_COUNT:
			content = {"error": "not enough packets to do anomaly detection"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		#detection_sequence = detection_sequence[:ANOMALY_INPUT_COUNT]
		packets = [ decode_packet(k.packet) for k in detection_sequence ]
		tcp_packets = [ pkt for pkt in packets if TCP in pkt ]
		# 

		tcp_packets_count = len(tcp_packets)
		train_packets_count = math.floor(tcp_packets_count/20) * 20
		tcp_packet_symbols = get_packet_symbols(tcp_packets,device.device_mac_address)

		anomaly_test_dataset = torch.tensor(tcp_packet_symbols[:train_packets_count]).reshape(-1,20,1)

		# load model, query model, get recon error 
		if device.model_trained == False:
			content = {"error":"model is training"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		try:
			PATH = device.anomaly_path
			model = torch.load(PATH)
		except:
			content = {"error":"model not trained"}
			return Response(content, status=status.HTTP_404_NOT_FOUND)

		prediction, losses = predict(model, anomaly_test_dataset)
		# return response 
		content = {"message": "Anomaly Query","losses":losses}
		device = {"device":device.device_mac_address}
		return Response(device, status = status.HTTP_200_OK)		
		#return Response(content, status = status.HTTP_200_OK)

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

		print("calling celery job")
		train_anomaly_model.delay(device.device_mac_address)
		print("called celery job")
		
		"""
		# query all data 
		packets = list(device.packet_set.all())
		if len(packets) <= ANOMALY_TRAIN_MIN_COUNT:
			content = {"error":"not enough packets"}
			return Response(content, status = status.HTTP_404_NOT_FOUND)

		collected_count = len(packets)
		steps = math.floor(collected_count/ANOMALY_INPUT_COUNT)
		
		# list of packets each length given by anomaly_input_count
		
		overlapping windows 
		packet_segments = []
		for k in range(0,steps):
			low = ANOMALY_TRAIN_MIN_COUNT *k
			high = ANOMALY_TRAIN_MIN_COUNT *(k+1)
			packet_segment = packets[low:high]
			packet_segments.append(packet_segment)
		"""
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


class AnomalyDetailPanel(generics.RetrieveAPIView):
	renderer_classes = [TemplateHTMLRenderer]

	def get(self, request, pk):

		# get last 200 packets from the device
		device = Device.objects.get(pk=pk)
		device
		packet_set = device.packet_set.order_by('pk')
	
		PATH = device.anomaly_path
	
		#if device.model_trained == False:
		loaded_model = torch.load(PATH)

		# test anomaly for everything
		tcp_packets = [ pkt for pkt in packet_set if TCP in decode_packet(pkt.packet)]
		tcp_packets_count = len(tcp_packets)
		# this has to be a multiple of 20 
		test_packets_count = math.floor(tcp_packets_count/20) * 20
		mac_address = device.device_mac_address
		
		test_packets_objects = tcp_packets[0:test_packets_count+1]

		test_packets = [ decode_packet(pkt.packet) for pkt in test_packets_objects ]

		packet_symbols = get_packet_symbols(test_packets,mac_address)
		
		steps = int(test_packets_count / 20)

		L = []
		for k in range(0,steps):
			low = 20*k
			high = 20 *(k+1)
			L.append(packet_symbols[low:high])
    
		all_losses = []
		index = 0
    	# get index from which anomaly starts 
		for l in L:	
			print(len(l))	
			input_symbols = torch.tensor(l).reshape(-1,20,1)
			pred,losses = predict(loaded_model,input_symbols)
			mean_loss = np.mean(losses)
			all_losses.append(mean_loss)
			index = index + 1

		display_symbols = []

		index = 0
		for mean_loss in all_losses:
			low = 20* index
			high = 20*(index+1)
			if mean_loss > 5:
				for sequence in packet_symbols[low:high]:
					print(sequence)
					display_symbols.append(sequence+[0])
			else:
				for sequence in packet_symbols[low:high]:
					print(sequence)
					display_symbols.append(sequence+[1])


		# get path for the image 
		content = []
		for symbol in display_symbols:
			representation = convert_symbol_to_string(symbol)
			content.append(representation)

		# render everything in template 
		data = {"symbols":content}

		return Response(data,template_name='anomaly_details.html')		

