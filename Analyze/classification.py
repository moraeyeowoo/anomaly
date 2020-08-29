from scapy.all import * 
from scapy.layers.http import *
import math
import numpy as np
from scipy.fftpack import fft, ifft
import copy
import os
import statistics
from Analyze.packet_converter import *

dlink1_mac = "b0:c5:54:25:1f:b6"
dlink2_mac = "c4:12:f5:1c:8c:f1"
dlink3_mac = "b0:c5:54:25:22:64"
edimax1_mac = "74:da:38:4a:a9:75"

load_layer("tls")

"""
    packets : packets filtered by mac address for 30 mins
"""
# timeseries : flow
# l          : period. 
def calculate_Ryy(timeseries,l):
    return sum( [timeseries[k]*timeseries[k-l] for k in range(l, len(timeseries))])

# timeseries: flow
# l         : period , T_i 
def calculate_r(timeseries,l):
    Ryy = calculate_Ryy(timeseries, l)
    r = (l * Ryy) / len(timeseries)
    return r 

def calculate_rn(timeseries,l):
    numerator = l*(calculate_Ryy(timeseries, l-1)+calculate_Ryy(timeseries,l)+calculate_Ryy(timeseries,l+1))
    denominator = len(timeseries)
    return (numerator/denominator)

def get_time_series_bad(packets, protocol,src_mac_addr):

    pcap_packets = [ decode_packet(packet.packet) for packet in packets ]
    filtered_packets = []
    if protocol == 'IGMP':
        for pcap_packet in pcap_packets:
            if IP in pcap_packet and pcap_packet.proto ==2 and pcap_packet.src == src_mac_addr:
                filtered_packets.append(packet)

    elif protocol == 'SSDP':
        for pcap_packet in pcap_packets:
            if 'NOTIFY' in str(pcap_packet) or 'MSEARCH' in str(pcap_packet) and pcap_packet.src == src_mac_addr:
                filtered_packets.append(packet)

    elif protocol == 'HTTPS':
        for pcap_packet in pcap_packets:
            if TCP in pcap_packet:
                if pcap_packet[TCP].sport == 443 and TLS in pcap_packet[TCP] and pcap_packet.src== src_mac_addr:
                    filtered_packets.append(packet)

    elif protocol == 'MDNS':
        for pcap_packet in pcap_packets:
            if UDP in pcap_packet:
                if pcap_packet[UDP].sport == 5353 and DNS in pcap_packet and pcap_packet.src == src_mac_addr:
                    filtered_packets.append(packet)
    
    else:
        filtered_packets = list(filter(lambda pcap_packet: protocol in pcap_packet, pcap_packets)) 


    start_time = packets[0].packet_time
    duration = len(packets)
    end_time = packets[duration-1].packet_time
    timeseries_duration = math.ceil(end_time - start_time)
    indices = [ math.floor(packet.packet_time - start_time) for packet in filtered_packets]
    zeroes = [0] * timeseries_duration
    for index in indices:
        zeroes[index] = 1
    return zeroes



def get_time_series(packets, protocol,src_mac_addr):

    filtered_packets = []
    if protocol == 'IGMP':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if IP in pcap_packet and pcap_packet.proto ==2 and pcap_packet.src == src_mac_addr:
                filtered_packets.append(packet)

    elif protocol == 'SSDP':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if 'NOTIFY' in str(pcap_packet) or 'MSEARCH' in str(pcap_packet) and pcap_packet.src == src_mac_addr:
                filtered_packets.append(packet)

    elif protocol == 'HTTPS':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if TCP in pcap_packet:
                if pcap_packet[TCP].sport == 443 and TLS in pcap_packet[TCP] and pcap_packet.src== src_mac_addr:
                    filtered_packets.append(packet)

    elif protocol == 'MDNS':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if UDP in pcap_packet:
                if pcap_packet[UDP].sport == 5353 and DNS in pcap_packet and pcap_packet.src == src_mac_addr:
                    filtered_packets.append(packet)
    
    else:
        filtered_packets = list(filter(lambda x: protocol in decode_packet(x.packet), list(packets))) 


    start_time = packets[0].packet_time
    duration = len(packets)
    end_time = packets[duration-1].packet_time
    timeseries_duration = math.ceil(end_time - start_time)
    indices = [ math.floor(packet.packet_time - start_time) for packet in filtered_packets]
    zeroes = [0] * timeseries_duration
    for index in indices:
        zeroes[index] = 1
    return zeroes

def get_candidate_Ts(timeseries,tolerance=0.1):
    x = timeseries
    y = fft(x)
    y_abs = np.absolute(y)
    indices = range(0,len(timeseries))
    Yf = [ (k, y_abs[k]) for k in indices]   
    max_frequency = max(y_abs)
    L = [ tuple for tuple in Yf if tuple[1] > tolerance * max(y_abs)]
    candidates = [ len(timeseries) / tuple[0] for tuple in L if not tuple[0] == 0 ]
    Ts = [ np.floor(T) for T in candidates]
    return Ts


def confirm_Ts(Ts,timeseries):
    ret = set()
    Ts = [ int(x) for x in Ts]
    for T_i in Ts:
        # check if it is localco maximume
        low = int(T_i*0.9)
        high = int(T_i*1.1)
        candidates = list(range(low,high))
        l_i = max(candidates, key=lambda x:calculate_Ryy(timeseries,x))
        candidates_Ryy = [ calculate_Ryy(timeseries,x) for x in candidates]
        local_max = all(map(lambda x: l_i > x, candidates_Ryy))
        if local_max:
            ret.add(l_i)
    return ret

def get_Ts(timeseries, tolerance=0.1):
    candidate_Ts = get_candidate_Ts(timeseries,tolerance)
    removed_duplicates = set(candidate_Ts)
    removed_short = [ k for k in removed_duplicates if k>4 and k<600 ]
    Ts = confirm_Ts(removed_short, timeseries)
    Ts = [ T for T in Ts if calculate_r(timeseries, T)> 0.2 and calculate_r(timeseries,T)<5]
    return Ts

#ARP, IGMP, ICMP,TCP,UDP,  NBNS, DNS, SSDP
def get_periods(pcap_packets,start, end,src_mac_address):
    periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "DNS":None,"SSDP":None,"HTTP":None,"HTTPS":None, "MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTP", "HTTPS", "MDNS"]
    for protocol in protocols:
        timeseries = get_time_series(pcap_packets, protocol, src_mac_address)[start:end]
        Ts = get_Ts(timeseries, 0.1)
        periods[protocol] = (timeseries, Ts)
    return periods

def get_characteristic_metric(periods):
    metrics = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "DNS":None,"SSDP":None, "HTTP":None,"HTTPS":None,"MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP","DNS", "SSDP", "HTTP","HTTPS","MDNS"]
    for protocol in protocols:
        timeseries = periods[protocol][0]
        Ts = periods[protocol][1]
        feature_vector = []
        for T in Ts:
            r = calculate_r(timeseries, T)
            rn = calculate_rn(timeseries, T)
            feature_vector.append((T,r,rn))
        metrics[protocol] = feature_vector
    return metrics


# periods = { "sub_1":(flow,Ts)}

def get_sub_periods(packets,src_mac_address):
    sub_one_periods = get_periods(packets,0,900,src_mac_address)
    sub_two_periods = get_periods(packets,450,1450,src_mac_address)
    sub_three_periods = get_periods(packets,900,1800,src_mac_address)
    sub_all_periods = get_periods(packets,0,1800,src_mac_address)

    periods = {"sub_1":sub_one_periods, "sub_2":sub_two_periods,
        "sub_3":sub_three_periods,"all":sub_all_periods}
    return periods 

#periods that occur at least in two 
def filter_periods(periods):
    filtered_periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None,"DNS":None,"SSDP":None,"HTTP":None,"HTTPS":None,"MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTP","HTTPS","MDNS"]

    for protocol in protocols:
        sub_1 = periods['sub_1'][protocol][1]
        sub_2 = periods['sub_2'][protocol][1]
        sub_3 = periods['sub_3'][protocol][1]
        sub_all = periods['all'][protocol][1]
        all_intervals = set(sub_1+sub_2+sub_3+sub_all)
        timeseries = periods['all'][protocol][0]
        Ts = []
        for T in all_intervals:

            l = []
            l.append(T in sub_1)
            l.append(T in sub_2)
            l.append(T in sub_3)
            l.append(T in sub_all)
            # discared inferred from less than two 
            if l.count(True)>2:
                Ts.append(T)
        filtered_periods[protocol] = (timeseries,Ts)
    return filtered_periods


def get_fingerprint(periods):
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTPS","HTTP","MDNS"]    
    protocols_4 = ["ARP", "IGMP", "ICMP"]
    feature_1 = 0
    L = [len(periods[protocol][1]) for protocol in protocols]
    for l in L:
        if not l == 0:
            feature_1 = feature_1 + 1 

    if feature_1 == 0:
        return []

    feature_2 = 0
    L = [len(periods[protocol][1]) for protocol in protocols_4]
    for l in L:
        if not l == 0:
            feature_2 = feature_2 + 1

    # 3. mean periods per flow
    feature_3 = 0
    L = [len(periods[protocol][1]) for protocol in protocols]
    feature_3 = sum(L) / feature_1 

    # 4. SD periods per flow
    feature_4 = statistics.stdev(L)

    # 5. No of flows having only one period
    L = [ protocol for protocol in protocols if len(periods[protocol][1])==1]
    feature_5 = len(L)

    # 6. No of flow having multiple period. 
    L = [ protocol for protocol in protocols if len(periods[protocol][1])>1]
    feature_6 = len(L)

    # feature 7 ~ 12 don't bother 
    Ts = []
    for protocol in protocols:
        Ts = Ts+periods[protocol][1]
    # 13 periods in [5s: 29s]
    S = [ T for T in Ts if T>5 and T<30]  
    feature_13 = len(S)
    
    # 14 periods in [30,59]
    S = [ T for T in Ts if T>30 and T<60]
    feature_14 = len(S)

    # 15
    S = [ T for T in Ts if T>60 and T<120]
    feature_15 = len(S)
    
    # 16
    S = [ T for T in Ts if T>120 and T<600]
    feature_16 = len(S)

    metrics = get_characteristic_metric(periods)
    
    # Mean(r) in [0.2; 0.7]
    feature_17 = 0
    # Mean(r) in [0.7; 1]
    feature_18 = 0    
    # Mean(r) in [1;2]
    feature_19 = 0    
    # Mean(r) in [2; infin]
    feature_20 = 0    
    # SD(r) in [0;0.02]
    feature_21 = 0     
    # SD(r) in [0.02;0.1]
    feature_22 = 0
    # SD(r) in [0.1, infin\
    feature_23 = 0 
    # Mean(rn) in [0.2;0.7]
    feature_24 = 0
    # Mean(rn) in [0.7;1]
    feature_25 = 0
    # Mean(rn) in [1;2]
    feature_26 = 0
    # Mean(rn) in [2, infin]
    feature_27 = 0
    # SD(rn) in [0;0.02]
    feature_28 = 0
    # SD(rn) in [0.02; 0.1]
    feature_29 = 0
    # SD(rn) in [0.1 ; infin]
    feature_30 = 0 

    for key in metrics:
        if not len(metrics[key])==0:
            rs = [k[1] for k in metrics[key]]
            mean_r = np.mean(rs)
            SD_r = np.std(rs)
            rns = [k[2] for k in metrics[key]]
            mean_rn = np.mean(rns)
            SD_rn = np.std(rns)
            # feature for mean(r)
            if 0.2 < mean_r and 0.7 > mean_r:
                feature_17 +=1
            elif 0.7 < mean_r and 1.0 > mean_r:
                feature_18 +=1
            elif 1.0 < mean_r and 2.0 > mean_r: 
                feature_19 +=1
            elif 2.0 < mean_r:
                feature_20 +=1
            
            # feature for SD(r)  
            if 0.0 < SD_r and 0.02 > SD_r:
                feature_21 +=1
            elif 0.02 < SD_r and SD_r < 0.1:
                feature_22 +=1
            elif SD_r > 0.1:
                feature_23 +=1
            
            # feature for mean(r)
            if 0.2 < mean_rn and 0.7 > mean_r:
                feature_24 +=1
            elif 0.7 < mean_rn and 1.0 > mean_r:
                feature_25 +=1
            elif 1.0 < mean_rn and 2.0 > mean_r: 
                feature_26 +=1
            elif 2.0 < mean_rn:
                feature_27 +=1
            
            # feature for SD(r)  
            if 0.0 < SD_rn and 0.02 > SD_r:
                feature_28 +=1
            elif 0.02 < SD_rn and SD_r < 0.1:
                feature_29 +=1
            elif SD_rn > 0.1:
                feature_30 +=1

    ret = [
        feature_1,
        feature_2,
        feature_3,
        feature_4,
        feature_5,
        feature_6,
        feature_13,
        feature_14,
        feature_15, 
        feature_16, 
        feature_17,
        feature_18,
        feature_19,  
        feature_20,  
        feature_21,      
        feature_22,
        feature_23,
        feature_24,
        feature_25, 
        feature_26,
        feature_27, 
        feature_28,
        feature_29, 
        feature_30
    ]
    return ret 



def print_period(timestamps, l):
    n = len(timestamps)//l
    for k in range(0,n):
        low = l*k
        high =l*k+l
        print(timestamps[low:high])


# features from 1 to 16 concerns only periods#
# features from 17 to 33 concerns also characteristic metric
# we need bin function
def create_bin(periods):
    # 1. filter periods
    # 2. get metric
    # 3. for each 
    pass