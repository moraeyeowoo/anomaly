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


def get_time_series(packets, protocol):

    filtered_packets = []
    if protocol == 'IGMP':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if IP in pcap_packet and pcap_packet.proto ==2:
                filtered_packets.append(packet)
    if protocol == 'SSDP':
        for packet in packets:
            pcap_packet = decode_packet(packet.packet)
            if 'NOTIFY' in str(pcap_packet) or 'MSEARCH' in str(pcap_packet):
                filtered_packets.append(packet)
    
    if protocol == 'TCP':        
        filtered_packets_1st = list(filter(lambda x: protocol in decode_packet(x.packet), list(packets)))
        filtered_packets = list(filter(lambda x: not TLS in decode_packet(x.packet),list(filtered_packets_1st)))
    
    if protocol == 'MDNS':
        filtered_packets_1st = list(filter(lambda x: DNS in decode_packet(x.packet), list(packets)))
        filtered_packets =     list(filter(lambda x: decode_packet(x.packet).sport ==5353, list(filtered_packets_1st)))
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
def get_periods(pcap_packets,start, end):
    periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "DNS":None,"SSDP":None,"HTTP":None,"TLS":None, "MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTP", "TLS", "MDNS"]
    for protocol in protocols:
        timeseries = get_time_series(pcap_packets, protocol)[start:end]
        Ts = get_Ts(timeseries, 0.1)
        periods[protocol] = (timeseries, Ts)
    return periods

def get_characteristic_metric(periods):
    metrics = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "DNS":None,"SSDP":None, "HTTP":None,"TLS":None,"MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP","DNS", "SSDP", "HTTP","TLS","MDNS"]
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

def get_sub_periods(packets):
    sub_one_periods = get_periods(packets,0,900)
    sub_two_periods = get_periods(packets,450,1450)
    sub_three_periods = get_periods(packets,900,1800)
    sub_all_periods = get_periods(packets,0,1800)

    periods = {"sub_1":sub_one_periods, "sub_2":sub_two_periods,
        "sub_3":sub_three_periods,"all":sub_all_periods}
    return periods 

#periods that occur at least in two 
def filter_periods(periods):
    filtered_periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None,"DNS":None,"SSDP":None,"HTTP":None,"TLS":None,"MDNS":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTP","TLS","MDNS"]

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


def fingerprint(periods):
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP","HTTP","TLS","MDNS"]    
    protocols_4 = ["ARP", "IGMP", "ICMP","HTTP","TLS","MDNS"]
    feature_1 = 0
    L = [len(periods[protocol][1]) for protocol in protocols]
    for l in L:
        if not l == 0:
            feature_1 = feature_1 + 1 

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
    feature4 = statistics.stdev(L)

    # 5. No of flows having only one period
    L = [ protocol for protocol in protocols if len(periods[protocol][1])==1]
    feature_5 = len(L)

    # 6. No of flow having multiple period. 
    L = [ protocol for protocol in protocols if len(periods[protocol][1])>1]
    feature_6 = len(L)

    # feature 7,8,9 don't bother 

    # 10 11, 12, don'/t bother

    #

    # 

    # for each flow, for each periods, calculate r and rn
    #  should be done on filtered periods instead
    #  sum periods across all flows/ 

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


    # 17 to 33 
    # call 
    filtered_periods = filter_periods(periods)
    metrics = get_characteristic_metric(periods)
    # sum accross all protocols

    # for each period, calculate mean r f
    # standard deviation doesn't mean anything 

    # 17 # Mean(r) in [0.2:0.7]
    # mean for what? for a protocol?     
    # average r and rn for each metric

    # 18 # Mean(r) in [0.7;1] 
    # number of peridos with mean r in [0.7;1]

    # 19 # Mean r [1;2]

    # 20 # Mean r [2,infinity]

    # 21 # SD(r) in [0,0.02]

    # 22 # SD(r) in [0.02;0.1]

    # 23 # SD(r) in [0.1,infinity]



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