from scapy.all import * 
import math
import numpy as np
from scipy.fftpack import fft, ifft
import copy
import os
import statistics

dlink1_mac = "b0:c5:54:25:1f:b6"
dlink2_mac = "c4:12:f5:1c:8c:f1"
dlink3_mac = "b0:c5:54:25:22:64"
edimax1_mac = "74:da:38:4a:a9:75"
xiaomi_mac = ""

pcap_files = os.listdir("./captures")
pcap_files.sort()



def timestamp_flow_by_device(pcap_packets, protocol, src_mac_addr,start, end): 
    if protocol == 'IGMP':
        packets = []
        for packet in pcap_packets:
            if IP in packet and packet.proto ==2:
                packets.append(packet)
    if protocol == 'SSDP':
        packets = []
        for packet in pcap_packets:
            if 'NOTIFY' in str(packet) or 'MSEARCH' in str(packet):
                packets.append(packet)
    else:
        packets = pcap_packets.filter(lambda x: protocol in x and x.src == src_mac_addr)
    start_time = pcap_packets[0].time
    end_time = pcap_packets[-1].time 
    flow_duration = math.ceil(end_time - start_time)
    indices = [math.floor(packet.time - start_time) for packet in packets]
    signal= [0] * flow_duration
    
    for index in indices:
        signal[index] = 1
    return signal[start:end]

def timestamp_flow(pcap_packets, protocol, start, end): 
    if protocol == 'IGMP':
        packets = []
        for packet in pcap_packets:
            if IP in packet and packet.proto ==2:
                packets.append(packet)
    if protocol == 'SSDP':
        packets = []
        for packet in pcap_packets:
            if 'NOTIFY' in str(packet) or 'MSEARCH' in str(packet):
                packets.append(packet)
    else:
        packets = [pkt for pkt in pcap_packets if protocol in pkt]
    start_time = pcap_packets[0].time
    end_time = pcap_packets[-1].time 
    flow_duration = math.ceil(end_time - start_time)
    indices = [math.floor(packet.time - start_time) for packet in packets]
    signal= [0] * flow_duration
    
    for index in indices:
        signal[index] = 1
    return signal[start:end]

def get_candidate_Ts(timestamps, d,tolerance):
    x = timestamps
    y = fft(x)
    y_abs = np.absolute(y)
    indices = range(0,d)
    Yf = [ (k, y_abs[k]) for k in indices]   
    max_frequency = max(y_abs)
    L = [ tuple for tuple in Yf if tuple[1] > tolerance * max(y_abs)]
    candidates = [ d / tuple[0] for tuple in L if not tuple[0] == 0 ]
    Ts = [ np.floor(T) for T in candidates]
    return Ts

# timestamps : flow
# l          : period. 
def calculate_Ryy(timestamps,l):
    return sum( [timestamps[k]*timestamps[k-l] for k in range(l, len(timestamps))])

# timestamps: flow
# l         : period , T_i 
def calculate_r(timestamps,l):
    Ryy = calculate_Ryy(timestamps, l)
    r = (l * Ryy) / len(timestamps)
    return r 

def calculate_rn(timestamps,l):
    numerator = l*(calculate_Ryy(timestamps, l-1)+calculate_Ryy(timestamps,l)+calculate_Ryy(timestamps,l+1))
    denominator = len(timestamps)
    return (numerator/denominator)

def confirm_Ts(Ts,timestamps):
    ret = set()
    Ts = [ int(x) for x in Ts]
    for T_i in Ts:
        # check if it is localco maximume
        low = int(T_i*0.9)
        high = int(T_i*1.1)
        candidates = list(range(low,high))
        l_i = max(candidates, key=lambda x:calculate_Ryy(timestamps,x))
        candidates_Ryy = [ calculate_Ryy(timestamps,x) for x in candidates]
        local_max = all(map(lambda x: l_i > x, candidates_Ryy))
        if local_max:
            ret.add(l_i)
    return ret

def get_Ts(timestamps, tolerance):
    candidate_Ts = get_candidate_Ts(timestamps, len(timestamps),tolerance)
    removed_duplicates = set(candidate_Ts)
    removed_short = [ k for k in removed_duplicates if k>4 and k<600 ]
    Ts = confirm_Ts(removed_short, timestamps)
    Ts = [ T for T in Ts if calculate_r(timestamps, T)> 0.1 and calculate_r(timestamps,T)<5]
    return Ts

#ARP, IGMP, ICMP,TCP,UDP,  NBNS, DNS, SSDP
def get_periods_by_device(pcap_packets, src_mac_addr,start, end):
    periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "NBNS":None, "DNS":None,"SSDP":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP"]
    for protocol in protocols:
        flow = timestamp_flow(pcap_packets, protocol, src_mac_addr, start,end)
        Ts = get_Ts(flow, 0.1)
        periods[protocol] = (flow, Ts)
    return periods

def get_periods(pcap_packets,start, end):
    periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "NBNS":None, "DNS":None,"SSDP":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP"]
    for protocol in protocols:
        flow = timestamp_flow(pcap_packets, protocol,start,end)
        Ts = get_Ts(flow, 0.1)
        periods[protocol] = (flow, Ts)
    return periods



def get_characteristic_metric(periods):
    metrics = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "NBNS":None, "DNS":None,"SSDP":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP"]
    for protocol in protocols:
        flow = periods[protocol][0]
        Ts = periods[protocol][1]
        feature_vector = []
        for T in Ts:
            r = calculate_r(flow, T)
            rn = calculate_rn(flow, T)
            feature_vector.append((T,r,rn))
        metrics[protocol] = feature_vector
    return metrics

def get_sub_periods_by_device(pcap_packets, src_mac_addr):
    sub_one_periods = get_periods(pcap_packets, src_mac_addr,0,900)
    sub_two_periods = get_periods(pcap_packets, src_mac_addr,450,1450)
    sub_three_periods = get_periods(pcap_packets,src_mac_addr,900,1800)
    sub_all_periods = get_periods(pcap_packets, src_mac_addr,0,1800)

    periods = {"sub_1":sub_one_periods, "sub_2":sub_two_periods,
        "sub_3":sub_three_periods,"all":sub_all_periods}
    return periods 

def get_sub_periods(pcap_packets):
    sub_one_periods = get_periods(pcap_packets,0,900)
    sub_two_periods = get_periods(pcap_packets,450,1450)
    sub_three_periods = get_periods(pcap_packets,900,1800)
    sub_all_periods = get_periods(pcap_packets,0,1800)

    periods = {"sub_1":sub_one_periods, "sub_2":sub_two_periods,
        "sub_3":sub_three_periods,"all":sub_all_periods}
    return periods 


#periods that occur at least in two 
def filter_periods(periods):
    filtered_periods = {"ARP":None, "IGMP":None, "ICMP":None, "TCP":None, "UDP":None, "NBNS":None, "DNS":None,"SSDP":None} 
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP"]

    for protocol in protocols:
        sub_1 = periods['sub_1'][protocol][1]
        sub_2 = periods['sub_2'][protocol][1]
        sub_3 = periods['sub_3'][protocol][1]
        sub_all = periods['all'][protocol][1]
        all_intervals = set(sub_1+sub_2+sub_3+sub_all)
        flow = periods['all'][protocol][0]
        Ts = []
        for T in all_intervals:
            l = []
            l.append(T in sub_1)
            l.append(T in sub_2)
            l.append(T in sub_3)
            l.append(T in sub_all)
            if l.count(True)>2:
                print(l)
                print(l.count(T))
                Ts.append(T)
        filtered_periods[protocol] = (flow,Ts)
    return filtered_periods

def fingerprint(periods):
    protocols = ["ARP", "IGMP","ICMP", "TCP","UDP", "DNS", "SSDP"]    
    protocols_4 = ["ARP", "IGMP", "ICMP"]
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

    # 17 # Mean(r) in [0.2:0.7]
    # number of periods with mean r in ...


def print_period(timestamps, l):
    n = len(timestamps)//l
    for k in range(0,n):
        low = l*k
        high =l*k+l
        print(timestamps[low:high])