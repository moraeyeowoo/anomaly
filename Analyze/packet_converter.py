import base64
from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

def encode_packet(packet):
	#encode to bytes
	bytes_encoded = bytes(packet)
	#encode to b64
	base64_encoded = base64.b64encode(bytes_encoded)
	#encode utf8
	utf8_encoded = base64_encoded.decode('utf8')
	print(type(utf8_encoded))
	return utf8_encoded
 
def decode_packet(utf8_encoded_packet):
	# decode to base 64
	base64_encoded = utf8_encoded_packet.encode('utf8')
	# decode to bytes
	bytes_encoded = base64.b64decode(base64_encoded)
	# convert to scapy packet object
	packet = Ether(bytes_encoded)
	return packet


def map_symbol(prev_pkt, curr_pkt, mac_address,frequent_packet_length):
    c = [0,0,0,0,0,0]
    # c1 direction 1 = incoming, 0 = outgoing
    if curr_pkt.src == mac_address:
        c[0] = 0
    elif curr_pkt.dst == mac_address:
        c[0] = 1
    
    if curr_pkt.src == mac_address:
        # local port
        if curr_pkt[TCP].sport in range(0,1024):
            c[1] = 0
        elif curr_pkt[TCP].sport in range(1024,49151):
            c[1] = 1
        elif curr_pkt[TCP].sport in range(49152, 65535):
            c[1] = 2
        # remote port
        if curr_pkt[TCP].dport in range(0,1024):
            c[2] = 0
        elif curr_pkt[TCP].dport in range(1024,49151):
            c[2] = 1
        elif curr_pkt[TCP].dport in range(49152, 65535):
            c[2] = 2
         
        
    elif curr_pkt.dst == mac_address:
        # local port
        if curr_pkt[TCP].sport in range(0,1024):
            c[1] = 0
        elif curr_pkt[TCP].sport in range(1024,49151):
            c[1] = 1
        elif curr_pkt[TCP].sport in range(49152, 65535):
            c[1] = 2
        # remote port
        if curr_pkt[TCP].dport in range(0,1024):
            c[2] = 0
        elif curr_pkt[TCP].dport in range(1024,49151):
            c[2] = 1
        elif curr_pkt[TCP].dport in range(49152, 65535):
            c[2] = 2
        
    # packet length, we need device type to create bin for this, just use raw numbers 
    #c[3] = float(len(curr_pkt))/100
    if len(curr_pkt) in frequent_packet_length:
        c[3] = frequent_packet_length.index(len(curr_pkt))
    else:
        c[3] = len(frequent_packet_length)

    # tcp flag
    c[4] = float(int(curr_pkt[TCP].flags)/10)
    # #protocols icgnore
    #c[5] = 
    IAT = curr_pkt.time - prev_pkt.time
    if IAT < 0.001:
        c[5] = 0
    elif IAT > 0.001 and IAT < 0.05:
        c[5] = 1
    elif IAT > 0.05:
        c[5] = 2 
    
    return c

def get_packet_symbols(pkts, mac_address):
    seq = []
    packet_lengths = []

    for pkt in pkts:
        packet_lengths.append(len(pkt))
    from collections import Counter
    packet_length_map = Counter(packet_lengths)
    packet_length_tuples = []
    
    for key in packet_length_map:
        val = packet_length_map[key]
        packet_length_tuples.append((key,val))

    if len(packet_length_tuples) >= 8:
        frequent_packet_length = [k[0] for k in packet_length_tuples[:8]]
    else:
        frequent_packet_length = [k[0] for k in packet_length_tuples]

    for k in range(0, len(pkts)-1):
        symbols = map_symbol(pkts[k+1], pkts[k], mac_address, frequent_packet_length)
        seq.append(symbols)
    return seq

def convert_symbol_to_string(symbol):
    c1 = symbol[0]
    c2 = symbol[1]
    c3 = symbol[2]
    c4 = symbol[3]
    c5 = int(symbol[4]*10)
    c6 = symbol[5]
    c7 = symbol[6]
    ret_map = {"direction":None, "local":None,"remote":None,"tcp":None,"status":None}
    ret = []
    if c1 == 0:
        ret.append("Incoming")
    elif c1 == 1:
        ret.append("Outgoing")
    
    if c2 ==0:
        ret.append("User Port")
    elif c2 ==1:
        ret.append("System Port")
    elif c2 ==2:
        ret.append("Other Port")
        
    if c3 ==0:
        ret.append("User Port")
    elif c3 ==1:
        ret.append("System Port")
    elif c3 ==2:
        ret.append("Other Port")
        
    ret.append(c4*10)
    tcp_flag_str = ""
    if c5 & FIN:
        tcp_flag_str+="FIN "
    if c5 & SYN:
        tcp_flag_str+="SYN "
    if c5 & RST:
        tcp_flag_str+="RST "
    if c5 & PSH:
        tcp_flag_str+="PSH "
    if c5 & ACK:
        tcp_flag_str+="ACK "
    if c5 & URG:
        tcp_flag_str+="URG "
    if c5 & ECE:
        tcp_flag_str+="ECE "
    if c5 & CWR:
        tcp_flag_str+="CWR "

    ret.append(tcp_flag_str)
    
    if c7 == 0:
        ret.append("Anomaly")
    elif c7 == 1:
        ret.append("Benign")

    return ret