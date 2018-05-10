import argparse
import socket
import sys
import struct
import os
import struct 
import datetime

ICMP = socket.getprotobyname("icmp")
TYPE = 8
PID = int(os.getpid() % (2 << 16))
CODE = 0

IP_PROTOCOL = 1 # ICMP

IDX_TYPE = 20

def create_socket(ttl):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    except socket.error:
        print("Error creating socket...")
        sys.exit()
    return s

def get_packet(seq, payload):
    packet = new_icmp_packet(TYPE, CODE, 0, PID, seq, payload)
    checksum = calculate_checksum(packet)
    return new_icmp_packet(TYPE, CODE, checksum, PID, seq, payload)
    
def new_icmp_packet(t, code, checksum, pkt_id, seq, payload):
    packet = struct.pack("!B", t) # specify the type of message as ICMP (TYPE = 8)
    packet += struct.pack("!B", code) # used for ping (CODE = 0)
    packet += struct.pack("!H", checksum) # checksum padding = 0
    packet += struct.pack("!H", pkt_id) # a random 16 bit id
    packet += struct.pack("!H", seq)
    packet += payload
    return packet


def pack_ip(packet, ip):
    ip = ip.split(".")
    for seg in ip:
        seg = int(seg)
        packet += struct.pack("!B", seg)
    return packet

def calculate_checksum(packet):
    s = 0
    for i in range(0, len(packet), 2):
        first_byte = packet[i]
        last_byte = packet[i + 1]
        word = (first_byte << 8) + last_byte
        s = ones_comp_add(s, word)
    return 0xffff - s
    
def ones_comp_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)
    
def send_one_ping(ttl, dest, data, seq):
    
    s = create_socket(ttl)
    packet = get_packet(seq, data.encode('utf-8'))
    before = datetime.datetime.now()

    try:
        s.sendto(packet, (dest, 1))
        s.settimeout(3)
        rData, _ = s.recvfrom(4096)
    except socket.timeout:
        print("Timed out, retrying... (seq={}, ttl={})".format(seq, ttl))
        rData = None

    after = datetime.datetime.now()
    ping = (after - before).total_seconds() * 1000
    return rData, ping

def analyse_response(rData, ping):
    print("ping: {}ms".format(ping))
    ICMP_type = rData[IDX_TYPE]
    source_ip_bytes = rData[12: 16]
    dest_ip_bytes = rData[16: 20]
    source_ip_str_rep = ip_from_bytes(source_ip_bytes)
    dest_ip_str_rep = ip_from_bytes(dest_ip_bytes)
    print(source_ip_str_rep, dest_ip_str_rep)
    if ICMP_type == 0:
        print("Destination reached.")
    else:
        print("Ttl exceeded.")

    print("\n")
    return ICMP_type == 0

def ip_from_bytes(b):
    ip = ""
    for byte in b:
        ip += str(byte) + "."
    return ip[:-1] # drop the last dot


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a ping test.")
    parser.add_argument("domain", type=str, help="enter a domain name")
    parser.add_argument("data", type=str, help="enter data to send")
    args = parser.parse_args()
    domain = args.domain
    data = args.data
    dest = socket.gethostbyname(domain)
    print("Sending IMCP packet to '{}', IP addr: {}...".format(domain, dest))

    rData = None
    reached = False
    i = 1
    while rData == None or reached == False:
        print("Sending ping... (seq={}, ttl={})".format(i, i))
        rData, ping = send_one_ping(i, dest, data, i)
        if rData == None:
            # if timed out, try again
            continue 

        reached = analyse_response(rData, ping)
        if not reached:
            i += 1
        
    

    
    
   
    
