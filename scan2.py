#scans ip address for address and pings for information on up or down

# python scan2.py 192.168.1.0/24
# ./ip_scanner.py -p 80 192.168.1.0/24

# pip install scapy dnspython

import sys
import time
import math
from scapy.all import *
from ipaddress import ip_network

a = sys.argv[1] # scanning method 
# b = sys.argv[2] # ports to scan 
# c = sys.argv[3] # specifies ip address range

def scan_net():
    total_start_time = time.time()
    ip_range = ip_network(a, strict=False)
    print(f"IP range: {ip_range}")
    
    for ip in ip_range.hosts():
        responsTimestart = time.time()
        status = 'N/A'
        toScan = f"{ip}"
        if ping(toScan):
            status = "UP"
            print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")
            open_ports(toScan)
        else:
            status = "DOWN"
            print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")
    print(f"total scan time: {math.floor(((time.time()) - total_start_time) * 1000)}ms")     

def ping(host):
    packet = IP(dst=host)/ICMP()
    response = sr1(packet, timeout=2, verbose=0)
    if response is None:
        return False
    elif response.haslayer(ICMP):
        return True

def open_ports(ip):
    start = 1
    end = 1024
    for port in range(start, end):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK response
                print(f"    - Port {port} (OPEN)")

scan_net()