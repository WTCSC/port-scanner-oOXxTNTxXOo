#scans ip address for address and pings for information on up or down

# python scan2.py 192.168.1.0/24
# ./ip_scanner.py -p 80 192.168.1.0/24

# pip install scapy dnspython

import sys
import time
import math
from scapy.all import *
from ipaddress import ip_network
import threading

a = sys.argv[1] # scanning method 
b = sys.argv[2] # ports to scan 
# c = sys.argv[3] # specifies ip address range

def scan_net():
    total_start_time = time.time()
    ip_range = ip_network(b, strict=False)
    scanningM = a
    print(f"IP range: {ip_range}")

    for ip in ip_range.hosts(): # scans the range of specifed ips
        responsTimestart = time.time()
        status = 'N/A'
        toScan = f"{ip}"
        ipstatus(responsTimestart, status, toScan, ip)
    print(f"total scan time: {math.floor(((time.time()) - total_start_time) * 1000)}ms")     

def ipstatus(responsTimestart, status, toScan, ip):
    specific_ports = str(a)
    if ping(toScan): # checks if ip is up or down
        status = "UP"
        print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")
        open_ports(toScan, specific_ports)
    else:
        status = "DOWN"
        print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")

def ping(host): # sends a packet to specified ip
    packet = IP(dst=host)/ICMP()
    try: 
        response = sr1(packet, timeout=2, verbose=0)
        if response is None: # verifies if packet was sent & recieved
            return False
        elif response.haslayer(ICMP):
            return True
    except Exception as e:
        print(f"Error scanning {host}")
        return False

def open_ports(ip, ports=None): # checks all ports
    if ports is None:
        return print("enter valid port range")
    elif ports == "A":
        ports = [21, 80, 443] #defualt port range
    else:
        ports = ports
    
    start = 1
    end = 1024
    for port in range(start, end):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        try:
            response = sr1(pkt, timeout=1, verbose=0)
            if response is not None and response.haslayer(TCP):
                if response[TCP].flags == "SA":  # SYN-ACK response
                    print(f"    - Port {port} (OPEN)")
        except Exception as e:
            print(f"Error scanning {port}")

scan_net()