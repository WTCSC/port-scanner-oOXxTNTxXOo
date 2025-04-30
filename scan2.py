# This script scans an IP address range and checks if hosts are up or down.
# It also scans for open ports on the hosts.
import sys
import time
import math
from scapy.all import *  # Scapy is used for crafting and sending packets
from ipaddress import ip_network  # Used for handling IP ranges
import threading  # For potential multithreading

# Command-line arguments
a = sys.argv[1]  # Scanning method (e.g., "A" for default ports)
b = sys.argv[2]  # IP range to scan

def scan_net():
    """
    Scans the specified IP range and checks the status of each host.
    """
    total_start_time = time.time()  # Start time for the entire scan
    ip_range = ip_network(b, strict=False)  # Parse the IP range
    scanningM = a  # Scanning method 
    print(f"IP range: {ip_range}")

    # Iterate through all hosts in the IP range
    for ip in ip_range.hosts():
        responsTimestart = time.time()  # Start time for each host scan
        status = 'N/A'  # Default status
        toScan = f"{ip}"  # Convert IP to string
        ipstatus(responsTimestart, status, toScan, ip)  # Check host status and scan ports
    print(f"Total scan time: {math.floor(((time.time()) - total_start_time) * 1000)}ms")

def ipstatus(responsTimestart, status, toScan, ip):
    """
    Checks if a host is up or down and scans its open ports if it's up.
    """
    specific_ports = str(a)  # Placeholder for specific ports 
    if ping(toScan):  # Ping the host to check if it's up
        status = "UP"
        print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")
        open_ports(toScan, specific_ports)  # Scan for open ports
    else:
        status = "DOWN"
        print(f"{ip}  ({status}) ({(math.floor((time.time() - responsTimestart)*100))/100}ms)")

def ping(host):
    """
    Sends an ICMP packet to the specified host to check if it's reachable.
    """
    packet = IP(dst=host)/ICMP()  # Create an ICMP packet
    try:
        response = sr1(packet, timeout=2, verbose=0)  # Send the packet and wait for a response
        if response is None:  # No response means the host is down
            return False
        elif response.haslayer(ICMP):  # Check if the response contains an ICMP layer
            return True
    except Exception as e:
        print(f"Error scanning {host}")  # Handle exceptions
        return False

def open_ports(ip, ports=None):
    """
    Scans the specified host for open ports.
    """
    if ports is None:
        return print("Enter a valid port range")  # Handle missing port range
    elif ports == "A":
        ports = [21, 80, 443]  # Default port range
    else:
        ports = ports  # Placeholder for custom port ranges 
    
    start = 1  # Start of the port range
    end = 1024  # End of the port range
    for port in range(start, end):  # Iterate through the port range
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")  # Create a TCP SYN packet
        try:
            response = sr1(pkt, timeout=1, verbose=0)  # Send the packet and wait for a response
            if response is not None and response.haslayer(TCP):  # Check if the response contains a TCP layer
                if response[TCP].flags == "SA":  # SYN-ACK response indicates an open port
                    print(f"    - Port {port} (OPEN)")
        except Exception as e:
            print(f"Error scanning {port}")  # Handle exceptions

# Start the network scan
scan_net()