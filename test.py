from scapy.all import *
from ipaddress import ip_network

def is_ip_up(ip):
    pkt = IP(dst=ip) / ICMP()
    response = sr1(pkt, timeout=2, verbose=0)
    if response is None:
        return False  # No response means the IP is down
    elif response.haslayer(ICMP):
        return True  # Received an ICMP response means the IP is up

def scan_ports(ip, start_port=1, end_port=1024):
    open_ports = []
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK response
                open_ports.append(port)
    return open_ports

ip_range = ip_network("192.168.1.0/24", strict=False)
for ip in ip_range:
    ip_address = f"{ip}"  # Replace with the target IP address
    start_port = 1
    end_port = 1024



if is_ip_up(ip_address):
    print(f"{ip_address} is up!")
    open_ports = scan_ports(ip_address, start_port, end_port)
    if open_ports:
        print(f"Open ports on {ip_address}: {open_ports}")
    else:
        print(f"No open ports found on {ip_address}")
else:
    print(f"{ip_address} is down.")
