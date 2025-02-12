#scans ip address for address and pings for information on up or down

# python scan2.py 192.168.1.0/24
# ./ip_scanner.py -p 80 192.168.1.0/24

# pip install scapy dnspython

import socket
import sys
import time
import csv
import math
from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp 
import dns.resolver
import dns.reversename

a = sys.argv[1] # scanning method 
# b = sys.argv[2] # ports to scan 
# c = sys.argv[3] # specifies ip address range

def scan_net():
    ip_range = ip_network(a, strict=False)
    print(f"DEBUG: User input IP range: {ip_range}")
    total_start_time = time.time()
    status = 'N/A'
    responsTime = 0
    for ip in ip_range.hosts():
        pinged = ping(ip)



        print(pinged)
        print(f"{ip} - {status} ({responsTime}ms)")
        total_end_time = time.time()

    total_elapsed_time = math.floor((total_end_time - total_start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth 
    print(total_elapsed_time)    
    # result, elapsed_time, mac_address = ping(ip_str)
    # hostname = reverse_dns_lookup(ip_str) if result == 'UP' else 'N/A'
    # print(f"\nTotal scan completed in {total_elapsed_time:.1f} ms.")
    # print(f"Scan complete. Found {active_hosts} active hosts, {down_hosts} down, {errors} errors")



    # status_output = format_output(ip_str, result, elapsed_time, hostname, mac_address)
    # print(status_output)
    # results.append({'IP': ip_str, 'Status': result, 'Time': elapsed_time, 'Hostname': hostname, 'MAC': mac_address})
    

def ping(ip):
    
    return
    
    
    # # Measure the time it takes to ping the IP address with a timeout of 30 seconds
    # start_time = time.time()
    # try:
    #     # Execute the ping command and check the result
    #     result = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    #     end_time = time.time()
    #     responsTime = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
    #     if result.returncode == 0:
    #         mac = mac_address(ip)
    #         status = 'UP'
    #         return status, responsTime, mac
    #     else:
    #         status = 'DOWN'
    #         return status, responsTime, 'N/A'
    # except socket.error:
    #     end_time = time.time()
    #     responsTime = math.floor((end_time - start_time) * 1000)  # Convert to milliseconds and floor to the nearest tenth
    #     return 'ERROR (Connection timeout)', responsTime, 'N/A'

def reverse_dns_lookup():

    return

def mac_address():

    return

def format_output(ip, status, elapsed_time, hostname, mac_address):
    if status == 'UP':
        return f"{ip} - {status} ({elapsed_time}ms)\n  Hostname: {hostname}\n  MAC: {mac_address}"
    elif status == 'DOWN':
        return f"{ip} - {status} (NO response)"
    else:
        return f"{ip} - {status} (Timed out)"

def csv_export(result):
    filename = "scan_results.csv"
    ipKey = result[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=ipKey)
        dict_writer.writeheader()
        dict_writer.writerows(result)

    

# ip_range = ip_network("192.168.1.0/24", strict=False)
# print(f"DEBUG: User input IP range: {ip_range}")

# for ip in ip_range.hosts():
#     print (ip)
# print(ip_network("192.168.1.0/24", strict=False))




# def scan(self):
#     """Scan the specified ports on the target IP.
#     https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
#     """
    
#     print(Fore.YELLOW + f"Scanning {self.target_ip} for open ports...")
#     for port in self.ports:
#         response = sr(IP(dst=self.target_ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)[0]
#         if response:
#             for sent, received in response:
#                 if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN-ACK
#                     print(Fore.GREEN + f"Port {port} is open")
#                 elif received.haslayer(TCP) and received[TCP].flags == 20:  # RST
#                     print(Fore.RED + f"Port {port} is closed")
#         else:
#             print(Fore.BLUE + f"Port {port} is filtered or no response")


scan_net()