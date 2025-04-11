[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=18061391)

# Port Scanner
This script scans an IP address range to check if hosts are up or down and identifies open ports on the hosts.

# Required dependencies:
pip install scapy dnspython

# Example Usage
python scan2.py A 192.168.1.0/24 - Scans the IP range with default ports (21, 80, 443)
./ip_scanner.py 80 192.168.1.0/24 - Example for scanning port 80
