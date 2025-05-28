# 🐍 Python-Based Attack Scenarios

This appendix describes the command and control and network exploitation tools developed using Python.

## DNS Tunnel C2

A custom DNS tunneling command-and-control server was built to bypass network security:

- Commands were encoded and embedded in subdomain queries
- Responses returned via crafted TXT records
- Python used dnspython and requests libraries
- GitHub API used for covert exfiltration and status tracking

## FortiGate Exploit Automation

Python scripts were written to automate:

- CVE-2018-13379 (Path traversal): download SSL VPN session file
- CVE-2018-13382 (Authentication bypass): access internal admin panel

## Network Disruption Scripts

Other scripts included:

- MAC flooding (Scapy)
- ICMP flood for denial-of-service simulation
- Rogue DHCP server using scapy.sendp()

> Scripts are for educational use only and are excluded from the public repo to comply with GitHub policies.