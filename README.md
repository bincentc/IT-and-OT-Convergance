# IT/OT Convergence Security Project

## 📚 Overview

This project demonstrates my practical skills in designing, attacking, and securing a realistic **IT/OT network**. It was developed as a final capstone for the **Industrial Network Cybersecurity** program at BCIT.  
<br>
The goal: **Build a vulnerable network, exploit it using real-world attack vectors, then redesign it to align with ISA/IEC 62443 standards and best practices.**

---

## 🔑 Project Objectives

- Design a **realistic IT/OT converged network**
- Perform **penetration tests** and exploit known CVEs (e.g., FortiGate SSL VPN vulnerabilities)
- Develop and execute **custom Python attack tools** (Command-and-Control server, rogue scripts)
- Analyze risks and redesign the network using **ISA/IEC 62443 standards**
- Deploy advanced defenses: **FortiGate firewalls, FortiAnalyzer, FortiClient EMS, Snort IDS, T-Pot honeypot**
- Validate improved resilience through documentation and demonstration

---

## 🏗️ Key Components

### Basic Network
- **IT Zone**: Windows Server (ADDS, DNS, DHCP), Splunk, Cisco switch, FortiGate firewall
- **OT Zone**: Siemens S7-1200 PLC, Siemens HMI, Factory I/O package sorting simulation, SCADA server

### Exploitation Phase
✅ Simulated attacks included:
- Command-and-Control server with encrypted communication via DNS tunneling
- Credential theft using FortiGate SSL VPN CVEs (CVE-2018-13379, CVE-2018-13382)
- MAC flooding to sniff plaintext traffic (Telnet)
- Rogue DHCP server to hijack client traffic
- PLC Denial-of-Service (DoS) to halt industrial process

### Advanced Network
- Redesigned following **ISA/IEC 62443-3-2** risk assessments
- Segmented zones/conduits based on **Purdue Model**
- Security tools: Snort IDS, T-Pot honeypot, FortiClient EMS for EDR & VPN, FortiAnalyzer for central logging
- Hardened switch configs (VLANs, port security, DHCP snooping)

---

## 🗂️ My Contributions

**Vincent Caluyo**
- Led internal network penetration testing: MAC flooding, rogue DHCP, PLC DoS
- Developed custom Python scripts for C2 server operations
- Deployed **Snort IDS** and **T-Pot honeypot**, integrated logs with Splunk & FortiAnalyzer
- Helped design secure zones/conduits & wrote technical documentation

---

## 📊 Results

✅ Identified real-world exploitable vulnerabilities  
✅ Designed and implemented an improved network with stricter segmentation, hardened devices, and layered defenses  
✅ Aligned with **ISA/IEC 62443** standards for industrial cybersecurity  
✅ Delivered a live demonstration and final report to faculty and peers

---

## 📁 Repo Contents

- `/docs` – Full final report (PDF)
- `/images` – Network diagrams, screenshots
- `/code` – Custom Python scripts for C2 server and attacks
- `README.md` – This file

---

## 📜 References

- ISA/IEC 62443 Industrial Automation and Control System Security Standard
- Purdue Enterprise Reference Architecture (PERA) Model
- Fortinet CVEs and PSIRT advisories
- Community tools: Snort IDS, T-Pot Honeypot, Splunk, FortiClient EMS

---

## ✅ Skills Demonstrated

- IT/OT network design
- Penetration testing and exploit development
- Python scripting for offensive security
- Risk assessment and standards compliance (IEC 62443)
- Security architecture redesign
- Security monitoring & incident response tools

---

**_Designed, tested, and defended by_**  
Vincent Caluyo, Santiago Juarez, Jayson Peters  
BCIT Industrial Network Cybersecurity | May 2025
