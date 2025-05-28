# 🛡️ IT/OT Convergence Cybersecurity Project

**Course:** INCS 4810 – Industrial Network Cybersecurity  
**Institution:** British Columbia Institute of Technology (BCIT)  
**Team Members:** Vincent Caluyo, Santiago Juarez, Jayson Peters  
**Completed:** May 23, 2025

---

## 📖 Project Summary

This capstone project involved the design, implementation, assessment, and hardening of a converged IT/OT network. Emphasizing real-world relevance, our work adhered to ISA/IEC 62443 standards and integrated technologies commonly found in modern industrial environments. The project demonstrated technical competencies across network engineering, penetration testing, risk assessment, and security infrastructure deployment.

---

## 🎯 Objectives

- Design a realistic IT/OT network for simulation and defense
- Conduct penetration testing to discover exploitable vulnerabilities
- Implement IEC 62443-compliant architecture with zones and conduits
- Deploy a variety of defensive tools including firewalls, honeypots, IDS, and endpoint security
- Showcase practical understanding of integrating cybersecurity into industrial control systems

---

## 🧩 Project Phases

### 1. 🛠️ Network Design & Implementation
- Developed a basic IT/OT network with:
  - Windows Server with AD DS, DNS, DHCP
  - Siemens S7-1200 PLC and Simatic HMI
  - FortiGate firewall bridging IT and OT zones
  - Splunk for centralized log monitoring
  - SCADA solution using Ignition

### 2. 🚨 Exploitation Phase
Simulated internal and external attacks:
- **Command & Control:** Python-based DNS-tunneled C2 server
- **VPN Credential Theft:** Exploited CVE-2018-13379 & CVE-2018-13382 in FortiOS
- **MAC Flooding:** Used Yersinia to force switch into hub mode and sniff credentials
- **Rogue DHCP:** Redirected client traffic using spoofed DHCP responses
- **PLC DoS:** Crashed industrial process by flooding Siemens PLC

### 3. 🔐 Hardened Network Redesign
Redesigned the network with security-first principles:
- Conducted a risk-based SL-T assessment aligned with IEC 62443-3-2
- Segmented devices into zones (Enterprise, IDMZ, Supervisory Control, Process Control)
- Established conduits using firewalls and VLANs
- Implemented endpoint protection, switch hardening, and strict firewall policies

---

## ⚙️ Key Technologies

- **Cybersecurity:** FortiGate, FortiClient EMS, FortiAnalyzer, Snort, T-Pot Honeypot
- **Networking:** Cisco switching, VLAN segmentation, VPN tunnels
- **Industrial:** Siemens S7-1200 PLC, Simatic HMI, Ignition SCADA
- **Monitoring:** Splunk, Fortinet logging, ELK stack
- **Attack Tools:** Yersinia, hping3, Scapy, Burp Suite

---

## 🧠 Risk Assessment & Security Levels

Following ISA/IEC-62443:
- Created asset inventory and risk matrix
- Quantified worst-case impacts (financial, safety, operational)
- Assigned Security Level Targets (SL-Ts) to each zone
- Built hardened architecture aligned to those SL-Ts

---

## 📊 Project Management

Utilized project management tools to stay on schedule:
- Deliverables included proposals, demos, presentations, and this report
- Gantt charts and WBS used to coordinate tasks and milestones

---

## 📁 Repository Structure

```
📦 IT-OT-Convergence-Security-Project/
├── README.md                # Project overview
├── LICENSE                  # MIT License
├── .gitignore               # Git ignored files
├── appendix/
│   ├── PLC_Program.md       # Ladder logic overview
│   └── Python_Attacks.md    # Details on Python C2/attacks
└── references.md            # All source material
```

---

## 📚 References

Sources include:
- Fortinet vulnerability disclosures
- International Society of Automation (ISA)
- ICS security research GitHub repos
- IEC 62443 documentation and course material

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

Special thanks to our instructors and peers at BCIT, and to the open-source and cybersecurity communities whose tools and guidance shaped this work.