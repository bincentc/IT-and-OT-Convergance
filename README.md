# 🛡️ IT/OT Convergence Cybersecurity Project

**Course:** INCS 4810 – Industrial Network Cybersecurity  
**Institution:** British Columbia Institute of Technology (BCIT)  
**Team Members:** Vincent Caluyo, Santiago Juarez, Jayson Peters  
**Project Duration:** April 28, 2025 – May 28, 2025

---

## 📖 Executive Summary

This capstone project demonstrates the integration of IT and OT systems within a simulated industrial environment. Designed from the ground up, our project applies real-world cybersecurity methodologies, industry-standard frameworks like ISA/IEC 62443, and active attack/defense cycles to model threats and countermeasures in a converged IT/OT setting. We implemented and tested vulnerabilities in a basic network, then restructured it into a hardened, IEC-compliant architecture.

---

## 🎯 Project Objectives

- Design and implement a hybrid IT/OT network with real and virtualized components
- Execute internal and external cyberattacks to evaluate vulnerabilities
- Conduct a security assessment aligned with IEC 62443 standards
- Redesign the network to meet SL-Ts (Security Level Targets) with proper segmentation and defense-in-depth
- Present a live demo, detailed report, and technical documentation

---

## 🛠️ Project Phases

### 🔹 Phase 1: Basic Network & Exploitation
- Flat architecture with minimal segmentation
- Featured insecure protocols (e.g., Modbus TCP), missing endpoint protection, open routing
- Simulated attacks:
  - MAC flooding using Yersinia
  - Rogue DHCP via packet spoofing
  - CVE-2018-13379 & 13382 exploit on FortiGate VPN
  - DNS-based Command and Control (C2) with Python and GitHub API
  - PLC DoS through traffic flooding

### 🔹 Phase 2: Risk Assessment & IEC 62443 Alignment
- Conducted detailed threat modeling and risk analysis per IEC 62443-3-2
- Created zone and conduit diagrams
- Identified vulnerabilities from poor design (e.g., no RBAC, flat VLANs)

### 🔹 Phase 3: Advanced Network Redesign
- Introduced segmented zones: Enterprise, IDMZ, DMZ, Control, OT
- Enforced Role-Based Access Control (RBAC) and firewall ACLs
- Deployed defensive measures:
  - FortiClient EMS, FortiAnalyzer, Snort, T-Pot honeypot
  - VLAN segmentation, switch port security, endpoint lockdown
  - SCADA & Historian for data logging and monitoring

---

## 🧰 Tools & Technologies

| Category | Tools |
|---|---|
| **Virtualization** | VMware Workstation |
| **Cybersecurity** | FortiGate, FortiAnalyzer, FortiClient EMS, Snort, T-Pot |
| **SIEM/Monitoring** | Splunk, ELK Stack |
| **ICS/OT** | Siemens S7-1200 PLC, Simatic HMI, Ignition SCADA, Factory I/O |
| **Penetration Testing** | Burp Suite, hping3, Yersinia, Python, Scapy |

---

## 🧩 Project Architecture

**Basic Network:**  
- Vulnerable design with poor segmentation, unencrypted protocols, and legacy configurations
- Minimal protections and default settings used intentionally for testing

**Advanced Network:**  
- Fully segmented per Purdue Model
- Zones included: IT, IDMZ, DMZ, Control, OT
- Enforced communication via monitored conduits
- Included secure remote access, SIEM, honeypot, and endpoint defense

---

## 🔐 IEC 62443 Compliance Strategy

- Mapped all assets into appropriate zones
- Defined security levels (SL-T) for each zone based on risk
- Applied:
  - Zone-based segmentation
  - Conduits with FortiGate firewall filtering
  - RBAC and AAA framework
  - IDS/IPS at communication boundaries

---

## 🗓️ Project Timeline

| Deliverable | Due Date | Status |
|------------|----------|--------|
| Team Charter | Apr 29 | ✅ Complete |
| Proposal | May 9 | ✅ Complete |
| Annotated Bibliography | May 9 | ✅ Complete |
| Basic Network Demo | May 13 | ✅ Complete |
| Presentation | May 20 | ✅ Complete |
| Final Report | May 28 | ✅ Complete |

---

## 📊 Work Breakdown & Challenges

- Tasks were managed using WBS and Gantt charts
- Key challenges:
  - Shortened timeline (4 weeks instead of 5)
  - Learning new tools (TIA Portal, Ignition)
  - Limited internet access temporarily in lab
- Mitigation strategies included daily standups, external documentation, and effective resource allocation

---

## 🧠 Team Reflections

- **Vincent:** Focused on network design, IDS, and honeypot setup
- **Jayson:** Led Fortinet deployments and Python/C2 programming
- **Santiago:** Managed IEC compliance and OT integration

Each team member contributed across disciplines, ensuring the final solution was realistic, defensible, and portfolio-ready.

---

## 📁 Repository Structure

```
📦 IT-OT-Convergence-Security-Project/
├── README.md                # This document
├── LICENSE                  # Project license (MIT)
├── .gitignore               # Git exclusion rules
├── appendix/
│   ├── PLC_Program.md       # PLC design & automation process
│   └── Python_Attacks.md    # Details on attack code
└── references.md            # Full bibliography and source links
```

---

## 📚 References

- Fortinet Security Advisories
- IEC 62443 documentation
- Purdue Model ICS architecture
- GitHub: ICS-Security-Tools, Honeypot-Scripts
- ISA Training Material

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

Thanks to the BCIT instructors for their guidance, and to open-source communities whose tools and frameworks made this project possible.