# IT/OT Convergence Security Project

**Course:** INCS 4810  
**Team Members:** Vincent Caluyo, Santiago Juarez, Jayson Peters  
**Completion Date:** May 23, 2025

---

## 📘 Executive Summary

This project showcases our hands-on design, implementation, exploitation, and hardening of an IT/OT converged network, applying real-world tools and following the ISA/IEC 62443 standard. It represents the culmination of our skills gained during the Industrial Network Cybersecurity program.

---

## 🔧 Project Overview

- Created a vulnerable network for simulated cyberattacks.
- Conducted penetration testing: MAC flooding, rogue DHCP, VPN exploit, PLC DoS.
- Hardened the system using IEC 62443 standards.
- Integrated real devices: Siemens PLC & HMI, Fortinet firewalls, SCADA, Splunk.

---

## 🧪 Tools & Technologies

- **Hardware:** Siemens S7-1200 PLC, Simatic HMI
- **Security:** FortiGate, FortiClient EMS, FortiAnalyzer, Snort, T-Pot honeypot
- **Monitoring:** Splunk, SCADA (Ignition), VLANs
- **Attack Tools:** Yersinia, hping3, Burp Suite

---

## 🚨 Exploitation Scenarios

1. **Command & Control Server:** Used DNS tunneling and GitHub API for fileless attacks.
2. **FortiGate SSL VPN Exploit:** Retrieved plaintext credentials and hijacked sessions.
3. **MAC Flooding:** Captured telnet credentials using Wireshark.
4. **Rogue DHCP Server:** Redirected client traffic for MITM attacks.
5. **PLC DoS Attack:** Halted industrial process with traffic flooding.

---

## 🔐 Advanced Network Design

- Used ISA/IEC 62443-3-2 to define security zones and conduits.
- Created a risk matrix to determine SL-Ts (Target Security Levels).
- Added VLAN segmentation, firewall rules, GPOs, switch port security, and more.

---

## 📈 Project Management

- Used Gantt chart to plan milestones.
- Completed team charter, proposal, demo, presentation, and final report on schedule.

---

## 📎 Appendices

- 📄 [PLC Program Details](#)
- 🐍 [Python Attack Scripts Overview](#)

---

## 📚 References

Sources include Fortinet advisories, ISA materials, ICS security GitHub repos, and documentation on IEC 62443 and the Purdue Model.

---

## 📝 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙌 Acknowledgments

Thanks to our instructors at BCIT and the resources from Fortinet, ISA, and GitHub open-source community.