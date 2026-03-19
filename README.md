# 🔍 NetRecon — Network Reconnaissance Tool

> A fast, multi-threaded port scanner with service detection, banner grabbing, and risk assessment. Built for SOC analysts and penetration testers.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

---

## ✨ Features

- ⚡ **Multi-threaded scanning** — up to 200 threads
- 🔎 **Banner grabbing** — detect service versions
- ⚠️ **Risk assessment** — flags HIGH/MEDIUM risk ports (Telnet, RDP, SMB...)
- 📄 **JSON export** — machine-readable output for SIEM ingestion

## 🚀 Quick Start
```bash
git clone https://github.com/arash-123456/NetRecon.git
cd NetRecon
python netrecon.py -t 192.168.1.1
python netrecon.py -t 10.0.0.1 -p 1-65535 --threads 200 -o report.json
```

## ⚖️ Legal Disclaimer

> Only scan systems you own or have **explicit written permission** to test.

## 🧠 SOC Use Cases

- Asset discovery during incident response
- Exposure assessment of internal network segments
- Threat hunting — identify unexpected open services
