# 🛡️ Pentesting Toolkit (Python)

A modular penetration testing toolkit featuring port scanning, subdomain enumeration, and brute-force capabilities.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📦 Features

| Module           | Description                          | Supported Protocols       |
|------------------|--------------------------------------|---------------------------|
| Port Scanner     | TCP/SYN scan with banner grabbing    | HTTP, SSH, FTP, SMTP      |
| Subdomain Finder | DNS brute-force enumeration          | DNS (A/CNAME records)     |
| Brute Forcer     | HTTP login attacks                   | Form-based auth, APIs     |
| Vuln Checker     | CVE detection from service banners   | 1500+ CVEs                |

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```
## Basic Usage
# Port scanning
python main.py scan-ports example.com -p 20-443 -b

# Subdomain discovery
python main.py scan-subs example.com -w wordlists/subdomains.txt

# Brute-force attack
python main.py brute http://test.com/login -u admin -w wordlists/passwords.txt

## 🧩Module Structure
pentool/
├── main.py                 # CLI interface
├── modules/
│   ├── scanner/            # Scanning tools
│   │   ├── port_scanner.py # Multi-threaded port scanner
│   │   ├── banner_graber.py# Service fingerprinting
│   │   └── subdomain.py    # DNS enumeration
│   └── attacker/           # Exploitation
│       ├── brute_forcer.py # HTTP brute-forcer
│       └── vuln_checker.py # CVE detection
└── wordlists/              # Preloaded dictionaries
## 🔧 Configuration
Edit config.ini (create if missing):
[scanning]
threads = 100
timeout = 3.0
stealth_mode = True
## 📊 Sample Output
[+] Port Scan Results:
Open Ports: [22, 80, 443]
22/tcp - SSH-2.0-OpenSSH_8.2
80/tcp - Apache/2.4.29 (Ubuntu)