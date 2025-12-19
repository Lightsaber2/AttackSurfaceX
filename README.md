# AttackSurfaceX
An Attack Surface Monitoring & Risk Intelligence Tool

---

## Overview
AttackSurfaceX is a **local attack surface monitoring tool** built with Python and Nmap.  
It continuously discovers exposed network services, tracks changes across scans, assigns risk scores, and generates structured security reports.

Unlike one-off scanners, AttackSurfaceX focuses on **visibility over time**, enabling detection of:
- newly exposed services
- closed or filtered ports
- high-risk legacy protocols
- attack surface evolution

**Disclaimer**  
This tool is intended for **educational use and authorized security assessments only**.  
Always ensure you have **explicit permission** before scanning any target.  
The author is **not responsible** for misuse or illegal activity.

---

## Key Features
- Controlled Nmap Scan Execution
- XML Parsing & Event Normalization
- Attack Surface Change Detection
- Rule-Based Risk Scoring
- Persistent Scan History (SQLite)
- Human-Readable CLI Output
- Structured JSON Report Generation
- Timestamped & Audit-Friendly Results
- Graceful Error Handling

---

## Project Structure

```
AttackSurfaceX/
├── analyzer/
│   ├── __init__.py
│   ├── diff.py              # Attack surface change detection
│   └── risk.py              # Rule-based risk scoring
│
├── logger/
│   ├── __init__.py
│   ├── schema.sql           # SQLite database schema
│   └── storage.py           # Persistent storage engine
│
├── parser/
│   ├── __init__.py
│   ├── events.py            # Normalized security event models
│   └── xml_parser.py        # Nmap XML → security events
│
├── scanner/
│   ├── __init__.py
│   ├── profiles.py          # Scan profiles
│   └── runner.py            # Nmap execution engine
│
├── utils/
│   ├── __init__.py
│   ├── config.py            # Configuration management
│   └── logger.py            # Centralized logging system
│
├── reports/                 # Generated scan reports
├── scans/                   # Raw Nmap XML output
├── logs/                    # Application logs
│
├── attack_surface.db        # Local SQLite database
├── config.yaml              # Configuration file
├── main.py                  # Orchestrator / entry point
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Installation

### System Dependency
AttackSurfaceX requires **Nmap** to be installed and available in PATH.

Download from: https://nmap.org/download.html

Verify:
```bash
nmap --version
```

---

### Python Setup
```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

---

## Usage

Basic Commands
Scan default target:
```bash
python main.py
```
Scan specific target:
```bash
python main.py -t 192.168.1.1
```
Use different scan profile:
```bash
python main.py -t scanme.nmap.org -p full
```
Preview scan command (dry run):
```bash
python main.py -t 10.0.0.0/24 -p stealth --dry-run
```
Available scan profiles:
- fast
- full
- comprehensive
- stealth

---

## Example Output

```
============================================================
Attack Surface Scan Started
============================================================
[+] Scan completed in 12.34s
[+] Scan ID       : 5
[+] Target        : scanme.nmap.org
[+] Profile       : fast
[+] Events Parsed : 12

============================================================
Attack Surface Changes
============================================================
Newly Opened Ports:
  [+] 45.33.32.156:8080

============================================================
Risk Assessment
============================================================
+----------------+-------+-----------+--------+
| Host           | Port  | Service   | Risk   |
+================+=======+===========+========+
| 45.33.32.156   | 21    | ftp       | 9/10   |
+----------------+-------+-----------+--------+
| 45.33.32.156   | 22    | ssh       | 5/10   |
+----------------+-------+-----------+--------+

============================================================
Report Generated
============================================================
Saved to: reports/report_scan_5.json
```

---

## Legal Disclaimer
AttackSurfaceX is intended for **educational use and authorized security testing only**.  
Unauthorized scanning of systems without permission is strictly prohibited.

---

## License
This project is licensed under the **MIT License**.

---

Developed by **Lightsaber2**
