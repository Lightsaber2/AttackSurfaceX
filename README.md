# AttackSurfaceX 🛰️
An Attack Surface Monitoring & Risk Intelligence Tool

---

## 📌 Overview
AttackSurfaceX is a **local attack surface monitoring tool** built with Python and Nmap.  
It continuously discovers exposed network services, tracks changes across scans, assigns risk scores, and generates structured security reports.

Unlike one-off scanners, AttackSurfaceX focuses on **visibility over time**, enabling detection of:
- newly exposed services
- closed or filtered ports
- high-risk legacy protocols

⚠️ **Disclaimer**  
This tool is intended for **educational use and authorized security assessments only**.  
Always ensure you have **explicit permission** before scanning any target.  
The author is **not responsible** for misuse or illegal activity.

---

## ✨ Key Features
- 🔍 Controlled Nmap Scan Execution
- 📄 XML Parsing & Event Normalization
- 🧠 Attack Surface Change Detection
- ⚠️ Rule-Based Risk Scoring
- 🗂️ Persistent Scan History (SQLite)
- 📊 Human-Readable CLI Output
- 📁 Structured JSON Report Generation
- 🕒 Timestamped & Audit-Friendly Results

---

## 📂 Project Structure

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
├── reports/
│   └── report_scan_*.json   # Generated scan reports
│
├── scans/                   # Raw Nmap XML output
├── attack_surface.db        # Local SQLite database
│
├── main.py                  # Orchestrator / entry point
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

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

## 🚀 Usage

Run a scan and generate a report:
```bash
python main.py
```

Each run will:
- execute an Nmap scan
- store results in SQLite
- detect attack surface changes
- calculate risk scores
- generate a JSON report in `reports/`

---

## 📊 Example Output

```
[+] Scan stored successfully
[+] Risk Assessment:
45.33.32.156:21 (ftp) -> Risk 9/10
45.33.32.156:22 (ssh) -> Risk 5/10
```

---

## 🛡️ Legal Disclaimer
AttackSurfaceX is intended for **educational use and authorized security testing only**.  
Unauthorized scanning of systems without permission is strictly prohibited.

---

## 📜 License
This project is licensed under the **MIT License**.

---

👨‍💻 Developed by **Lightsaber2**
