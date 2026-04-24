<div align="center">

# 🏹 MergenSec

**High-Precision Autonomous Vulnerability Mapping Framework**

*Inspired by Mergen — the deity of wisdom and archery in Turkic mythology*

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.29-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=flat)

</div>

---

## 📖 Overview

MergenSec is a Python-based security auditing tool that automatically detects open network services and maps them to known vulnerabilities from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/). It reduces the need for manual security checks by combining async network scanning with real-time CVE lookups and an interactive dashboard.

## ✨ Features

- **Async Network Scanning** — Fast TCP/UDP port discovery using `python-nmap` and `asyncio`
- **CVE Lookup** — Automatic querying of the NVD API for known vulnerabilities
- **Risk Categorization** — CVSS-based scoring (Critical / High / Medium / Low)
- **Interactive Dashboard** — Visual risk maps and filterable CVE tables via Streamlit
- **JSON Reporting** — Exportable security reports for each scan session

## 🏗️ Architecture

```
User Input (IP / CIDR)
        │
        ▼
  AsyncScanner          ← python-nmap + asyncio
        │
        ▼
  CVEFetcher            ← NVD API + aiohttp
        │
        ▼
  VulnMapper            ← pandas + CVSS scoring
        │
   ┌────┴────┐
   ▼         ▼
Dashboard  JSON Report
(Streamlit)
```

## 🚀 Getting Started

### Prerequisites

- Python 3.12+
- Nmap installed on your system
- NVD API Key → [Request here](https://nvd.nist.gov/developers/request-an-api-key)

### Installation

```bash
# Clone the repository
git clone https://github.com/CikolataliPuding/mergensec.git
cd mergensec

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env and add your NVD_API_KEY

# Initialize the database
python -c "from database.db import init_db; init_db()"

# Run the dashboard
streamlit run dashboard/app.py
```

## 📁 Project Structure

```
mergensec/
├── core/
│   ├── scanner.py          # AsyncScanner — network scanning engine
│   ├── cve_fetcher.py      # CVEFetcher — NVD API integration
│   ├── vuln_mapper.py      # VulnMapper — CVE matching & CVSS scoring
│   └── report_generator.py # JSON report generation
├── database/
│   ├── models.py           # SQLAlchemy models
│   └── db.py               # Database connection
├── dashboard/
│   └── app.py              # Streamlit web interface
├── tests/
│   ├── test_scanner.py
│   ├── test_cve_fetcher.py
│   └── test_vuln_mapper.py
├── reports/                # Generated scan reports (gitignored)
├── .env.example
├── requirements.txt
└── README.md
```

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=core --cov-report=term-missing
```

## 👥 Team

| Name | Role | Module |
|---|---|---|
| Egemen Korkmaz | Lead Developer | Scanner Engine + Integration |
| Selameddin Tirit | Backend Developer | CVE Fetcher + NVD API |
| Çağrı Doğan | Backend Developer | Vulnerability Mapper + Reports |
| Mustafa Bite | Frontend Developer | Streamlit Dashboard |
| Zid Alkahni | Database + QA | SQLAlchemy + Pytest |

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">
<i>YMH220/YMH210 Python Project — 2025-26</i>
</div>