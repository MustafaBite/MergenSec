<div align="center">

# 🏹 MergenSec

**Autonomous Vulnerability Mapping Framework**

*Inspired by Mergen — the deity of wisdom and archery in Turkic mythology*

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.29-FF4B4B?style=flat&logo=streamlit&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-7.9+-0E83CD?style=flat&logo=nmap&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)
![Status](https://img.shields.io/badge/Status-In%20Development-f59e0b?style=flat)

> Documentation is the interface between your code and the human trying to use it.

</div>

---

## What Is MergenSec?

MergenSec scans a target network, detects open services, and automatically maps them to known CVE records from the National Vulnerability Database (NVD). It generates an interactive risk dashboard and a downloadable JSON report — replacing hours of manual security auditing with a single command.

---

## Features

- **Async network scanning** — discovers open TCP/UDP ports using `python-nmap` and `asyncio`
- **Automatic CVE lookup** — queries the NVD API and returns matching vulnerability records
- **CVSS risk scoring** — categorizes every finding as Critical, High, Medium, or Low
- **Interactive dashboard** — visualizes results in real time via Streamlit
- **JSON reporting** — exports a structured security report for each scan session

---

## Architecture

```
User enters target IP or CIDR range
              │
              ▼
       AsyncScanner                ← python-nmap + asyncio
    (port & service discovery)
              │
              ▼
        CVEFetcher                 ← NVD API + aiohttp
    (fetch matching CVE records)
              │
              ▼
        VulnMapper                 ← pandas + CVSS scoring
    (match services → CVEs)
              │
       ┌──────┴──────┐
       ▼             ▼
  Dashboard      JSON Report
  (Streamlit)    (reports/)
```

---

## Prerequisites

Before installing, make sure you have the following:

- **Python 3.12+** — [Download](https://www.python.org/downloads/)
- **Nmap** — [Download](https://nmap.org/download.html) and add to system PATH
- **NVD API Key** — [Request for free](https://nvd.nist.gov/developers/request-an-api-key)

Verify your setup:

```bash
python --version   # Python 3.12+
nmap --version     # Nmap 7.x
```

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/mergensec.git
cd mergensec
```

**2. Create and activate a virtual environment**

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Configure environment variables**

```bash
cp .env.example .env
```

Open `.env` and add your NVD API key:

```
NVD_API_KEY=your_api_key_here
DATABASE_URL=sqlite:///mergensec.db
```

**5. Initialize the database**

```bash
python -c "from database.db import init_db; init_db()"
```

**6. Launch the dashboard**

```bash
streamlit run dashboard/app.py
```

The dashboard opens at `http://localhost:8501`.

---

## Usage

1. Enter a target IP address or CIDR range (e.g. `192.168.1.1` or `192.168.1.0/24`)
2. Click **Start Scan**
3. Review the risk summary, CVE table, and CVSS distribution chart
4. Download the JSON report using the **Export Report** button

> **Note:** Running Nmap may require administrator/root privileges depending on your OS.
>
> Windows: run terminal as Administrator
> Linux/macOS: prefix with `sudo`

---

## Project Structure

```
mergensec/
├── core/
│   ├── scanner.py           # AsyncScanner — async port and service discovery
│   ├── cve_fetcher.py       # CVEFetcher — NVD API integration
│   ├── vuln_mapper.py       # VulnMapper — CVE matching and CVSS scoring
│   └── report_generator.py  # JSON report generation
├── database/
│   ├── models.py            # SQLAlchemy ORM models
│   └── db.py                # Database connection and initialization
├── dashboard/
│   └── app.py               # Streamlit web interface
├── tests/
│   ├── test_scanner.py
│   ├── test_cve_fetcher.py
│   └── test_vuln_mapper.py
├── reports/                 # Generated scan reports (gitignored)
├── .env.example             # Environment variable template
├── requirements.txt
├── CONTRIBUTING.md
└── README.md
```

---

## Running Tests

```bash
# Run all tests with verbose output
pytest tests/ -v

# Run a specific module's tests
pytest tests/test_scanner.py -v

# Generate a coverage report
pytest tests/ --cov=core --cov-report=term-missing
```

---

## Contributing

MergenSec uses a **feature branch workflow**. All contributions go through pull requests targeting the `dev` branch.

```bash
# Start from the latest dev branch
git checkout dev
git pull origin dev

# Create your feature branch
git checkout -b feature/your-feature-name

# Push and open a Pull Request → target: dev
git push origin feature/your-feature-name
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide on branch naming, commit message format, and code style requirements.

---

## Common Issues

| Error | Cause | Fix |
|---|---|---|
| `nmap: command not found` | Nmap not installed | Install from [nmap.org](https://nmap.org/download.html) |
| `KeyError: NVD_API_KEY` | `.env` file missing | Run `cp .env.example .env` and add your key |
| `429 Too Many Requests` | NVD rate limit exceeded | Rate limiting is handled automatically; wait 30s and retry |
| `PermissionError` | Nmap needs elevated privileges | Run with `sudo` (Linux/macOS) or as Administrator (Windows) |
| `ModuleNotFoundError` | Virtual environment not active | Run `source venv/bin/activate` first |

---

## Team

| Name | Role | Module |
|---|---|---|
| Egemen Korkmaz | Lead Developer | Scanner engine, integration, coordination |
| Selameddin Tirit | Backend Developer | CVE fetcher, NVD API |
| Çağrı Doğan | Backend Developer | Vulnerability mapper, JSON reports |
| Mustafa Bite | Frontend Developer | Streamlit dashboard |
| Zid Alkahni | Database & QA | SQLAlchemy models, Pytest |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Credits

Built as part of **YMH220/YMH210 Python Project** at Fırat University.
Vulnerability data provided by the [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

---

<div align="center">
<sub>MergenSec — 2025 | Fırat University | YMH220/YMH210</sub>
</div>