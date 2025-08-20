# SaintScan – Lightweight Vulnerability Assessment Tool

SaintScan is a **Python-based vulnerability scanner** designed to demonstrate security testing knowledge in a portfolio-ready project.  
It performs basic crawling, scans for common issues, and generates **JSON/CSV reports** for further analysis.

---

## ✨ Features
-  Crawl target websites up to a given depth
-  Detect common web security issues:
  - Missing security headers
  - Sensitive files exposure (`robots.txt`, `/admin`, `/phpinfo.php`, `.git/`, etc.)
  - Open redirect parameters (`?url=`, `?redirect=`, etc.)
  - Basic reflected XSS checks
  - Weak TLS/SSL configuration
-  Export results to **JSON** and **CSV**

---

## 📦 Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/YOUR-USERNAME/saintscan.git
cd saintscan
pip install -r requirements.txt

## 🚀 Usage
- Run with CLI arguments:

```bash
python main.py --url https://target.com --depth 2 --json reports/target.json --csv reports/targets.csv

## ⚖️ Ethics & Safety Disclaimer
- This tool is intended for educational purposes only
- Use it on your own system or systems you have explicit permission to test.
- Do not scan systems you don't own or operate without authorization
- The author assumes no liability for misuse

- By using SaintScan, you agree to these terms and take full responsibility for your actions.