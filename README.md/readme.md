# Security Automation using Python

## Project Overview
This project demonstrates a Python-based security automation system that simulates a Security Operations Center (SOC) workflow. It automates repetitive security tasks by:

- Parsing logs from different sources (authentication, firewall, web server logs).  
- Detecting suspicious patterns such as brute-force login attempts.  
- Enriching alerts with Threat Intelligence using AbuseIPDB API.  
- Triggering safe automated responses, such as blocking suspicious IPs.  
- Generating organized, tabulated security reports for easy human review.  

The project provides hands-on experience in Security Orchestration, Automation, and Response (SOAR) concepts.

---

## Features
- **Log Parsing:** Converts raw logs into structured data for analysis.  
- **Anomaly Detection:** Detects brute-force attacks and other anomalous patterns.  
- **Threat Intelligence Integration:** Enriches alerts with IP reputation from public APIs.  
- **Automated Response:** Blocks suspicious IPs safely in a simulated environment and logs actions.  
- **Professional Reporting:** Displays alerts and actions in clean, tabulated terminal outputs.  

---

## Requirements
- **Python Version:** 3.x  
- **Python Libraries:** 
  - `requests`  
  - `tabulate`  
- **Sample Log Files:** Stored in the `logs/` folder (e.g., `auth.log`)  
- **AbuseIPDB API Key:** Optional but recommended for real TI enrichment  

---

## Project Structure
Security Automation/
├─ config/
│ └─ config.json
├─ logs/
│ └─ auth.log
├─ scripts/
│ ├─ log_parser.py # Parses raw logs into structured data
│ ├─ detector.py # Detects suspicious events
│ ├─ ti_enrichment.py # Enriches alerts with Threat Intelligence
│ └─ response.py # Triggers automated responses
├─ blocked_ips.txt # Stores blocked IPs
├─ screenshots/ # Stores screenshots for documentation
└─ README.md # Project overview and instructions


---

## How to Run
1. Open a terminal/PowerShell and navigate to the `scripts/` folder:

```powershell
cd "D:\Security Automation\scripts"
python log_parser.py
python detector.py
python ti_enrichment.py
python response.py

##Check outputs:

Terminal tables for parsed logs, detected alerts, enriched alerts, and automated responses.
blocked_ips.txt file for IPs blocked by the automated response module.

##Future Enhancements
Email Notifications: Send alerts automatically via email.
Color-coded Terminal Output: Highlight critical IPs using colorama.
Configurable Rules: Manage thresholds and alert rules via a config.json file.
Integration with Real Systems: Connect automated responses to actual firewalls or SIEM tools.

