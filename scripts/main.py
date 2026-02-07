
# Track failed logins per IP
failed_logins = {}

for log in log_parser.logs:
    ip = log["ip"]
    event = log["event"]
    timestamp = log["timestamp_dt"]

    if event == "LOGIN_FAILED":
        if ip not in failed_logins:
            failed_logins[ip] = []
        failed_logins[ip].append(timestamp)

        # Check if there are too many failed attempts in the time window
        window_start = timestamp - timedelta(minutes=TIME_WINDOW_MINUTES)
        recent_attempts = [t for t in failed_logins[ip] if t >= window_start]

        if len(recent_attempts) >= MAX_FAILED_ATTEMPTS:
            alerts.append({
                "ip": ip,
                "count": len(recent_attempts),
                "message": f"Brute-force login detected from IP {ip} ({len(recent_attempts)} failed attempts in last {TIME_WINDOW_MINUTES} mins)"
            })

# Print alerts
print("ALERTS:")
for alert in alerts:
    print(alert["message"])


import os

print("Current working directory:", os.getcwd())

logs = []

with open(r"..\logs\auth.log", "r") as file:
    for line in file:
        line = line.strip()
        if not line:
            continue
        parts = line.split(" - ")
        log_entry = {
            "timestamp": parts[0],
            "event": parts[1],
            "ip": parts[2],
            "user": parts[3]
        }
        logs.append(log_entry)

print("Parsed Logs:", logs)


# response.py
import ti_enrichment  # Get enriched alerts from ti_enrichment.py
from tabulate import tabulate
import datetime

# -------------------------------
# Configuration
# -------------------------------
BLOCKED_FILE = r"..\blocked_ips.txt"  # File to store blocked IPs

# -------------------------------
# Load existing blocked IPs
# -------------------------------
try:
    with open(BLOCKED_FILE, "r") as f:
        blocked_ips = [line.strip() for line in f.readlines()]
except FileNotFoundError:
    blocked_ips = []

# -------------------------------
# Automated Response Logic
# -------------------------------
# Conditions to block:
# - Failed attempts >= 3 OR
# - Abuse score >= 50
actions_taken = []

for alert in ti_enrichment.enriched_alerts:
    ip = alert["ip"]
    attempts = alert["count"]
    abuse_score = alert.get("abuse_score", 0)

    # Check if IP is already blocked
    if ip not in blocked_ips and (attempts >= 3 or (abuse_score and abuse_score >= 50)):
        blocked_ips.append(ip)
        actions_taken.append({
            "ip": ip,
            "attempts": attempts,
            "abuse_score": abuse_score,
            "action": "Blocked",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

# -------------------------------
# Save updated blocked IPs
# -------------------------------
with open(BLOCKED_FILE, "w") as f:
    for ip in blocked_ips:
        f.write(ip + "\n")

# -------------------------------
# Display actions in a table
# -------------------------------
if actions_taken:
    table_data = []
    for a in actions_taken:
        table_data.append([
            a["ip"], a["attempts"], a["abuse_score"], a["action"], a["timestamp"]
        ])
    headers = ["IP Address", "Failed Attempts", "Abuse Score", "Action Taken", "Timestamp"]
    print("\nAUTOMATED RESPONSES:")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
else:
    print("\nNo automated actions required.")


# ti_enrichment.py
import requests
import json
import detector  # Import the alerts from detector.py
from tabulate import tabulate

# -------------------------------
# Load API key from config.json
# -------------------------------
try:
    with open(r"..\config\config.json", "r") as f:
        config = json.load(f)
except FileNotFoundError:
    print("Error: config.json not found in config folder")
    exit()

ABUSEIPDB_API_KEY = config.get("abuseipdb_api_key")
if not ABUSEIPDB_API_KEY:
    print("Error: Please add 'abuseipdb_api_key' in config.json")
    exit()

# -------------------------------
# Function to check IP reputation
# -------------------------------
def check_ip_abuseipdb(ip):
    """
    Queries AbuseIPDB API for a given IP.
    Returns the abuse score (0-100) if successful, else None.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            abuse_score = data['data']['abuseConfidenceScore']
            return abuse_score
        else:
            print(f"API error for IP {ip}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Request error for IP {ip}: {e}")
        return None

# -------------------------------
# Enrich detector alerts
# -------------------------------
enriched_alerts = []

if not detector.alerts:
    print("No alerts found from detector.py")
else:
    for alert in detector.alerts:
        ip = alert["ip"]
        abuse_score = check_ip_abuseipdb(ip)
        alert["abuse_score"] = abuse_score
        enriched_alerts.append(alert)

# -------------------------------
# Print enriched alerts in table format
# -------------------------------
if enriched_alerts:
    table_data = []
    for ea in enriched_alerts:
        table_data.append([
            ea['ip'],
            ea['count'],
            ea.get('abuse_score', 'N/A')
        ])

    headers = ["IP Address", "Failed Attempts", "Abuse Score"]
    print("\nENRICHED ALERTS:")
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
else:
    print("No alerts to display.")
