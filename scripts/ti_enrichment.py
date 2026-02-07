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
