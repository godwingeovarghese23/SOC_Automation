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
