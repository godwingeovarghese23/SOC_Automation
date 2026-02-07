# detector.py
from datetime import datetime, timedelta
import log_parser  # Import the parsed logs from log_parser.py

# Thresholds
MAX_FAILED_ATTEMPTS = 3
TIME_WINDOW_MINUTES = 5  # 5-minute window

# Convert log timestamps to datetime objects
for log in log_parser.logs:
    log["timestamp_dt"] = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")

# Detect brute-force login attempts
alerts = []

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
