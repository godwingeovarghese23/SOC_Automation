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
