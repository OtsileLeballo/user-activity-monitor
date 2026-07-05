# ============================================================
# USER ACTIVITY MONITOR - Log Analysis Tool
# IT Support + SOC Hybrid Project
# ============================================================

import re
import datetime
from collections import Counter

# ============================================================
# STEP 1: SAMPLE LOG DATA (Hardcoded - No file needed)
# ============================================================

log_entries = [
    "2026-07-05 08:15:32 User: jdoe Login: SUCCESS IP: 192.168.1.50",
    "2026-07-05 08:16:10 User: jdoe Login: FAILED IP: 192.168.1.50",
    "2026-07-05 08:16:45 User: jdoe Login: FAILED IP: 192.168.1.50",
    "2026-07-05 08:17:20 User: jdoe Login: FAILED IP: 192.168.1.50",
    "2026-07-05 08:18:02 User: jdoe Login: SUCCESS IP: 192.168.1.50",
    "2026-07-05 09:30:15 User: bsmith Login: SUCCESS IP: 10.0.0.25",
    "2026-07-05 14:22:45 User: jdoe Login: SUCCESS IP: 203.0.113.45",
    "2026-07-05 23:15:33 User: asmith Login: SUCCESS IP: 192.168.1.60",
    "2026-07-05 23:16:01 User: asmith Login: FAILED IP: 192.168.1.60",
    "2026-07-05 23:16:30 User: asmith Login: FAILED IP: 192.168.1.60",
    "2026-07-05 23:17:02 User: asmith Login: SUCCESS IP: 10.0.0.50",
    "2026-07-06 01:22:10 User: jdoe Login: SUCCESS IP: 192.168.1.50",
    "2026-07-06 02:15:33 User: cwilson Login: SUCCESS IP: 172.16.0.100",
]

# ============================================================
# STEP 2: ANALYZE THE LOGS
# ============================================================

def analyze_logs(entries):
    """Scan each log entry and detect suspicious activity"""
    alerts = []
    failed_attempts = Counter()
    user_logins = {}  # Track login times for each user

    for entry in entries:
        # Extract data using regex
        time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', entry)
        user_match = re.search(r'User: (\w+)', entry)
        status_match = re.search(r'Login: (\w+)', entry)
        ip_match = re.search(r'IP: ([\d.]+)', entry)

        if not (time_match and user_match and status_match and ip_match):
            continue

        timestamp = datetime.datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
        user = user_match.group(1)
        status = status_match.group(1)
        ip = ip_match.group(1)

        # ----- ALERT 1: Brute Force (3+ failed attempts) -----
        if status == "FAILED":
            failed_attempts[user] += 1
            if failed_attempts[user] >= 3:
                alerts.append({
                    "type": "🔴 BRUTE FORCE ATTACK",
                    "user": user,
                    "time": timestamp,
                    "detail": f"{failed_attempts[user]} failed login attempts",
                    "severity": "HIGH"
                })

        # ----- ALERT 2: After-Hours Login (10pm - 6am) -----
        if status == "SUCCESS" and (timestamp.hour >= 22 or timestamp.hour <= 5):
            alerts.append({
                "type": "🟡 AFTER-HOURS LOGIN",
                "user": user,
                "time": timestamp,
                "detail": f"Login at {timestamp.strftime('%H:%M')} (outside business hours)",
                "severity": "MEDIUM"
            })

        # ----- ALERT 3: Unusual IP (Not in corporate ranges) -----
        if status == "SUCCESS":
            is_corporate = (ip.startswith("192.168.") or 
                           ip.startswith("10.") or 
                           ip.startswith("172.16."))
            if not is_corporate:
                alerts.append({
                    "type": "🔴 UNUSUAL IP ADDRESS",
                    "user": user,
                    "time": timestamp,
                    "detail": f"Login from non-corporate IP: {ip}",
                    "severity": "HIGH"
                })

        # ----- ALERT 4: Multiple Logins in Short Time -----
        if user not in user_logins:
            user_logins[user] = []
        user_logins[user].append(timestamp)

    # Check for 5+ logins within 10 minutes
    for user, times in user_logins.items():
        if len(times) >= 5:
            times.sort()
            for i in range(len(times) - 4):
                diff = (times[i+4] - times[i]).total_seconds()
                if diff <= 600:
                    alerts.append({
                        "type": "🟡 RAPID SUCCESSION",
                        "user": user,
                        "time": times[i],
                        "detail": f"{len(times)} logins within {int(diff/60)} minutes",
                        "severity": "MEDIUM"
                    })
                    break

    return alerts

# ============================================================
# STEP 3: GENERATE REPORT
# ============================================================

def generate_report(alerts, total_entries):
    """Print a professional summary report"""
    print("\n" + "="*60)
    print("        📋 USER ACTIVITY MONITORING REPORT")
    print("="*60)

    print(f"\n📊 Summary:")
    print(f"   - Total log entries analyzed: {total_entries}")
    print(f"   - Alerts triggered: {len(alerts)}")

    if len(alerts) == 0:
        print("\n✅ No suspicious activity detected.")
        print("="*60)
        return

    high = [a for a in alerts if a["severity"] == "HIGH"]
    medium = [a for a in alerts if a["severity"] == "MEDIUM"]

    print(f"   - HIGH severity: {len(high)}")
    print(f"   - MEDIUM severity: {len(medium)}")

    print("\n" + "-"*60)
    print("🚨 DETAILED ALERTS")
    print("-"*60)

    for alert in alerts:
        print(f"\n{alert['type']} [{alert['severity']}]")
        print(f"   👤 User: {alert['user']}")
        print(f"   🕐 Time: {alert['time']}")
        print(f"   📝 Detail: {alert['detail']}")

    # Recommendations
    print("\n" + "-"*60)
    print("📌 RECOMMENDATIONS")
    print("-"*60)

    affected = set(a["user"] for a in alerts)
    print(f"\n👥 Affected users: {', '.join(affected)}")

    print("""
📋 Next steps:
   1. 🔴 Investigate all HIGH severity alerts immediately
   2. 🔐 Reset passwords for affected users
   3. 📍 Review unusual IP addresses for known threats
   4. ⏰ Follow up on after-hours logins
   5. 📝 Check for similar patterns in the last 7 days
""")

    print("="*60)
    print("End of Report")
    print("="*60)

# ============================================================
# STEP 4: RUN THE ANALYSIS
# ============================================================

print("🔍 USER ACTIVITY MONITOR - Starting Analysis...")
print("-"*60)

alerts = analyze_logs(log_entries)
generate_report(alerts, len(log_entries))
