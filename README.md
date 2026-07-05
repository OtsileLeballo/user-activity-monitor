🔍 User Activity Monitor - Log Analysis Tool

 📌 Overview

The **User Activity Monitor** is a Python-based log analysis tool that detects suspicious user activity from authentication logs. It was built to demonstrate practical skills in **IT support** (user management) and **SOC operations** (threat detection).

This project simulates how a real security monitoring tool would flag potential incidents like brute force attacks, after-hours logins, and unusual IP addresses—then generates a professional report with actionable recommendations for IT and security teams.



 🚀 Features

| Detection | Description | Severity |
|-----------|-------------|----------|
| 🔴 Brute Force Attack | 3+ failed login attempts for the same user | HIGH |
| 🔴 Unusual IP Address | Login from a non-corporate IP range | HIGH |
| 🟡 After-Hours Login | Login between 10pm and 6am | MEDIUM |
| 🟡 Rapid Succession | 5+ logins within 10 minutes | MEDIUM |

 Why I Built This
I built this project to bridge the gap between IT support and cybersecurity. Most IT support roles focus on user management, while SOC roles focus on threat detection. This tool combines both—showing I can troubleshoot user issues AND identify security incidents.

 What I Learned
How to parse and analyze log files using Python

How to identify common attack patterns (brute force, unusual access)

How to structure a professional security report

How to think like both an IT support technician and a SOC analyst

## 📊 Sample Output
