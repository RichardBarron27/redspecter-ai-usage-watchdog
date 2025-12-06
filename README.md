<p align="center">
  <img src="https://raw.githubusercontent.com/RichardBarron27/red-specter-offensive-framework/main/assets/red-specter-logo.png" alt="Red Specter Logo" width="200">
</p>

# 🛡️ Red Specter – AI Usage Watchdog
Part of the Red Specter Purple Team AI Defense Suite

![License](https://img.shields.io/badge/license-MIT-success)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![Language](https://img.shields.io/badge/language-Python3-blue)
![Version](https://img.shields.io/badge/version-v0.1--Beta-blueviolet)
![Status](https://img.shields.io/badge/state-Public-success)

> A privacy-first Linux agent for monitoring AI usage on endpoints.

---



## 🔍 Description

AI Usage Watchdog is a lightweight **Linux-first endpoint agent** that detects and logs AI / LLM usage on the host in a **privacy-preserving** manner.

It complements:

| Tool | Purpose |
|---|---|
| **AI Endpoint Guard** | Enforces safe AI usage rules |
| **AI Breach Monitor** | Detects abnormal AI behaviour |
| **AI Usage Watchdog** | Visibility & governance |

Together, these form the **Red Specter Purple Team AI Defense Suite**.

---

## ✨ Features

| Feature | Status |
|---|:---:|
| AI usage detection (runtime signatures) | ✔ |
| JSONL logging for SIEM ingestion | ✔ |
| Lightweight & agent-based | ✔ |
| No prompt or content capture | ✔ |
| Local event viewer (`watchdog_view`) | 🚧 v0.2 |
| Policy engine + fleet aggregation | ⏳ v0.3 |

---

## Quick Start

### Install dependency

```bash
sudo apt install python3-psutil
Run a single scan (debug)
bash
Copy code
cd agent
./redspecter_ai_usage_watchdog.py --once --debug
Run continuously
bash
Copy code
./redspecter_ai_usage_watchdog.py --interval 15
Logs
text
Copy code
~/.redspecter_ai_watchdog/logs/events.jsonl
Each event is a JSON object including:

Timestamp

PID + process name

Username & hostname

Matched signature (risk/category)

Privacy posture:

❌ No prompt text

❌ No file/document contents

✅ Only metadata

🔍 Live TUI Dashboard (v0.2)
bash
Copy code
cd tools
./watchdog_dashboard.py
Features:

Auto-refreshing view (every 3s)

Risk-based color coding (LOW / MED / HIGH)

Keyboard controls:

q → quit

r → refresh immediately

This provides a quick SOC-style view into AI usage on the endpoint.

🗺 Roadmap
Version	Goal	Status
v0.1	Agent MVP	✔
v0.2	Dashboard viewer + SIEM export	🚧
v0.3	Policies + central aggregation	⏳
v1.0	Public hardened release	⏳

See ROADMAP.md for full details.

🎯 Purple Team Mission
Offense-driven defense.
We use adversarial insight to design better defensive controls.

Always authorized. Always ethical.

❤️ Support Red Specter
If you find this useful and want to support further development:

PayPal: https://paypal.me/richardbarron1747

Your support helps me build more tools like this — thank you!



