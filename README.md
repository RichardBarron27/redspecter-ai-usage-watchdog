<p align="center">
  <img src="https://raw.githubusercontent.com/RichardBarron27/red-specter-offensive-framework/main/assets/red-specter-logo.png" alt="Red Specter Logo" width="200">
</p>

# 🛡️ Red Specter – AI Usage Watchdog
Part of the **Red Specter Purple Team AI Defense Suite**

![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![Language](https://img.shields.io/badge/Python-3.10+-blue)
![Version](https://img.shields.io/badge/Version-v0.2-orange)
![Status](https://img.shields.io/badge/Status-Active-success)

A privacy-first Linux agent for monitoring AI usage on endpoints with zero content capture.

---

## 🔍 Description
AI Usage Watchdog is a lightweight Linux-first endpoint agent that detects and logs AI / LLM usage on the host in a **privacy-preserving** manner.

It complements other Red Specter AI Security Suite tools:

| Tool | Purpose |
|------|---------|
| **AI Endpoint Guard** | Enforces safe AI usage rules |
| **AI Breach Monitor** | Detects abnormal AI behaviour |
| **AI Usage Watchdog** | Visibility & governance |

Together, these form the **Red Specter Purple Team AI Defense Suite**.

---

## ✨ Features

| Feature | Status |
|--------|--------|
| AI usage detection (runtime signatures) | ✔ |
| JSONL logging for SIEM ingestion | ✔ |
| Lightweight agent | ✔ |
| Zero prompt/content capture | ✔ |
| Local event dashboard (`watchdog_dashboard.py`) | 🚧 v0.2 |
| Policy engine + fleet aggregation | ⏳ v0.3 |

---

## 🚀 Quick Start

### Install dependency
```bash
sudo apt install python3-psutil
Run a single scan (debug)
cd agent
./redspecter_ai_usage_watchdog.py --once --debug

Run continuously
./redspecter_ai_usage_watchdog.py --interval 15

Logs stored at
~/.redspecter_ai_watchdog/logs/events.jsonl


Each event includes:

Timestamp

PID + process name

Username & hostname

Matched signature (risk/category)

Privacy posture:

❌ No prompt text

❌ No file/document contents

✔ Only metadata captured

🔍 Live TUI Dashboard (v0.2)
cd tools
./watchdog_dashboard.py


Features:

Auto-refreshing (every 3s)

Color-coded severity

Keyboard navigation

q → quit

r → force refresh

A lightweight SOC-style view into real-time AI usage on the endpoint.

🗺 Roadmap
Version	Goal	Status
v0.1	Agent MVP	✔
v0.2	Dashboard viewer + SIEM export	🚧
v0.3	Policies + central aggregation	⏳
v1.0	Public hardened release	⏳

See ROADMAP.md for full intent & backlog.

🎯 Purple Team Mission

Offense-driven defense.
We use adversarial insight to design better defensive controls.

Always authorized. Always ethical.
Red Specter defends by thinking like an attacker.

❤️ Support Red Specter
---

## ⭐ Support & Contribute

If you find this project useful, please consider:

- ⭐ Starring the repository — it helps others discover the project
- 🐛 Reporting issues and ideas via GitHub Issues

👉 PayPal: https://paypal.me/richardbarron1747

Every contribution helps build more tools like this — thank you!
