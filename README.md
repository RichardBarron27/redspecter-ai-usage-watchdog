# 🛡️ Red Specter – AI Usage Watchdog

Part of the **Red Specter Purple Team AI Defense Suite**  
**Offense-driven defense. Visibility without surveillance.**

---

## 🔖 Status & Badges
![Private Repo](https://img.shields.io/badge/visibility-private-800080)
![Python](https://img.shields.io/badge/language-Python3-blue)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-success)
![Stage](https://img.shields.io/badge/version-v0.1--dev-orange)

---

## 🎯 Mission

AI Usage Watchdog provides **endpoint visibility** into AI/LLM usage,
generating **privacy-preserving audit logs** for authorised security operations.

Designed to complement:

| Tool | Purpose |
|---|---|
| **AI Endpoint Guard** | Block unsafe AI actions |
| **AI Breach Monitor** | Detect abnormal AI activity |
| **AI Usage Watchdog** | Visibility & governance |

Together, they form the **Red Specter Purple Team AI Defense Suite**.

---

## ✨ Features (v0.1 – Agent MVP)

| Capability | Status |
|---|:---:|
| Linux-first agent (Python + psutil) | ✔ |
| Real-time AI usage detection | ✔ |
| Signature-based detection | ✔ |
| JSONL logs (SIEM-ready) | ✔ |
| CLI viewer dashboard | 🚧 v0.2 |
| Fleet management + policies | ⏳ v0.3 |

---

## 🚀 Quick Start

Install dependency:

```bash
sudo apt install python3-psutil
# or
pip install --user psutil
Run a single scan:

cd agent
./redspecter_ai_usage_watchdog.py --once --debug


Run continuously:

./redspecter_ai_usage_watchdog.py --interval 15


View logs with the dashboard tool:

cd tools
./watchdog_view.py

📂 Log Path

Events stored as JSONL:

~/.redspecter_ai_watchdog/logs/events.jsonl


Privacy posture:

❌ No prompt contents ever logged

❌ No document/file contents collected

✔ Only process metadata & signature matches

🗺 Roadmap
Version	Focus	Status
v0.1	Core agent + logging	✔
v0.2	Dashboard + export helpers	🚧
v0.3	Policies + aggregation	⏳
v1.0	Hardened public release	🔜

See ROADMAP.md
 for details.

🧩 Purple Team Strategy

Use offensive insight to design defensive controls:

Detect misuse

Govern usage

Protect users & org assets

This is lawful, authorised defensive cyber operations only.

❤️ Support Red Specter

Help fuel development of free, ethical cybersecurity tools:

☕ Buy Me a Coffee — (add link when ready)

💸 PayPal — (add link when ready)

📜 License

MIT License — see LICENSE

© 2025 Richard Barron — All Rights Reserved
