# 🛡️ Red Specter – AI Usage Watchdog
Part of the Red Specter Purple Team AI Defense Suite

> Offense-driven defense. Visibility without surveillance.

Red Specter – AI Usage Watchdog is a **lightweight Linux agent** that observes
AI / LLM usage on an endpoint and produces **privacy-preserving audit logs**.

It is designed to complement:

- **Red Specter – AI Endpoint Guard** (endpoint enforcement)
- **Red Specter – AI Breach Monitor** (intrusion / anomaly detection)

Together, these tools form the foundation of the **Red Specter Purple Team AI Defense Suite**.

---

## ✨ Features (v0.1 – Agent MVP)

- 🐧 **Linux-first agent** (Python)
- 🔎 **Process + command line inspection** using `psutil`
- 🧩 **Signature-based detection** of common AI runtimes and API calls  
  (e.g. local LLMs, `api.openai.com`, Anthropic, Gemini, generic `llm` tools)
- 📜 **JSONL event logging** to a local file for easy ingestion into SIEM / log stacks
- 🔐 **Privacy-first design**  
  - No prompt / message content captured  
  - No file contents captured  
  - Only process metadata + signature matches

---

## 🚀 Quick Start

### 1. Requirements

- Python 3
- `psutil` library

Install `psutil` on Kali:

```bash
sudo apt install python3-psutil
# or:
pip install --user psutil
