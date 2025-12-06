#!/usr/bin/env python3
"""
Red Specter - AI Usage Watchdog (Linux Agent v0.1)

Purpose:
    Lightweight process watcher that logs suspected AI/LLM usage events
    on a Linux endpoint in a privacy-preserving way.

Features (v0.1):
    - Polls running processes at a fixed interval
    - Matches against simple, configurable signatures
      (process name or command-line substrings)
    - Logs events to a JSONL file with risk/category metadata
    - Avoids capturing full prompt content or files
"""

import argparse
import json
import os
import socket
import time
from datetime import datetime, timezone

try:
    import psutil  # type: ignore
except ImportError:
    print("[!] psutil is required. Install with: pip install psutil")
    raise

# ---------------------------------------------------------------------------
# Signature configuration (MVP – can later move to external JSON/YAML)
# ---------------------------------------------------------------------------

SIGNATURES = [
    {
        "name": "ollama_local_llm",
        "description": "Local LLM runtime (Ollama)",
        "match_type": "process_name_contains",
        "pattern": "ollama",
        "risk": "medium",
        "category": "local_llm",
    },
    {
        "name": "open_webui_frontend",
        "description": "Open WebUI interface",
        "match_type": "process_name_contains",
        "pattern": "open-webui",
        "risk": "medium",
        "category": "local_llm_ui",
    },
    {
        "name": "openai_api_call",
        "description": "Process calling OpenAI API endpoint",
        "match_type": "cmdline_contains",
        "pattern": "api.openai.com",
        "risk": "high",
        "category": "remote_llm",
    },
    {
        "name": "anthropic_api_call",
        "description": "Process calling Anthropic API endpoint",
        "match_type": "cmdline_contains",
        "pattern": "api.anthropic.com",
        "risk": "high",
        "category": "remote_llm",
    },
    {
        "name": "google_gemini_api_call",
        "description": "Process calling Google Gemini / generative AI endpoint",
        "match_type": "cmdline_contains",
        "pattern": "generativelanguage.googleapis.com",
        "risk": "high",
        "category": "remote_llm",
    },
    {
        "name": "generic_llm_keyword",
        "description": "Process with generic LLM-related keyword in command line",
        "match_type": "cmdline_contains",
        "pattern": "llm",
        "risk": "low",
        "category": "generic_ai",
    },
]

# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def ensure_log_dir(path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def match_signature(sig: dict, proc_info: dict) -> bool:
    """Return True if this process matches the given signature."""
    pname = (proc_info.get("name") or "").lower()
    cmdline_list = proc_info.get("cmdline") or []
    cmdline_str = " ".join(cmdline_list).lower()

    pattern = sig.get("pattern", "").lower()
    mtype = sig.get("match_type", "")

    if not pattern or not mtype:
        return False

    if mtype == "process_name_contains":
        return pattern in pname
    elif mtype == "cmdline_contains":
        return pattern in cmdline_str

    return False


def scan_once(signatures, seen, hostname, logfile, debug=False):
    """Perform a single scan of running processes."""
    events_written = 0

    try:
        with open(logfile, "a", encoding="utf-8") as f:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    info = proc.info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

                pid = info.get("pid")
                pname = info.get("name") or ""
                cmdline = info.get("cmdline") or []
                username = info.get("username") or "unknown"

                for sig in signatures:
                    if not match_signature(sig, info):
                        continue

                    key = (pid, sig["name"])
                    if key in seen:
                        # Already logged this pid+signature combo this run
                        continue

                    seen.add(key)

                    event = {
                        "timestamp_utc": utc_now_iso(),
                        "hostname": hostname,
                        "username": username,
                        "pid": pid,
                        "process_name": pname,
                        "cmdline": cmdline,  # Command line only; NOT logging file content or prompts
                        "signature_name": sig.get("name"),
                        "signature_description": sig.get("description"),
                        "risk": sig.get("risk", "unknown"),
                        "category": sig.get("category", "unknown"),
                        "version": "v0.1",
                        "product": "Red Specter AI Usage Watchdog",
                    }

                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
                    events_written += 1

                    if debug:
                        print(
                            f"[MATCH] {event['timestamp_utc']} "
                            f"{event['process_name']} (pid={pid}) "
                            f"-> {event['signature_name']} "
                            f"[risk={event['risk']}]"
                        )
    except OSError as e:
        print(f"[!] Failed to write log file '{logfile}': {e}")

    return events_written


def main():
    parser = argparse.ArgumentParser(
        description="Red Specter AI Usage Watchdog (Linux Agent v0.1)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Scan interval in seconds (default: 10)",
    )
    parser.add_argument(
        "--logfile",
        type=str,
        default=os.path.expanduser(
            "~/.redspecter_ai_watchdog/logs/events.jsonl"
        ),
        help="Path to JSONL log file "
        "(default: ~/.redspecter_ai_watchdog/logs/events.jsonl)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit (no loop)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print matches to stdout as they are logged",
    )

    args = parser.parse_args()

    ensure_log_dir(args.logfile)
    hostname = socket.gethostname()

    print(
        f"[+] Red Specter AI Usage Watchdog v0.1 starting on host '{hostname}'\n"
        f"    Log file : {args.logfile}\n"
        f"    Interval : {args.interval} seconds\n"
        f"    Mode     : {'single-scan' if args.once else 'continuous'}"
    )

    seen = set()

    if args.once:
        events = scan_once(SIGNATURES, seen, hostname, args.logfile, args.debug)
        print(f"[+] Scan complete. Events logged: {events}")
        return

    try:
        while True:
            events = scan_once(SIGNATURES, seen, hostname, args.logfile, args.debug)
            if args.debug:
                print(f"[+] Cycle complete. Events logged this cycle: {events}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[+] Watchdog stopped by user (Ctrl+C). Goodbye.")


if __name__ == "__main__":
    main()
