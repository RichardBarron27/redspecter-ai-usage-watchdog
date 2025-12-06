#!/usr/bin/env python3
"""
Red Specter - AI Usage Watchdog Viewer (v0.1)

Simple CLI tool to summarise events from the Watchdog JSONL log file.

Usage examples:

    python3 watchdog_view.py
    python3 watchdog_view.py --logfile /path/to/events.jsonl
    python3 watchdog_view.py --top 10

"""

import argparse
import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional


DEFAULT_LOGFILE = os.path.expanduser("~/.redspecter_ai_watchdog/logs/events.jsonl")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Red Specter - AI Usage Watchdog log viewer"
    )
    parser.add_argument(
        "--logfile",
        type=str,
        default=DEFAULT_LOGFILE,
        help=f"Path to JSONL log file (default: {DEFAULT_LOGFILE})",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top items to display in summaries (default: 5)",
    )
    parser.add_argument(
        "--show-events",
        action="store_true",
        help="Print each matching event as JSON",
    )
    return parser.parse_args()


def load_events(logfile: str) -> List[Dict[str, Any]]:
    path = Path(logfile)
    if not path.exists():
        print(f"[!] Log file does not exist: {logfile}")
        return []

    events: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
                events.append(evt)
            except json.JSONDecodeError:
                # Skip malformed lines
                continue
    return events


def parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # datetime.fromisoformat handles the ISO8601 we used in the agent
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def print_summary(events: List[Dict[str, Any]], top_n: int = 5) -> None:
    if not events:
        print("[+] No events found in log.")
        return

    total = len(events)
    risks = Counter(evt.get("risk", "unknown") for evt in events)
    signatures = Counter(evt.get("signature_name", "unknown") for evt in events)
    users = Counter(evt.get("username", "unknown") for evt in events)
    hosts = Counter(evt.get("hostname", "unknown") for evt in events)

    timestamps = [parse_ts(evt.get("timestamp_utc")) for evt in events]
    timestamps = [t for t in timestamps if t is not None]
    if timestamps:
        first_ts = min(timestamps)
        last_ts = max(timestamps)
        time_range = f"{first_ts.isoformat()}  →  {last_ts.isoformat()}"
    else:
        time_range = "unknown"

    print("==============================================")
    print(" Red Specter - AI Usage Watchdog: Log Summary")
    print("==============================================")
    print(f"Total events : {total}")
    print(f"Time range   : {time_range}")
    print()

    def print_counter(title: str, counter: Counter, top: int) -> None:
        print(f"{title}:")
        if not counter:
            print("  (none)")
            print()
            return
        for item, count in counter.most_common(top):
            print(f"  {item:30} {count}")
        print()

    print_counter("By risk", risks, top_n)
    print_counter("By signature", signatures, top_n)
    print_counter("By user", users, top_n)
    print_counter("By host", hosts, top_n)


def print_events(events: List[Dict[str, Any]]) -> None:
    if not events:
        return

    for evt in events:
        print(json.dumps(evt, ensure_ascii=False))


def main() -> None:
    args = parse_args()
    logfile = args.logfile

    print(f"[+] Reading events from: {logfile}")
    events = load_events(logfile)

    print_summary(events, top_n=args.top)

    if args.show_events:
        print("---------- Raw events ----------")
        print_events(events)


if __name__ == "__main__":
    main()
