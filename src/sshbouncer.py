#!/usr/bin/env python3
"""
SSHBouncer — Real-Time SSH Intrusion Detection for Linux

Monitors SSH authentication logs in real-time, detects brute-force attempts,
sends optional email alerts, and optionally blocks offending IPs via UFW or iptables.

Usage:
    sudo python3 sshbouncer.py                  # Run with defaults
    sudo python3 sshbouncer.py -c /etc/sshbouncer/config.json
    sudo python3 sshbouncer.py --dry-run         # Monitor only, no blocking
    sudo python3 sshbouncer.py --status           # Show current threat table
"""

import time
from parser import parse_line
from engine import DetectionEngine


CONFIG = {
    "threshold": 5,
    "window_seconds": 300,
    "block_enabled": False,
    "block_method": "ufw",
    "email_enabled": False,
}


def tail_follow(filepath):
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()


def main():
    engine = DetectionEngine(CONFIG)

    for line in tail_follow("/var/log/auth.log"):
        event = parse_line(line)
        if event:
            engine.process_event(event)


if __name__ == "__main__":
    main()
