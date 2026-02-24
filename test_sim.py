#!/usr/bin/env python3
"""
SSHGuardian Test Harness — Simulate SSH attacks against a fake auth.log.

Creates a temporary auth.log, writes simulated attack lines into it,
and lets you watch SSHGuardian detect and respond to them in real-time.

Usage:
    # Terminal 1 — start SSHGuardian pointed at the fake log:
    sudo python3 sshguardian.py -c test_config.json --dry-run

    # Terminal 2 — run this script:
    python3 test_sim.py

    Or all-in-one:
    sudo python3 test_sim.py --self-test
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime

# ─── Colors ───────────────────────────────────────────────────────────────────
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"

FAKE_LOG = "/tmp/sshguardian_test_auth.log"
TEST_CONFIG = "/tmp/sshguardian_test_config.json"


def write_test_config():
    """Write a config that points at the fake log and disables blocking."""
    config = {
        "auth_log": FAKE_LOG,
        "threshold": 3,
        "window_seconds": 60,
        "block_enabled": False,
        "email_enabled": False,
        "whitelist": ["127.0.0.1"],
        "log_file": "/tmp/sshguardian_test.log",
        "log_level": "INFO",
        "cooldown_minutes": 1,
    }
    with open(TEST_CONFIG, "w") as f:
        json.dump(config, f, indent=2)
    return TEST_CONFIG


def sim_line(user: str, ip: str, success: bool = False) -> str:
    """Generate a realistic syslog SSH line."""
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    host = "testhost"
    if success:
        return f"{ts} {host} sshd[12345]: Accepted password for {user} from {ip} port 22 ssh2"
    return f"{ts} {host} sshd[12345]: Failed password for invalid user {user} from {ip} port 22 ssh2"


def run_simulation():
    """Write simulated attack lines into the fake log."""

    # Ensure the log file exists
    open(FAKE_LOG, "a").close()

    print(f"\n{B}{C}═══ SSHGuardian Test Simulation ═══{X}\n")
    print(f"  Writing to: {FAKE_LOG}")
    print("  Threshold:  3 failures in 60s\n")

    scenarios = [
        (
            "Scenario 1: Slow probe (below threshold)",
            [
                ("admin", "10.0.0.50", False),
                ("root", "10.0.0.50", False),
            ],
        ),
        (
            "Scenario 2: Brute-force burst (exceeds threshold)",
            [
                ("root", "192.168.1.100", False),
                ("admin", "192.168.1.100", False),
                ("ubuntu", "192.168.1.100", False),
                ("test", "192.168.1.100", False),
                ("deploy", "192.168.1.100", False),
            ],
        ),
        (
            "Scenario 3: Multiple attackers",
            [
                ("root", "203.0.113.5", False),
                ("admin", "203.0.113.5", False),
                ("root", "198.51.100.7", False),
                ("root", "203.0.113.5", False),
                ("admin", "198.51.100.7", False),
                ("root", "198.51.100.7", False),
                ("test", "198.51.100.7", False),
            ],
        ),
        (
            "Scenario 4: Legitimate login mixed in",
            [
                ("deploy", "10.0.0.1", True),
            ],
        ),
        (
            "Scenario 5: Whitelisted IP (should be ignored)",
            [
                ("root", "127.0.0.1", False),
                ("root", "127.0.0.1", False),
                ("root", "127.0.0.1", False),
                ("root", "127.0.0.1", False),
            ],
        ),
    ]

    with open(FAKE_LOG, "a") as log:
        for title, events in scenarios:
            print(f"  {Y}▸ {title}{X}")
            for user, ip, success in events:
                line = sim_line(user, ip, success)
                log.write(line + "\n")
                log.flush()
                tag = f"{G}✓ OK{X}" if success else "  FAIL"
                print(f"    {tag}  {user}@{ip}")
                time.sleep(0.4)
            print()
            time.sleep(1)

    print(f"  {B}{G}Simulation complete.{X}")
    print("  Check SSHGuardian output for detections.\n")


def self_test():
    """Run SSHGuardian + simulation together for a quick smoke test."""
    print(f"\n{B}{C}═══ SSHGuardian Self-Test ═══{X}\n")

    # Prepare
    write_test_config()
    open(FAKE_LOG, "w").close()  # fresh log

    # Start SSHGuardian in background
    script_dir = os.path.dirname(os.path.abspath(__file__))
    guardian_path = os.path.join(script_dir, "sshguardian.py")

    print("  Starting SSHGuardian (dry-run)...")
    proc = subprocess.Popen(
        [sys.executable, guardian_path, "-c", TEST_CONFIG, "--dry-run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(1)

    # Run simulation
    run_simulation()

    # Give it a moment to process
    time.sleep(2)

    # Kill guardian
    proc.send_signal(signal.SIGINT)
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()

    # Show guardian output
    print(f"\n{B}{C}═══ SSHGuardian Output ═══{X}\n")
    for line in output.splitlines():
        print(f"  {line}")

    # Check if alerts fired
    alert_count = output.count("ALERT")
    print(f"\n  {B}Results:{X}")
    if alert_count >= 2:
        print(f"  {G}✓ PASS{X} — {alert_count} alerts detected (expected ≥ 2)")
    else:
        print(f"  {Y}⚠ CHECK{X} — only {alert_count} alerts detected (expected ≥ 2)")

    if "127.0.0.1" not in output.split("ALERT")[0] if "ALERT" in output else True:
        print(f"  {G}✓ PASS{X} — Whitelisted IP (127.0.0.1) was not alerted")

    if "Accepted" in output:
        print(f"  {G}✓ PASS{X} — Legitimate login was logged")

    # Cleanup
    for f in [FAKE_LOG, TEST_CONFIG, "/tmp/sshguardian_test.log"]:
        if os.path.isfile(f):
            os.remove(f)

    print(f"\n  {G}{B}Self-test complete.{X}\n")


def main():
    parser = argparse.ArgumentParser(description="SSHGuardian Test Simulator")
    parser.add_argument(
        "--self-test", action="store_true", help="Run SSHGuardian + simulation together"
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
    else:
        run_simulation()


if __name__ == "__main__":
    main()
