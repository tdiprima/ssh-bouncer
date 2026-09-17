#!/usr/bin/env python3
"""
SSHBouncer Test Harness — Simulate SSH attacks against a fake auth.log.

Creates a temporary auth.log, writes simulated attack lines into it,
and lets you watch SSHBouncer detect and respond to them in real-time.

Usage:
    # Terminal 1 — start SSHBouncer pointed at the fake log:
    python3 sshbouncer.py -c /tmp/sshbouncer_test_config.json --dry-run

    # Terminal 2 — run this script:
    python3 test_sim.py

    Or all-in-one (exit status 0 on pass, 1 on failure):
    python3 test_sim.py --self-test
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── Colors ───────────────────────────────────────────────────────────────────
G = "\033[92m"
R = "\033[91m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"

FAKE_LOG = "/tmp/sshbouncer_test_auth.log"
TEST_CONFIG = "/tmp/sshbouncer_test_config.json"
TEST_LOG_FILE = "/tmp/sshbouncer_test.log"
TEST_STATE_FILE = "/tmp/sshbouncer_test_state.json"
TEST_DRY_RUN_STATE_FILE = "/tmp/sshbouncer_test_state.dry-run.json"

# IPs the scenarios below drive past the threshold (3 failures in 60s).
EXPECTED_ALERT_IPS = ("192.168.1.100", "203.0.113.5", "198.51.100.7")
# IPs that must never alert: below threshold, or whitelisted.
EXPECTED_QUIET_IPS = ("10.0.0.50", "127.0.0.1")
LEGITIMATE_LOGIN_IP = "10.0.0.1"


def write_test_config():
    """Write a config that points at the fake log and disables blocking."""
    config = {
        "auth_log": FAKE_LOG,
        "threshold": 3,
        "window_seconds": 60,
        "block_enabled": False,
        "email_enabled": False,
        "whitelist": ["127.0.0.1"],
        "log_file": TEST_LOG_FILE,
        "log_level": "INFO",
        "cooldown_minutes": 1,
        "state_file": TEST_STATE_FILE,
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

    print(f"\n{B}{C}═══ SSHBouncer Test Simulation ═══{X}\n")
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
    print("  Check SSHBouncer output for detections.\n")


def start_daemon() -> subprocess.Popen:
    """Launch sshbouncer.py in dry-run against the test config."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    daemon_path = os.path.join(script_dir, "sshbouncer.py")
    print("  Starting SSHBouncer (dry-run)...")
    return subprocess.Popen(
        [sys.executable, daemon_path, "-c", TEST_CONFIG, "--dry-run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_daemon(proc: subprocess.Popen) -> tuple[str, int]:
    """Send SIGINT and collect output + exit status. Kills on hang."""
    proc.send_signal(signal.SIGINT)
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
    return output, proc.returncode


def alerted_ips(output: str) -> set:
    """Extract every IP the engine reported as brute-force."""
    return set(re.findall(r"event=brute_force_detected ip=(\S+)", output))


def evaluate_output(output: str, exit_code: int) -> list:
    """Return a list of (passed, description) checks from the daemon output."""
    detected = alerted_ips(output)
    checks = [
        (exit_code == 0, f"Daemon exited cleanly (exit code {exit_code})"),
        ("event=startup" in output, "Daemon started and read the config"),
    ]
    for ip in EXPECTED_ALERT_IPS:
        checks.append((ip in detected, f"Brute force detected from {ip}"))
    for ip in EXPECTED_QUIET_IPS:
        checks.append((ip not in detected, f"No alert for {ip} (below threshold or whitelisted)"))
    checks.append(
        (f"event=accepted_login ip={LEGITIMATE_LOGIN_IP}" in output,
         f"Legitimate login from {LEGITIMATE_LOGIN_IP} was logged"),
    )
    checks.append(
        (output.count("event=brute_force_detected ip=192.168.1.100") == 1,
         "Cooldown suppressed repeat alerts for 192.168.1.100"),
    )
    return checks


def cleanup_test_files() -> None:
    for path in (FAKE_LOG, TEST_CONFIG, TEST_LOG_FILE, TEST_STATE_FILE, TEST_DRY_RUN_STATE_FILE):
        if os.path.isfile(path):
            Path(path).unlink()


def self_test() -> int:
    """Run SSHBouncer + simulation together. Returns 0 on pass, 1 on any failed check."""
    print(f"\n{B}{C}═══ SSHBouncer Self-Test ═══{X}\n")

    cleanup_test_files()
    write_test_config()
    open(FAKE_LOG, "w").close()  # fresh log

    proc = start_daemon()
    time.sleep(1)

    if proc.poll() is not None:
        output, _ = proc.communicate()
        print(f"  {R}✗ FAIL{X} — daemon exited before simulation (exit code {proc.returncode})")
        for line in output.splitlines():
            print(f"  {line}")
        cleanup_test_files()
        return 1

    run_simulation()
    time.sleep(2)  # let the follower drain the last lines
    output, exit_code = stop_daemon(proc)

    print(f"\n{B}{C}═══ SSHBouncer Output ═══{X}\n")
    for line in output.splitlines():
        print(f"  {line}")

    checks = evaluate_output(output, exit_code)
    print(f"\n  {B}Results:{X}")
    failed = 0
    for passed, description in checks:
        tag = f"{G}✓ PASS{X}" if passed else f"{R}✗ FAIL{X}"
        print(f"  {tag} — {description}")
        if not passed:
            failed += 1

    cleanup_test_files()

    if failed:
        print(f"\n  {R}{B}Self-test FAILED ({failed} check(s)).{X}\n")
        return 1
    print(f"\n  {G}{B}Self-test passed.{X}\n")
    return 0


def main():
    parser = argparse.ArgumentParser(description="SSHBouncer Test Simulator")
    parser.add_argument(
        "--self-test", action="store_true", help="Run SSHBouncer + simulation together"
    )
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())
    run_simulation()


if __name__ == "__main__":
    main()
