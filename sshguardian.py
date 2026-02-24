#!/usr/bin/env python3
"""
SSHGuardian — Real-Time SSH Intrusion Detection for Linux

Monitors SSH authentication logs in real-time, detects brute-force attempts,
sends optional email alerts, and optionally blocks offending IPs via UFW or iptables.

Usage:
    sudo python3 sshguardian.py                  # Run with defaults
    sudo python3 sshguardian.py -c /etc/sshguardian/config.json
    sudo python3 sshguardian.py --dry-run         # Monitor only, no blocking
    sudo python3 sshguardian.py --status           # Show current threat table
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
import subprocess
import re
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# ─── Version ──────────────────────────────────────────────────────────────────
VERSION = "1.0.0"

# ─── Default paths ────────────────────────────────────────────────────────────
DEFAULT_CONFIG = "/etc/sshguardian/config.json"
DEFAULT_LOG_FILE = "/var/log/sshguardian.log"
STATE_FILE = "/var/lib/sshguardian/state.json"

# ─── Auth log locations (tried in order) ──────────────────────────────────────
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",       # Debian / Ubuntu
    "/var/log/secure",         # RHEL / CentOS / Fedora
]

# ─── Regex patterns for SSH log lines ─────────────────────────────────────────
PATTERNS = {
    "failed_password": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "invalid_user": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Invalid user (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "connection_closed_preauth": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Connection closed by (?:authenticating user \S+ )?(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "accepted_login": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Accepted (?:password|publickey) for (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    ),
    "too_many_auth": re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+"
        r"Disconnecting.*authenticating user (?P<user>\S+)?\s*(?P<ip>\d+\.\d+\.\d+\.\d+).*Too many authentication failures"
    ),
}

# ─── ANSI colors for terminal output ──────────────────────────────────────────
class C:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════
DEFAULT_SETTINGS = {
    "auth_log": "auto",
    "threshold": 5,
    "window_seconds": 300,
    "block_enabled": False,
    "block_method": "ufw",
    "block_duration_minutes": 60,
    "email_enabled": False,
    "email_to": "",
    "email_from": "",
    "smtp_server": "localhost",
    "smtp_port": 25,
    "smtp_tls": False,
    "smtp_user": "",
    "smtp_pass": "",
    "whitelist": ["127.0.0.1"],
    "log_file": DEFAULT_LOG_FILE,
    "log_level": "INFO",
    "cooldown_minutes": 10,
}


def load_config(path: str) -> dict:
    """Load configuration, merging user settings over defaults."""
    config = dict(DEFAULT_SETTINGS)
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                user_config = json.load(f)
            config.update(user_config)
            return config
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[WARN] Could not load config {path}: {exc}", file=sys.stderr)
    return config


def resolve_auth_log(config: dict) -> str:
    """Determine which auth log file to monitor."""
    if config["auth_log"] != "auto":
        return config["auth_log"]
    for candidate in AUTH_LOG_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return AUTH_LOG_CANDIDATES[0]


# ═══════════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════════
def setup_logging(config: dict) -> logging.Logger:
    logger = logging.getLogger("sshguardian")
    logger.setLevel(getattr(logging, config["log_level"].upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_dir = os.path.dirname(config["log_file"])
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    try:
        fh = logging.FileHandler(config["log_file"])
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        logger.warning("Could not open log file %s — console only", config["log_file"])

    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# Email Alerts
# ═══════════════════════════════════════════════════════════════════════════════
def send_email_alert(config: dict, subject: str, body: str, logger: logging.Logger):
    """Send an email alert via SMTP."""
    if not config["email_enabled"] or not config["email_to"]:
        return

    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = config["email_from"] or f"sshguardian@{os.uname().nodename}"
        msg["To"] = config["email_to"]

        with smtplib.SMTP(config["smtp_server"], config["smtp_port"], timeout=15) as srv:
            if config["smtp_tls"]:
                srv.starttls()
            if config["smtp_user"]:
                srv.login(config["smtp_user"], config["smtp_pass"])
            srv.sendmail(msg["From"], [config["email_to"]], msg.as_string())

        logger.info("✉  Email alert sent → %s: %s", config["email_to"], subject)
    except Exception as exc:
        logger.error("Failed to send email: %s", exc)


def build_alert_body(ip: str, tracker: dict, hostname: str) -> str:
    """Build a human-readable alert email body."""
    entry = tracker[ip]
    lines = [
        f"═══ SSHGuardian Alert ═══",
        f"",
        f"Host:        {hostname}",
        f"Threat IP:   {ip}",
        f"Failed attempts: {entry['count']} in {entry['window']}s window",
        f"First seen:  {entry['first_seen']}",
        f"Last seen:   {entry['last_seen']}",
        f"Users tried: {', '.join(sorted(entry['users']))}",
        f"",
        f"Action taken: {'IP BLOCKED' if entry.get('blocked') else 'ALERT ONLY (blocking disabled)'}",
        f"",
        f"— SSHGuardian v{VERSION}",
    ]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# IP Blocking
# ═══════════════════════════════════════════════════════════════════════════════
def block_ip(ip: str, config: dict, logger: logging.Logger, dry_run: bool = False) -> bool:
    """Block an IP address using UFW or iptables."""
    if not config["block_enabled"] or dry_run:
        if dry_run:
            logger.info("🔒 [DRY-RUN] Would block IP %s via %s", ip, config["block_method"])
        return False

    method = config["block_method"].lower()
    try:
        if method == "ufw":
            cmd = ["ufw", "insert", "1", "deny", "from", ip, "to", "any"]
        elif method == "iptables":
            cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        else:
            logger.error("Unknown block_method: %s", method)
            return False

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            logger.warning("🔒 BLOCKED %s via %s", ip, method)
            return True
        else:
            logger.error("Block failed for %s: %s", ip, result.stderr.strip())
            return False
    except FileNotFoundError:
        logger.error("%s not found — install it or change block_method in config", method)
        return False
    except subprocess.TimeoutExpired:
        logger.error("Timeout blocking %s", ip)
        return False


def unblock_ip(ip: str, config: dict, logger: logging.Logger):
    """Remove a block rule for an IP."""
    method = config["block_method"].lower()
    try:
        if method == "ufw":
            cmd = ["ufw", "delete", "deny", "from", ip, "to", "any"]
        elif method == "iptables":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            return
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        logger.info("🔓 UNBLOCKED %s via %s", ip, method)
    except Exception as exc:
        logger.error("Failed to unblock %s: %s", ip, exc)


# ═══════════════════════════════════════════════════════════════════════════════
# State persistence — survive restarts
# ═══════════════════════════════════════════════════════════════════════════════
def save_state(tracker: dict, blocked: dict):
    """Persist tracker and blocked IPs to disk."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    state = {
        "tracker": {},
        "blocked": {},
    }
    for ip, info in tracker.items():
        state["tracker"][ip] = {
            "count": info["count"],
            "users": list(info["users"]),
            "timestamps": [t.isoformat() for t in info["timestamps"]],
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"],
        }
    for ip, unblock_time in blocked.items():
        state["blocked"][ip] = unblock_time.isoformat()
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except OSError:
        pass


def load_state() -> tuple:
    """Restore tracker and blocked IPs from disk."""
    tracker = defaultdict(lambda: {
        "count": 0, "timestamps": [], "users": set(),
        "first_seen": "", "last_seen": "", "alerted": False, "blocked": False,
    })
    blocked = {}
    if not os.path.isfile(STATE_FILE):
        return tracker, blocked
    try:
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
        for ip, info in state.get("tracker", {}).items():
            tracker[ip] = {
                "count": info["count"],
                "timestamps": [datetime.fromisoformat(t) for t in info["timestamps"]],
                "users": set(info["users"]),
                "first_seen": info["first_seen"],
                "last_seen": info["last_seen"],
                "alerted": True,
                "blocked": False,
            }
        for ip, t in state.get("blocked", {}).items():
            blocked[ip] = datetime.fromisoformat(t)
    except (json.JSONDecodeError, OSError, KeyError):
        pass
    return tracker, blocked


# ═══════════════════════════════════════════════════════════════════════════════
# Log Tail — follow auth.log in real-time
# ═══════════════════════════════════════════════════════════════════════════════
def tail_follow(filepath: str, logger: logging.Logger):
    """
    Generator that yields new lines appended to a file (like tail -F).
    Handles log rotation (file shrinks or inode changes).
    """
    while not os.path.isfile(filepath):
        logger.warning("Waiting for %s to appear...", filepath)
        time.sleep(2)

    with open(filepath, "r") as f:
        # Seek to end — we only care about new lines
        f.seek(0, 2)
        stat = os.stat(filepath)
        inode = stat.st_ino

        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.3)
                # Check for log rotation
                try:
                    new_stat = os.stat(filepath)
                    if new_stat.st_ino != inode or new_stat.st_size < f.tell():
                        logger.info("Log rotation detected — reopening %s", filepath)
                        f.close()
                        time.sleep(0.5)
                        f_new = open(filepath, "r")
                        inode = os.stat(filepath).st_ino
                        # Replace generator's file handle (we re-enter the loop)
                        yield from _continue_tail(f_new, filepath, logger)
                        return
                except FileNotFoundError:
                    time.sleep(1)


def _continue_tail(f, filepath, logger):
    """Continue tailing from a newly opened file."""
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if line:
            yield line.rstrip("\n")
        else:
            time.sleep(0.3)
            try:
                new_stat = os.stat(filepath)
                if new_stat.st_ino != inode or new_stat.st_size < f.tell():
                    logger.info("Log rotation detected — reopening %s", filepath)
                    f.close()
                    time.sleep(0.5)
                    f_new = open(filepath, "r")
                    inode = os.stat(filepath).st_ino
                    yield from _continue_tail(f_new, filepath, logger)
                    return
            except FileNotFoundError:
                time.sleep(1)


# ═══════════════════════════════════════════════════════════════════════════════
# Core Detection Engine
# ═══════════════════════════════════════════════════════════════════════════════
def parse_line(line: str) -> dict | None:
    """Parse a single log line. Returns dict with type/ip/user or None."""
    for event_type, pattern in PATTERNS.items():
        m = pattern.search(line)
        if m:
            groups = m.groupdict()
            return {
                "type": event_type,
                "ip": groups.get("ip", ""),
                "user": groups.get("user", "unknown"),
                "timestamp": groups.get("timestamp", ""),
            }
    return None


class DetectionEngine:
    """Tracks failed SSH attempts per IP and triggers alerts/blocks."""

    def __init__(self, config: dict, logger: logging.Logger, dry_run: bool = False):
        self.config = config
        self.logger = logger
        self.dry_run = dry_run
        self.hostname = os.uname().nodename
        self.whitelist = set(config.get("whitelist", []))

        # State
        self.tracker, self.blocked = load_state()
        self.cooldowns = {}  # ip -> datetime when cooldown expires
        self.stats = {"events_total": 0, "alerts_fired": 0, "ips_blocked": 0, "start_time": datetime.now()}

    def process_event(self, event: dict):
        """Process a parsed SSH event."""
        ip = event["ip"]
        user = event["user"]
        etype = event["type"]
        now = datetime.now()

        # ── Accepted login — informational log ──
        if etype == "accepted_login":
            self.logger.info(
                "%s✓  Accepted login%s for %s%s%s from %s%s%s",
                C.GRN, C.RST, C.BLD, user, C.RST, C.CYN, ip, C.RST,
            )
            return

        # ── Skip whitelisted IPs ──
        if ip in self.whitelist:
            return

        self.stats["events_total"] += 1

        # ── Initialize or update tracker ──
        entry = self.tracker[ip]
        entry["timestamps"].append(now)
        entry["count"] += 1
        entry["users"].add(user)
        if not entry["first_seen"]:
            entry["first_seen"] = now.strftime("%Y-%m-%d %H:%M:%S")
        entry["last_seen"] = now.strftime("%Y-%m-%d %H:%M:%S")
        entry["window"] = self.config["window_seconds"]

        # ── Prune old timestamps outside the detection window ──
        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        entry["timestamps"] = [t for t in entry["timestamps"] if t > cutoff]
        recent_count = len(entry["timestamps"])

        # ── Log each failed attempt ──
        severity = "⚡" if recent_count >= self.config["threshold"] - 1 else "•"
        self.logger.info(
            "%s  Failed auth from %s%s%s → user=%s%s%s  [%d in window]",
            severity, C.YEL, ip, C.RST, C.BLD, user, C.RST, recent_count,
        )

        # ── Threshold reached? ──
        if recent_count >= self.config["threshold"]:
            self._trigger_alert(ip, entry, now)

    def _trigger_alert(self, ip: str, entry: dict, now: datetime):
        """Fire alert and optionally block when threshold is exceeded."""

        # Cooldown check — don't spam alerts for the same IP
        if ip in self.cooldowns and now < self.cooldowns[ip]:
            return

        self.cooldowns[ip] = now + timedelta(minutes=self.config["cooldown_minutes"])
        self.stats["alerts_fired"] += 1

        recent = len(entry["timestamps"])
        users_str = ", ".join(sorted(entry["users"]))

        self.logger.warning(
            "%s%s🚨 ALERT: %s exceeded threshold — %d failures in %ds (users: %s)%s",
            C.RED, C.BLD, ip, recent, self.config["window_seconds"], users_str, C.RST,
        )

        # ── Email alert ──
        subject = f"[SSHGuardian] 🚨 Brute-force detected from {ip} on {self.hostname}"
        body = build_alert_body(ip, self.tracker, self.hostname)
        send_email_alert(self.config, subject, body, self.logger)

        # ── Block ──
        if self.config["block_enabled"] and ip not in self.blocked:
            blocked = block_ip(ip, self.config, self.logger, self.dry_run)
            if blocked:
                entry["blocked"] = True
                self.blocked[ip] = now + timedelta(minutes=self.config["block_duration_minutes"])
                self.stats["ips_blocked"] += 1

        entry["alerted"] = True
        save_state(self.tracker, self.blocked)

    def expire_blocks(self):
        """Unblock IPs whose block duration has expired."""
        now = datetime.now()
        expired = [ip for ip, exp in self.blocked.items() if now >= exp]
        for ip in expired:
            unblock_ip(ip, self.config, self.logger)
            del self.blocked[ip]
            if ip in self.tracker:
                self.tracker[ip]["blocked"] = False
        if expired:
            save_state(self.tracker, self.blocked)

    def print_status(self):
        """Print a summary table of current tracked IPs."""
        now = datetime.now()
        uptime = now - self.stats["start_time"]
        hours = int(uptime.total_seconds() // 3600)
        mins = int((uptime.total_seconds() % 3600) // 60)

        print(f"\n{C.BLD}{C.CYN}═══ SSHGuardian Status ═══{C.RST}")
        print(f"  Uptime:       {hours}h {mins}m")
        print(f"  Events seen:  {self.stats['events_total']}")
        print(f"  Alerts fired: {self.stats['alerts_fired']}")
        print(f"  IPs blocked:  {self.stats['ips_blocked']}")
        print(f"  Active blocks: {len(self.blocked)}")
        print()

        if not self.tracker:
            print(f"  {C.DIM}No tracked IPs yet.{C.RST}\n")
            return

        print(f"  {'IP':<18} {'Fails':>6} {'Users':<30} {'Last Seen':<20} {'Status':<10}")
        print(f"  {'─'*18} {'─'*6} {'─'*30} {'─'*20} {'─'*10}")
        for ip, info in sorted(self.tracker.items(), key=lambda x: x[1]["count"], reverse=True):
            users = ", ".join(sorted(info["users"]))[:28]
            status = f"{C.RED}BLOCKED{C.RST}" if info.get("blocked") else (
                f"{C.YEL}ALERTED{C.RST}" if info.get("alerted") else f"{C.DIM}tracking{C.RST}"
            )
            print(f"  {ip:<18} {info['count']:>6} {users:<30} {info['last_seen']:<20} {status}")
        print()


# ═══════════════════════════════════════════════════════════════════════════════
# Status command (read-only)
# ═══════════════════════════════════════════════════════════════════════════════
def show_status():
    """Show current state without running the daemon."""
    tracker, blocked = load_state()
    now = datetime.now()

    print(f"\n{C.BLD}{C.CYN}═══ SSHGuardian — Current State ═══{C.RST}")
    print(f"  Active blocks: {len(blocked)}")

    if not tracker:
        print(f"  {C.DIM}No tracked IPs in state file.{C.RST}\n")
        return

    print(f"\n  {'IP':<18} {'Fails':>6} {'Users':<30} {'Last Seen':<20} {'Blocked':<10}")
    print(f"  {'─'*18} {'─'*6} {'─'*30} {'─'*20} {'─'*10}")
    for ip, info in sorted(tracker.items(), key=lambda x: x[1]["count"], reverse=True):
        users = ", ".join(sorted(info["users"]))[:28]
        is_blocked = ip in blocked
        status = f"{C.RED}YES{C.RST}" if is_blocked else f"{C.DIM}no{C.RST}"
        if is_blocked:
            exp = blocked[ip]
            remaining = exp - now
            if remaining.total_seconds() > 0:
                mins = int(remaining.total_seconds() // 60)
                status = f"{C.RED}YES ({mins}m left){C.RST}"
        print(f"  {ip:<18} {info['count']:>6} {users:<30} {info['last_seen']:<20} {status}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="SSHGuardian — Real-Time SSH Intrusion Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG, help="Config file path")
    parser.add_argument("--dry-run", action="store_true", help="Monitor only — no blocking")
    parser.add_argument("--status", action="store_true", help="Show current threat table and exit")
    parser.add_argument("--version", action="version", version=f"SSHGuardian v{VERSION}")
    args = parser.parse_args()

    # ── Status mode ──
    if args.status:
        show_status()
        sys.exit(0)

    # ── Root check ──
    if os.geteuid() != 0:
        print(f"{C.RED}Error: SSHGuardian must run as root to read auth logs and manage firewall rules.{C.RST}")
        print(f"  Try: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    # ── Load config ──
    config = load_config(args.config)
    if args.dry_run:
        config["block_enabled"] = False

    logger = setup_logging(config)
    auth_log = resolve_auth_log(config)

    # ── Banner ──
    logger.info("═" * 55)
    logger.info("  SSHGuardian v%s starting", VERSION)
    logger.info("  Host:       %s", os.uname().nodename)
    logger.info("  Monitoring: %s", auth_log)
    logger.info("  Threshold:  %d failures in %ds", config["threshold"], config["window_seconds"])
    logger.info("  Blocking:   %s", f"{config['block_method'].upper()}" if config["block_enabled"] else "DISABLED")
    logger.info("  Email:      %s", config["email_to"] if config["email_enabled"] else "DISABLED")
    logger.info("  Dry-run:    %s", "YES" if args.dry_run else "no")
    logger.info("  Whitelist:  %s", ", ".join(config["whitelist"]) if config["whitelist"] else "none")
    logger.info("═" * 55)

    # ── Detection engine ──
    engine = DetectionEngine(config, logger, dry_run=args.dry_run)

    # ── Signal handlers ──
    shutdown = False

    def handle_signal(signum, frame):
        nonlocal shutdown
        sig_name = signal.Signals(signum).name
        logger.info("Received %s — shutting down", sig_name)
        shutdown = True

    def handle_usr1(signum, frame):
        engine.print_status()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGUSR1, handle_usr1)

    # ── Block expiration counter ──
    last_expire_check = time.time()

    # ── Main loop ──
    logger.info("Watching %s for SSH events... (Ctrl+C to stop)", auth_log)

    try:
        for line in tail_follow(auth_log, logger):
            if shutdown:
                break

            event = parse_line(line)
            if event:
                engine.process_event(event)

            # Periodic block expiration check (every 30s)
            now_ts = time.time()
            if now_ts - last_expire_check > 30:
                engine.expire_blocks()
                last_expire_check = now_ts

    except KeyboardInterrupt:
        pass

    logger.info("SSHGuardian stopped.")
    save_state(engine.tracker, engine.blocked)


if __name__ == "__main__":
    main()
