#!/usr/bin/env python3
"""
SSHGuardian Installer — Sets up config, directories, and systemd service.

Usage:
    sudo python3 install.py           # Interactive install
    sudo python3 install.py --uninstall
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

# ─── Paths ────────────────────────────────────────────────────────────────────
INSTALL_DIR = "/opt/sshguardian"
CONFIG_DIR = "/etc/sshguardian"
CONFIG_FILE = f"{CONFIG_DIR}/config.json"
LOG_DIR = "/var/log"
LOG_FILE = f"{LOG_DIR}/sshguardian.log"
STATE_DIR = "/var/lib/sshguardian"
SYSTEMD_FILE = "/etc/systemd/system/sshguardian.service"
SCRIPT_NAME = "sshguardian.py"

# ─── Colors ───────────────────────────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"

# ─── Default config ──────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
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
    "log_file": LOG_FILE,
    "log_level": "INFO",
    "cooldown_minutes": 10,
}

# ─── Systemd unit ─────────────────────────────────────────────────────────────
SYSTEMD_UNIT = f"""[Unit]
Description=SSHGuardian — Real-Time SSH Intrusion Detection
After=network.target sshd.service
Wants=sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {INSTALL_DIR}/{SCRIPT_NAME} -c {CONFIG_FILE}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sshguardian

[Install]
WantedBy=multi-user.target
"""


def banner():
    print(
        f"""
{B}{C}╔══════════════════════════════════════════════════╗
║          SSHGuardian  —  Installer               ║
║    Real-Time SSH Intrusion Detection for Linux    ║
╚══════════════════════════════════════════════════╝{X}
"""
    )


def check_root():
    if os.geteuid() != 0:
        print(f"{R}Error: installer must be run as root.{X}")
        print("  Try: sudo python3 install.py")
        sys.exit(1)


def ask(prompt, default=""):
    """Prompt user with a default value."""
    if default:
        val = input(f"  {prompt} [{default}]: ").strip()
        return val if val else default
    return input(f"  {prompt}: ").strip()


def ask_yn(prompt, default=False):
    """Yes/No prompt."""
    hint = "[Y/n]" if default else "[y/N]"
    val = input(f"  {prompt} {hint}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def install():
    banner()
    check_root()

    print(f"{B}Step 1: Configuration{X}\n")

    config = dict(DEFAULT_CONFIG)

    # Threshold
    t = ask("Failed login threshold before alert", str(config["threshold"]))
    try:
        config["threshold"] = int(t)
    except ValueError:
        pass

    w = ask("Detection window (seconds)", str(config["window_seconds"]))
    try:
        config["window_seconds"] = int(w)
    except ValueError:
        pass

    # Whitelist
    wl = ask("Whitelisted IPs (comma-separated)", ", ".join(config["whitelist"]))
    config["whitelist"] = [ip.strip() for ip in wl.split(",") if ip.strip()]

    # Blocking
    print()
    config["block_enabled"] = ask_yn("Enable automatic IP blocking?", False)
    if config["block_enabled"]:
        method = ask("Block method (ufw / iptables)", config["block_method"])
        config["block_method"] = method if method in ("ufw", "iptables") else "ufw"
        dur = ask("Block duration (minutes)", str(config["block_duration_minutes"]))
        try:
            config["block_duration_minutes"] = int(dur)
        except ValueError:
            pass

    # Email
    print()
    config["email_enabled"] = ask_yn("Enable email alerts?", False)
    if config["email_enabled"]:
        config["email_to"] = ask("Alert recipient email")
        config["smtp_server"] = ask("SMTP server", config["smtp_server"])
        port = ask("SMTP port", str(config["smtp_port"]))
        try:
            config["smtp_port"] = int(port)
        except ValueError:
            pass
        config["smtp_tls"] = ask_yn("Use STARTTLS?", False)
        config["smtp_user"] = ask("SMTP username (blank for none)", "")
        if config["smtp_user"]:
            config["smtp_pass"] = ask("SMTP password", "")
        config["email_from"] = ask("From address", f"sshguardian@{os.uname().nodename}")

    # ── Create directories ──
    print(f"\n{B}Step 2: Installing files{X}\n")

    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

    # Copy script
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), SCRIPT_NAME)
    dst = os.path.join(INSTALL_DIR, SCRIPT_NAME)
    if os.path.isfile(src):
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        print(f"  {G}✓{X}  Installed {dst}")
    else:
        print(f"  {R}✗{X}  Could not find {src}")
        print(f"      Make sure {SCRIPT_NAME} is in the same directory as install.py")
        sys.exit(1)

    # Write config (don't overwrite existing without asking)
    if os.path.isfile(CONFIG_FILE):
        if ask_yn(f"  Config already exists at {CONFIG_FILE}. Overwrite?", False):
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
            print(f"  {G}✓{X}  Config updated: {CONFIG_FILE}")
        else:
            print(f"  {Y}⏭{X}  Keeping existing config")
    else:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(CONFIG_FILE, 0o600)
        print(f"  {G}✓{X}  Config created: {CONFIG_FILE} (mode 600)")

    # Write systemd unit
    with open(SYSTEMD_FILE, "w") as f:
        f.write(SYSTEMD_UNIT)
    print(f"  {G}✓{X}  Systemd service: {SYSTEMD_FILE}")

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    print(f"  {G}✓{X}  systemctl daemon-reload")

    # ── Done ──
    print(f"\n{B}Step 3: Next steps{X}\n")
    print(f"  Start now:           {C}sudo systemctl start sshguardian{X}")
    print(f"  Enable on boot:      {C}sudo systemctl enable sshguardian{X}")
    print(f"  Check status:        {C}sudo systemctl status sshguardian{X}")
    print(f"  View live log:       {C}sudo journalctl -u sshguardian -f{X}")
    print(
        f"  View threat table:   {C}sudo python3 {INSTALL_DIR}/{SCRIPT_NAME} --status{X}"
    )
    print(f"  Edit config:         {C}sudo nano {CONFIG_FILE}{X}")
    print(
        f"  Send SIGUSR1 for live status:  {C}sudo kill -USR1 $(pidof -x sshguardian.py){X}"
    )
    print(f"\n  {G}{B}Installation complete!{X}\n")


def uninstall():
    banner()
    check_root()

    print(f"{Y}Uninstalling SSHGuardian...{X}\n")

    # Stop service
    subprocess.run(["systemctl", "stop", "sshguardian"], capture_output=True)
    subprocess.run(["systemctl", "disable", "sshguardian"], capture_output=True)
    print(f"  {G}✓{X}  Service stopped and disabled")

    # Remove files
    for path in [SYSTEMD_FILE]:
        if os.path.isfile(path):
            os.remove(path)
            print(f"  {G}✓{X}  Removed {path}")

    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    if os.path.isdir(INSTALL_DIR):
        shutil.rmtree(INSTALL_DIR)
        print(f"  {G}✓{X}  Removed {INSTALL_DIR}")

    if os.path.isdir(STATE_DIR):
        shutil.rmtree(STATE_DIR)
        print(f"  {G}✓{X}  Removed {STATE_DIR}")

    # Keep config and logs — user data
    print(f"\n  {Y}Kept (user data):{X}")
    print(f"    Config:  {CONFIG_DIR}")
    print(f"    Log:     {LOG_FILE}")
    print(f"\n  To remove everything:  {D}sudo rm -rf {CONFIG_DIR} {LOG_FILE}{X}")
    print(f"\n  {G}{B}Uninstall complete.{X}\n")


def main():
    parser = argparse.ArgumentParser(description="SSHGuardian Installer")
    parser.add_argument("--uninstall", action="store_true", help="Remove SSHGuardian")
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
    else:
        install()


if __name__ == "__main__":
    main()
