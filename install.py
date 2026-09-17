#!/usr/bin/env python3
"""
SSHBouncer Installer — Sets up config, directories, and systemd service.

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
from pathlib import Path
from typing import Dict


# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
INSTALL_DIR = Path("/opt/sshbouncer")
CONFIG_DIR = Path("/etc/sshbouncer")
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_DIR = Path("/var/lib/sshbouncer")
SYSTEMD_FILE = Path("/etc/systemd/system/sshbouncer.service")

APP_FILES = [
    "sshbouncer.py",
    "parser.py",
    "engine.py",
    "actions.py",
    "config.py",
    "state.py",
    "logfollow.py",
]


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
    "log_file": "/var/log/sshbouncer.log",
    "log_level": "INFO",
    "cooldown_minutes": 10,
    "state_file": str(STATE_DIR / "state.json"),
}


# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────
def require_root():
    if os.geteuid() != 0:
        print("Error: must run installer as root.")
        sys.exit(1)


def ask(prompt: str, default: str = "") -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(f"{prompt} ({hint}): ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


# ─────────────────────────────────────────────
# Config Collection
# ─────────────────────────────────────────────
def collect_config() -> Dict:
    config = DEFAULT_CONFIG.copy()

    config["threshold"] = int(
        ask("Failed login threshold", str(config["threshold"]))
    )

    config["window_seconds"] = int(
        ask("Detection window (seconds)", str(config["window_seconds"]))
    )

    whitelist = ask("Whitelisted IPs/CIDRs (comma-separated)", ", ".join(config["whitelist"]))
    config["whitelist"] = [entry.strip() for entry in whitelist.split(",") if entry.strip()]

    config["block_enabled"] = ask_yes_no("Enable IP blocking?", False)

    if config["block_enabled"]:
        config["block_method"] = ask("Block method (ufw/iptables)", "ufw")
        config["block_duration_minutes"] = int(
            ask("Block duration (minutes)", str(config["block_duration_minutes"]))
        )

    config["email_enabled"] = ask_yes_no("Enable email alerts?", False)

    if config["email_enabled"]:
        config["email_to"] = ask("Alert email")
        config["email_from"] = ask("Sender address (blank = sshbouncer@hostname)", "")
        config["smtp_server"] = ask("SMTP server", "localhost")
        config["smtp_port"] = int(ask("SMTP port", str(config["smtp_port"])))
        config["smtp_tls"] = ask_yes_no("Use STARTTLS?", False)
        config["smtp_user"] = ask("SMTP username (blank = no auth)", "")
        print("SMTP password: set SSHBOUNCER_SMTP_PASS in the service environment, "
              "or add smtp_pass to the config file after install.")

    return config


# ─────────────────────────────────────────────
# File Installation
# ─────────────────────────────────────────────
def create_directories():
    for path in (INSTALL_DIR, CONFIG_DIR, STATE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def copy_application_files():
    source_dir = Path(__file__).resolve().parent / "src"

    for filename in APP_FILES:
        src = source_dir / filename
        dst = INSTALL_DIR / filename

        if not src.exists():
            print(f"Missing required file: {filename}")
            sys.exit(1)

        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        print(f"Installed {dst}")


def write_config(config: Dict):
    if CONFIG_FILE.exists():
        overwrite = ask_yes_no("Config exists. Overwrite?", False)
        if not overwrite:
            print("Keeping existing config.")
            return

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

    os.chmod(CONFIG_FILE, 0o600)
    print(f"Config written to {CONFIG_FILE}")


# ─────────────────────────────────────────────
# Systemd Setup
# ─────────────────────────────────────────────
def build_systemd_unit() -> str:
    return f"""[Unit]
Description=SSHBouncer — Real-Time SSH Intrusion Detection
After=network.target sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {INSTALL_DIR}/sshbouncer.py -c {CONFIG_FILE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def install_systemd_service():
    SYSTEMD_FILE.write_text(build_systemd_unit())
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    print("Systemd service installed.")


def enable_service():
    subprocess.run(["systemctl", "enable", "sshbouncer"], check=False)
    print("Service enabled.")


def start_service():
    subprocess.run(["systemctl", "start", "sshbouncer"], check=False)
    print("Service started.")


def stop_and_disable_service():
    subprocess.run(["systemctl", "stop", "sshbouncer"], check=False)
    subprocess.run(["systemctl", "disable", "sshbouncer"], check=False)


def remove_installed_files():
    if SYSTEMD_FILE.exists():
        SYSTEMD_FILE.unlink()

    if INSTALL_DIR.exists():
        shutil.rmtree(INSTALL_DIR)

    if STATE_DIR.exists():
        shutil.rmtree(STATE_DIR)

    subprocess.run(["systemctl", "daemon-reload"], check=False)


# ─────────────────────────────────────────────
# High-Level Actions
# ─────────────────────────────────────────────
def run_install():
    require_root()

    config = collect_config()
    create_directories()
    copy_application_files()
    write_config(config)
    install_systemd_service()

    if ask_yes_no("Start service now?", True):
        enable_service()
        start_service()

    print("Installation complete.")


def run_uninstall():
    require_root()

    stop_and_disable_service()
    remove_installed_files()

    print("Uninstall complete.")
    print("Config and logs were preserved.")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SSHBouncer Installer")
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()

    if args.uninstall:
        run_uninstall()
    else:
        run_install()


if __name__ == "__main__":
    main()
