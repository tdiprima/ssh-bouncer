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

import argparse
import logging
import os
import signal
import sys
import time

from config import DEFAULT_CONFIG_PATH, ConfigError, load_config, resolve_auth_log
from engine import DetectionEngine
from logfollow import LogFollower
from parser import parse_line
from state import StateStore

logger = logging.getLogger("sshbouncer")

EXIT_OK = 0
EXIT_CONFIG_ERROR = 2
EXIT_RUNTIME_ERROR = 3
EXPIRY_CHECK_INTERVAL_SECONDS = 30
LOG_FORMAT = "%(asctime)s level=%(levelname)s component=%(name)s %(message)s"


def parse_arguments(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SSHBouncer — real-time SSH brute-force detection")
    parser.add_argument(
        "-c", "--config",
        default=None,
        help=f"path to config.json (default: {DEFAULT_CONFIG_PATH} if it exists, else built-in defaults)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="monitor and alert, but never touch the firewall"
    )
    parser.add_argument(
        "--status", action="store_true", help="print the threat table from saved state and exit"
    )
    return parser.parse_args(argv)


def resolve_config_path(explicit_path: str | None) -> str | None:
    """Explicit -c wins. Otherwise use the installed config only when it exists."""
    if explicit_path is not None:
        return explicit_path
    if os.path.isfile(DEFAULT_CONFIG_PATH):
        return DEFAULT_CONFIG_PATH
    return None


def configure_logging(config: dict) -> None:
    """Log to stderr always, and to log_file when it is writable."""
    root = logging.getLogger()
    root.setLevel(config["log_level"])
    formatter = logging.Formatter(LOG_FORMAT)

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    try:
        file_handler = logging.FileHandler(config["log_file"], encoding="utf-8")
    except OSError as error:
        logger.warning("event=log_file_unavailable path=%s error=%s", config["log_file"], error)
        return
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)


def format_status_table(rows: list) -> str:
    """Render (ip, failures, expires_at) rows as a fixed-width text table."""
    lines = [f"{'IP':<40} {'FAILS':>5}  BLOCKED UNTIL"]
    lines.append("-" * 70)
    if not rows:
        lines.append("(no tracked IPs)")
    for ip, failures, expires_at in rows:
        blocked = expires_at.strftime("%Y-%m-%d %H:%M:%S") if expires_at else "-"
        lines.append(f"{ip:<40} {failures:>5}  {blocked}")
    return "\n".join(lines)


def show_status(config: dict) -> int:
    """Static snapshot from the saved state file. Does not touch the firewall."""
    engine = DetectionEngine(config, state_store=None)
    saved = StateStore(config["state_file"]).load()
    engine.blocked = saved["blocks"]
    for ip, timestamps in saved["tracker"].items():
        engine.tracker[ip] = timestamps
    sys.stdout.write(format_status_table(engine.status_rows()) + "\n")
    return EXIT_OK


class Daemon:
    """Owns the monitoring loop and signal handling."""

    def __init__(self, config: dict, dry_run: bool):
        self.config = config
        self.engine = DetectionEngine(config, StateStore(config["state_file"]), dry_run=dry_run)
        self.stop_requested = False
        self.status_requested = False
        self.last_expiry_check = time.monotonic()

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self.handle_stop_signal)
        signal.signal(signal.SIGINT, self.handle_stop_signal)
        signal.signal(signal.SIGUSR1, self.handle_status_signal)

    def handle_stop_signal(self, signum, _frame) -> None:
        logger.info("event=shutdown_requested signal=%s", signal.Signals(signum).name)
        self.stop_requested = True

    def handle_status_signal(self, _signum, _frame) -> None:
        self.status_requested = True

    def run(self) -> int:
        auth_log = resolve_auth_log(self.config["auth_log"])
        logger.info(
            "event=startup auth_log=%s threshold=%d window_seconds=%d block_enabled=%s dry_run=%s",
            auth_log, self.config["threshold"], self.config["window_seconds"],
            self.config["block_enabled"], self.engine.dry_run,
        )
        self.engine.restore_state()
        self.install_signal_handlers()

        follower = LogFollower(auth_log, sleep_fn=self.idle)
        try:
            for line in follower.follow(should_stop=lambda: self.stop_requested):
                event = parse_line(line)
                if event:
                    self.engine.process_event(event)
                self.periodic_tasks()
        finally:
            follower.close()
            self.engine.save_state()
            logger.info("event=shutdown_complete")
        return EXIT_OK

    def idle(self, seconds: float) -> None:
        """Sleep between polls, but still service signals and block expiry."""
        self.periodic_tasks()
        if not self.stop_requested:
            time.sleep(seconds)

    def periodic_tasks(self) -> None:
        if self.status_requested:
            self.status_requested = False
            sys.stdout.write(format_status_table(self.engine.status_rows()) + "\n")
            sys.stdout.flush()

        if time.monotonic() - self.last_expiry_check >= EXPIRY_CHECK_INTERVAL_SECONDS:
            self.last_expiry_check = time.monotonic()
            self.engine.expire_blocks()


def main(argv=None) -> int:
    args = parse_arguments(argv)

    try:
        config = load_config(resolve_config_path(args.config))
    except ConfigError as error:
        sys.stderr.write(f"ERROR: {error}\n")
        return EXIT_CONFIG_ERROR

    configure_logging(config)

    if args.status:
        return show_status(config)

    try:
        return Daemon(config, dry_run=args.dry_run).run()
    except ConfigError as error:
        logger.error("event=startup_failed error=%s", error)
        return EXIT_CONFIG_ERROR
    except OSError as error:
        logger.error("event=runtime_failure error=%s", error)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    sys.exit(main())
