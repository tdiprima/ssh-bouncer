# Detection brain
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from actions import FirewallError, block_ip, send_email, unblock_ip

logger = logging.getLogger("sshbouncer.engine")


class DetectionEngine:
    def __init__(self, config: dict, state_store=None, dry_run: bool = False, now_fn=datetime.now):
        self.config = config
        self.state_store = state_store
        self.dry_run = dry_run
        self.now = now_fn
        self.whitelist = list(config.get("whitelist", []))
        self.tracker = defaultdict(list)
        self.blocked = {}  # ip -> {"blocked_at", "expires_at", "method"}
        self.last_alert = {}  # ip -> datetime of last alert

    # ── Startup / shutdown ──────────────────────────────────────────────────

    def restore_state(self) -> None:
        """Load persisted blocks and failure history. Expired blocks are removed right away."""
        if self.state_store is None:
            return
        saved = self.state_store.load()
        self.blocked = dict(saved["blocks"])
        for ip, timestamps in saved["tracker"].items():
            self.tracker[ip] = list(timestamps)
        logger.info(
            "event=state_restored blocks=%d tracked_ips=%d", len(self.blocked), len(self.tracker)
        )
        self.expire_blocks()

    def save_state(self) -> None:
        if self.state_store is None:
            return
        self.state_store.save(self.blocked, dict(self.tracker))

    # ── Event handling ──────────────────────────────────────────────────────

    def process_event(self, event: dict):
        if event["type"] == "accepted_login":
            logger.info("event=accepted_login ip=%s user=%s", event["ip"], event.get("user"))
            return

        ip = event["ip"]
        if self.is_whitelisted(ip):
            logger.debug("event=whitelisted_ignored ip=%s", ip)
            return

        now = self.now()
        self.tracker[ip].append(now)

        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        self.tracker[ip] = [t for t in self.tracker[ip] if t > cutoff]

        if len(self.tracker[ip]) >= self.config["threshold"]:
            self.trigger(ip)

    def is_whitelisted(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("event=invalid_ip_in_event ip=%r", ip)
            return True  # fail closed: never act on something we cannot parse
        return any(address in network for network in self.whitelist)

    def trigger(self, ip: str):
        if ip in self.blocked:
            return
        if self.in_cooldown(ip):
            logger.debug("event=alert_suppressed_cooldown ip=%s", ip)
            return

        failures = len(self.tracker[ip])
        logger.warning(
            "event=brute_force_detected ip=%s failures=%d window_seconds=%d",
            ip, failures, self.config["window_seconds"],
        )
        self.last_alert[ip] = self.now()

        block_applied = self.apply_block(ip)

        if self.config.get("email_enabled"):
            send_email(
                subject=f"Brute-force detected from {ip}",
                body=self.build_alert_body(ip, failures, block_applied),
                config=self.config,
            )

        self.save_state()

    def in_cooldown(self, ip: str) -> bool:
        last = self.last_alert.get(ip)
        if last is None:
            return False
        cooldown = timedelta(minutes=self.config.get("cooldown_minutes", 0))
        return self.now() - last < cooldown

    def build_alert_body(self, ip: str, failures: int, block_applied: bool) -> str:
        action = "blocked" if block_applied else "not blocked"
        return (
            f"{ip} exceeded threshold: {failures} failed logins "
            f"within {self.config['window_seconds']} seconds.\n"
            f"Action taken: {action}."
        )

    # ── Blocking ────────────────────────────────────────────────────────────

    def apply_block(self, ip: str) -> bool:
        """Block ip if blocking is on. Returns True only when the firewall rule was installed."""
        if not self.config.get("block_enabled"):
            return False
        if self.dry_run:
            logger.info("event=block_skipped reason=dry_run ip=%s", ip)
            return False

        method = self.config.get("block_method", "ufw")
        try:
            block_ip(ip, method)
        except FirewallError as error:
            logger.error("event=block_failed ip=%s method=%s error=%s", ip, method, error)
            return False

        now = self.now()
        self.blocked[ip] = {
            "blocked_at": now,
            "expires_at": now + timedelta(minutes=self.config["block_duration_minutes"]),
            "method": method,
        }
        return True

    def expire_blocks(self) -> list:
        """Remove firewall rules whose ban has ended. Returns the IPs that were unblocked."""
        now = self.now()
        expired = [ip for ip, block in self.blocked.items() if block["expires_at"] <= now]
        released = []
        for ip in expired:
            method = self.blocked[ip]["method"]
            try:
                unblock_ip(ip, method)
            except FirewallError as error:
                # Keep the record so we retry next cycle instead of forgetting a live rule.
                logger.error("event=unblock_failed ip=%s method=%s error=%s", ip, method, error)
                continue
            del self.blocked[ip]
            self.tracker.pop(ip, None)
            released.append(ip)
            logger.info("event=block_expired ip=%s", ip)
        if released:
            self.save_state()
        return released

    # ── Reporting ───────────────────────────────────────────────────────────

    def status_rows(self) -> list:
        """One row per tracked or blocked IP: (ip, recent_failures, blocked_until_or_None)."""
        now = self.now()
        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        rows = []
        for ip in sorted(set(self.tracker) | set(self.blocked)):
            recent = sum(1 for t in self.tracker.get(ip, []) if t > cutoff)
            block = self.blocked.get(ip)
            rows.append((ip, recent, block["expires_at"] if block else None))
        return rows
