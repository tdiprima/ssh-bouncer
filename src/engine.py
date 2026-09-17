# Detection brain
import ipaddress
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from actions import FirewallError
from firewall import FirewallLifecycle, reconcile_blocks

logger = logging.getLogger("sshbouncer.engine")


class DetectionEngine:
    def __init__(
        self,
        config: dict,
        state_store=None,
        dry_run: bool = False,
        now_fn=datetime.now,
        firewall=None,
        notifier=None,
    ):
        self.config = config
        self.state_store = state_store
        self.dry_run = dry_run
        self.now = now_fn
        self.firewall = firewall or FirewallLifecycle(config.get("block_method", "ufw"), dry_run=dry_run)
        self.notifier = notifier
        self.whitelist = list(config.get("whitelist", []))
        self.tracker = defaultdict(list)
        self.blocked = {}  # ip -> {"blocked_at", "expires_at", "method"}
        self.last_alert = {}  # ip -> datetime of last alert
        # True while in-memory state is newer than what is on disk. Cleared by a successful save.
        self.unsaved_changes = False

    # ── Startup / shutdown ──────────────────────────────────────────────────

    def restore_state(self) -> None:
        """Load persisted blocks and failure history, reconcile with the firewall, expire old blocks."""
        if self.state_store is None:
            return
        saved = self.state_store.load()
        self.blocked = dict(saved["blocks"])
        for ip, timestamps in saved["tracker"].items():
            self.tracker[ip] = list(timestamps)
        logger.info(
            "event=state_restored blocks=%d tracked_ips=%d", len(self.blocked), len(self.tracker)
        )
        self.reconcile_with_firewall()
        self.prune()
        self.expire_blocks()

    def reconcile_with_firewall(self) -> None:
        """Make the block table match the rules that are really installed.

        Only meaningful when blocking is on. Records for rules that vanished are dropped;
        tagged rules with no record are adopted so they still expire.
        """
        if not self.config.get("block_enabled"):
            return
        try:
            live_rules = self.firewall.list_rules()
        except FirewallError as error:
            logger.error("event=firewall_reconcile_skipped error=%s", error)
            return

        result = reconcile_blocks(
            self.blocked, live_rules, self.firewall.method, self.now(), self.block_duration()
        )
        for ip in result["dropped"]:
            logger.warning("event=block_record_dropped reason=rule_missing ip=%s", ip)
        for ip in result["adopted"]:
            logger.warning("event=block_rule_adopted reason=no_record ip=%s", ip)
        if result["dropped"] or result["adopted"]:
            self.blocked = result["blocks"]
            self.save_state()

    def save_state(self) -> bool:
        """Persist state. Returns False (and remembers the debt) when the write failed."""
        self.prune()
        if self.state_store is None:
            return True
        saved = self.state_store.save(self.blocked, dict(self.tracker))
        self.unsaved_changes = not saved
        return saved

    def retry_save_if_needed(self) -> None:
        if self.unsaved_changes:
            logger.info("event=state_save_retry")
            self.save_state()

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
        self.tracker[ip] = self.recent_failures(self.tracker[ip], now)

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
        # Persist before notifying: a slow or failed SMTP call must never delay or lose the record.
        if not self.save_state():
            logger.error("event=state_persist_failed context=block ip=%s block_applied=%s", ip, block_applied)

        self.notify(ip, failures, block_applied)

    def notify(self, ip: str, failures: int, block_applied: bool) -> None:
        if self.notifier is None:
            return
        self.notifier.enqueue(
            subject=f"Brute-force detected from {ip}",
            body=self.build_alert_body(ip, failures, block_applied),
        )

    def in_cooldown(self, ip: str) -> bool:
        last = self.last_alert.get(ip)
        if last is None:
            return False
        return self.now() - last < self.cooldown()

    def build_alert_body(self, ip: str, failures: int, block_applied: bool) -> str:
        action = "blocked" if block_applied else "not blocked"
        if block_applied and self.dry_run:
            action = "blocked (dry-run, simulated)"
        return (
            f"{ip} exceeded threshold: {failures} failed logins "
            f"within {self.config['window_seconds']} seconds.\n"
            f"Action taken: {action}."
        )

    # ── Blocking ────────────────────────────────────────────────────────────

    def apply_block(self, ip: str) -> bool:
        """Block ip if blocking is on. Returns True when a rule was installed (or simulated in dry-run)."""
        if not self.config.get("block_enabled"):
            return False

        try:
            self.firewall.block(ip)
        except FirewallError as error:
            logger.error("event=block_failed ip=%s method=%s error=%s", ip, self.firewall.method, error)
            return False

        now = self.now()
        self.blocked[ip] = {
            "blocked_at": now,
            "expires_at": now + self.block_duration(),
            "method": self.firewall.method,
        }
        return True

    def expire_blocks(self) -> list:
        """Remove firewall rules whose ban has ended. Returns the IPs that were unblocked."""
        now = self.now()
        expired = [ip for ip, block in self.blocked.items() if block["expires_at"] <= now]
        released = []
        for ip in expired:
            try:
                self.firewall.unblock(ip)
            except FirewallError as error:
                # Keep the record so we retry next cycle instead of forgetting a live rule.
                logger.error("event=unblock_failed ip=%s error=%s", ip, error)
                continue
            del self.blocked[ip]
            self.tracker.pop(ip, None)
            released.append(ip)
            logger.info("event=block_expired ip=%s", ip)
        if released:
            self.save_state()
        return released

    # ── Housekeeping ────────────────────────────────────────────────────────

    def prune(self) -> None:
        """Forget failures outside the window and alerts past their cooldown.

        Runs periodically so quiet addresses do not accumulate forever.
        """
        now = self.now()
        for ip in list(self.tracker):
            recent = self.recent_failures(self.tracker[ip], now)
            if recent:
                self.tracker[ip] = recent
            else:
                del self.tracker[ip]

        cooldown = self.cooldown()
        for ip in list(self.last_alert):
            if now - self.last_alert[ip] >= cooldown:
                del self.last_alert[ip]

    def recent_failures(self, timestamps: list, now: datetime) -> list:
        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        return [timestamp for timestamp in timestamps if timestamp > cutoff]

    def block_duration(self) -> timedelta:
        return timedelta(minutes=self.config["block_duration_minutes"])

    def cooldown(self) -> timedelta:
        return timedelta(minutes=self.config.get("cooldown_minutes", 0))

    # ── Reporting ───────────────────────────────────────────────────────────

    def status_rows(self) -> list:
        """One row per tracked or blocked IP: (ip, recent_failures, blocked_until_or_None)."""
        now = self.now()
        rows = []
        for ip in sorted(set(self.tracker) | set(self.blocked)):
            recent = len(self.recent_failures(self.tracker.get(ip, []), now))
            block = self.blocked.get(ip)
            rows.append((ip, recent, block["expires_at"] if block else None))
        return rows
