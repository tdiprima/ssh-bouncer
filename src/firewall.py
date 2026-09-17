# Firewall rule lifecycle: the only place that installs, removes, lists, or reconciles rules.
#
# Every rule goes through here so that:
#   * dry-run is enforced once, for block AND unblock, instead of at each call site;
#   * rules carry an ownership tag and can be found again after a crash or a lost state file;
#   * uninstall reuses the same cleanup as the daemon.
import logging
from datetime import datetime, timedelta

from actions import (
    FirewallError,
    build_block_command,
    build_legacy_unblock_command,
    build_list_command,
    build_unblock_command,
    parse_rule_listing,
    run_firewall_command,
)

logger = logging.getLogger("sshbouncer.firewall")


class FirewallLifecycle:
    """Mode-aware boundary around the host firewall for one block method."""

    def __init__(self, method: str, dry_run: bool = False, runner=run_firewall_command):
        self.method = method
        self.dry_run = dry_run
        self.run = runner

    def block(self, ip: str) -> None:
        """Install a tagged deny rule. Raises FirewallError when the rule was not installed."""
        if self.dry_run:
            logger.info("event=firewall_block_simulated ip=%s method=%s", ip, self.method)
            return
        self.run(build_block_command(ip, self.method))
        logger.info("event=firewall_block ip=%s method=%s", ip, self.method)

    def unblock(self, ip: str) -> None:
        """Remove the deny rule for ip. Falls back to the untagged spec for rules from old versions."""
        if self.dry_run:
            logger.info("event=firewall_unblock_simulated ip=%s method=%s", ip, self.method)
            return
        try:
            self.run(build_unblock_command(ip, self.method))
        except FirewallError as tagged_error:
            logger.debug("event=firewall_unblock_tagged_failed ip=%s error=%s", ip, tagged_error)
            self.run(build_legacy_unblock_command(ip, self.method))
        logger.info("event=firewall_unblock ip=%s method=%s", ip, self.method)

    def list_rules(self) -> dict:
        """Map source IP -> owned (True when the rule carries our tag). Empty in dry-run."""
        if self.dry_run:
            return {}
        output = self.run(build_list_command(self.method))
        return parse_rule_listing(output, self.method)

    def remove_owned_rules(self) -> tuple:
        """Delete every tagged rule. Returns (removed_ips, failed_ips)."""
        try:
            rules = self.list_rules()
        except FirewallError as error:
            logger.error("event=firewall_list_failed method=%s error=%s", self.method, error)
            return [], []

        removed = []
        failed = []
        for ip in sorted(ip for ip, owned in rules.items() if owned):
            try:
                self.unblock(ip)
            except FirewallError as error:
                logger.error("event=firewall_cleanup_failed ip=%s error=%s", ip, error)
                failed.append(ip)
                continue
            removed.append(ip)
        return removed, failed


def reconcile_blocks(
    recorded: dict, live_rules: dict, method: str, now: datetime, duration: timedelta
) -> dict:
    """Merge the saved block table with what the firewall actually contains.

    Pure function so it is testable without root.
      * recorded rule still present (tagged or legacy): keep the record;
      * recorded rule missing from firewall: drop the record, nothing left to expire;
      * tagged rule with no record: adopt it with a fresh expiry so it does get released.
    Returns {"blocks": merged, "adopted": [...], "dropped": [...]}.
    """
    blocks = {}
    dropped = []
    for ip, record in recorded.items():
        if ip in live_rules:
            blocks[ip] = record
        else:
            dropped.append(ip)

    adopted = []
    for ip, owned in live_rules.items():
        if not owned or ip in blocks:
            continue
        blocks[ip] = {"blocked_at": now, "expires_at": now + duration, "method": method}
        adopted.append(ip)

    return {"blocks": blocks, "adopted": adopted, "dropped": dropped}
