# Firewall commands + email. Nothing else. Rule ownership and lifecycle live in firewall.py.
import ipaddress
import logging
import re
import shlex
import smtplib
import socket
import ssl
import subprocess
from email.mime.text import MIMEText

logger = logging.getLogger("sshbouncer.actions")

FIREWALL_COMMAND_TIMEOUT_SECONDS = 30
SMTP_TIMEOUT_SECONDS = 30

# Every rule this program installs carries this comment so it can be found again later.
RULE_TAG = "sshbouncer"

# "[ 3] Anywhere   DENY IN   1.2.3.4   # sshbouncer" from `ufw status numbered`.
UFW_DENY_LINE = re.compile(
    r"^\[\s*\d+\]\s+.+?\s+(?:DENY|REJECT)(?:\s+IN)?\s+(?P<source>\S+)(?:\s+#\s*(?P<comment>.*?))?\s*$"
)


class FirewallError(RuntimeError):
    """Raised when a firewall command fails or cannot be run."""


# ufw handles both address families itself; netfilter needs one binary per family.
IPTABLES_BINARIES = ("iptables", "ip6tables")


def iptables_binary_for(ip: str) -> str:
    """ip6tables for IPv6 addresses, iptables otherwise. Raises ValueError for non-addresses."""
    return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"


def build_block_command(ip: str, method: str) -> list:
    if method == "ufw":
        return ["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", RULE_TAG]
    if method == "iptables":
        return [iptables_binary_for(ip), "-I", "INPUT", "1", "-s", ip, "-m", "comment",
                "--comment", RULE_TAG, "-j", "DROP"]
    raise ValueError("Unknown block method")


def build_unblock_command(ip: str, method: str) -> list:
    if method == "ufw":
        return ["ufw", "delete", "deny", "from", ip, "to", "any", "comment", RULE_TAG]
    if method == "iptables":
        return [iptables_binary_for(ip), "-D", "INPUT", "-s", ip, "-m", "comment",
                "--comment", RULE_TAG, "-j", "DROP"]
    raise ValueError("Unknown block method")


def build_legacy_unblock_command(ip: str, method: str) -> list:
    """Delete spec for rules installed by versions that did not tag rules."""
    if method == "ufw":
        return ["ufw", "delete", "deny", "from", ip, "to", "any"]
    if method == "iptables":
        return [iptables_binary_for(ip), "-D", "INPUT", "-s", ip, "-j", "DROP"]
    raise ValueError("Unknown block method")


def build_list_commands(method: str) -> list:
    """Every command whose combined output describes all rules for this method."""
    if method == "ufw":
        return [["ufw", "status", "numbered"]]
    if method == "iptables":
        return [[binary, "-S", "INPUT"] for binary in IPTABLES_BINARIES]
    raise ValueError("Unknown block method")


def parse_rule_listing(output: str, method: str) -> dict:
    """Map source IP -> True when the deny rule carries our tag, False when it does not."""
    if method == "ufw":
        return parse_ufw_listing(output)
    if method == "iptables":
        return parse_iptables_listing(output)
    raise ValueError("Unknown block method")


def parse_ufw_listing(output: str) -> dict:
    rules = {}
    for line in output.splitlines():
        match = UFW_DENY_LINE.match(line)
        if not match:
            continue
        source = normalize_rule_source(match.group("source"))
        if source is None:
            continue
        rules[source] = (match.group("comment") or "") == RULE_TAG
    return rules


def parse_iptables_listing(output: str) -> dict:
    rules = {}
    for line in output.splitlines():
        try:
            tokens = shlex.split(line)
        except ValueError:
            logger.warning("event=iptables_line_unparseable line=%r", line)
            continue
        if "-s" not in tokens or "DROP" not in tokens:
            continue
        source = normalize_rule_source(tokens[tokens.index("-s") + 1])
        if source is None:
            continue
        is_tagged = "--comment" in tokens and tokens[tokens.index("--comment") + 1] == RULE_TAG
        rules[source] = is_tagged
    return rules


def normalize_rule_source(source: str) -> str | None:
    """Canonical address for a single-host rule source; None for networks, 'Anywhere', or junk."""
    host = source.removesuffix("/32").removesuffix("/128")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def run_firewall_command(cmd: list) -> str:
    """Run a firewall command and return its stdout.

    Raises FirewallError on non-zero exit, timeout, or missing binary.
    """
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=FIREWALL_COMMAND_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise FirewallError(f"firewall tool not found: {cmd[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise FirewallError(f"firewall command timed out: {' '.join(cmd)}") from error

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise FirewallError(
            f"firewall command failed (exit {result.returncode}): {' '.join(cmd)}: {detail}"
        )
    return result.stdout


def default_sender_address() -> str:
    return f"sshbouncer@{socket.gethostname()}"


def send_email(subject: str, body: str, config: dict) -> bool:
    """Deliver an alert. Returns True on success, False (logged) on any delivery failure."""
    if not config.get("email_enabled"):
        return False

    if config.get("smtp_user") and not config.get("smtp_tls"):
        # Config validation already rejects this; keep the guard so a hand-built config cannot
        # push a password over cleartext.
        logger.error("event=email_refused reason=credentials_without_tls server=%s", config["smtp_server"])
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config.get("email_from") or default_sender_address()
    msg["To"] = config["email_to"]

    try:
        with smtplib.SMTP(
            config["smtp_server"], config["smtp_port"], timeout=SMTP_TIMEOUT_SECONDS
        ) as srv:
            if config.get("smtp_tls"):
                # Default context verifies the chain and hostname; smtplib's implicit one does neither.
                srv.starttls(context=ssl.create_default_context())
            if config.get("smtp_user"):
                srv.login(config["smtp_user"], config["smtp_pass"])
            srv.sendmail(msg["From"], [msg["To"]], msg.as_string())
    except (smtplib.SMTPException, OSError) as error:
        logger.error(
            "event=email_failed to=%s server=%s:%s error=%s",
            config["email_to"], config["smtp_server"], config["smtp_port"], error,
        )
        return False

    logger.info("event=email_sent to=%s subject=%r", config["email_to"], subject)
    return True
