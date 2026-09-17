# Firewall + email. Nothing else.
import logging
import smtplib
import socket
import subprocess
from email.mime.text import MIMEText

logger = logging.getLogger("sshbouncer.actions")

FIREWALL_COMMAND_TIMEOUT_SECONDS = 30
SMTP_TIMEOUT_SECONDS = 30


class FirewallError(RuntimeError):
    """Raised when a firewall command fails or cannot be run."""


def build_block_command(ip: str, method: str) -> list:
    if method == "ufw":
        return ["ufw", "insert", "1", "deny", "from", ip, "to", "any"]
    if method == "iptables":
        return ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    raise ValueError("Unknown block method")


def build_unblock_command(ip: str, method: str) -> list:
    if method == "ufw":
        return ["ufw", "delete", "deny", "from", ip, "to", "any"]
    if method == "iptables":
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    raise ValueError("Unknown block method")


def run_firewall_command(cmd: list) -> None:
    """Run a firewall command. Raises FirewallError on non-zero exit, timeout, or missing binary."""
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


def block_ip(ip: str, method="ufw"):
    """Insert a deny rule. Raises FirewallError if the rule was not installed."""
    run_firewall_command(build_block_command(ip, method))
    logger.info("event=firewall_block ip=%s method=%s", ip, method)


def unblock_ip(ip: str, method="ufw"):
    """Remove a deny rule. Raises FirewallError if removal fails."""
    run_firewall_command(build_unblock_command(ip, method))
    logger.info("event=firewall_unblock ip=%s method=%s", ip, method)


def default_sender_address() -> str:
    return f"sshbouncer@{socket.gethostname()}"


def send_email(subject: str, body: str, config: dict) -> bool:
    """Deliver an alert. Returns True on success, False (logged) on any delivery failure."""
    if not config.get("email_enabled"):
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
                srv.starttls()
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
