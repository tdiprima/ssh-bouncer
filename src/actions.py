# Firewall + email. Nothing else.
import subprocess
import smtplib
from email.mime.text import MIMEText

def block_ip(ip: str, method="ufw"):
    if method == "ufw":
        cmd = ["ufw", "insert", "1", "deny", "from", ip, "to", "any"]
    elif method == "iptables":
        cmd = ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    else:
        raise ValueError("Unknown block method")

    subprocess.run(cmd, check=False)


def send_email(subject: str, body: str, config: dict):
    if not config.get("email_enabled"):
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = config["email_from"]
    msg["To"] = config["email_to"]

    with smtplib.SMTP(config["smtp_server"], config["smtp_port"]) as srv:
        if config.get("smtp_tls"):
            srv.starttls()
        if config.get("smtp_user"):
            srv.login(config["smtp_user"], config["smtp_pass"])
        srv.sendmail(msg["From"], [msg["To"]], msg.as_string())
