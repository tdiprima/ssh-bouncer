# Detection brain
from collections import defaultdict
from datetime import datetime, timedelta
from actions import block_ip, send_email


class DetectionEngine:
    def __init__(self, config: dict):
        self.config = config
        self.tracker = defaultdict(list)
        self.blocked = set()

    def process_event(self, event: dict):
        if event["type"] == "accepted_login":
            return

        ip = event["ip"]
        now = datetime.now()

        self.tracker[ip].append(now)

        cutoff = now - timedelta(seconds=self.config["window_seconds"])
        self.tracker[ip] = [t for t in self.tracker[ip] if t > cutoff]

        if len(self.tracker[ip]) >= self.config["threshold"]:
            self.trigger(ip)

    def trigger(self, ip: str):
        if ip in self.blocked:
            return

        print(f"🚨 Brute force detected from {ip}")

        if self.config.get("block_enabled"):
            block_ip(ip, self.config.get("block_method", "ufw"))
            self.blocked.add(ip)

        if self.config.get("email_enabled"):
            send_email(
                subject=f"Brute-force detected from {ip}",
                body=f"{ip} exceeded threshold.",
                config=self.config,
            )
